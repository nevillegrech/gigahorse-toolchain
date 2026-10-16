"""Bounded checks of printed expressions along a recovered execution trace.

Only emitted variables enter the printed environment. Memory/world operations
still execute in RecoveredMachine; this checks operands, conditions, PHI copies
and raw-word annotations, not a standalone interpreter for the whole output.
The expression parser accepts a fixed AST subset and never calls eval().
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .constant_memory import proof_is_current
from .controlflow import FlowPlan
from .model import Function, Instruction, Program
from .presentation import InternalInterfaces
from .recovered import Expressions
from .render import PURE
from .revert_folding import find_revert_folds
from .reverts import analyze_reverts
from .semantics import Term, atom, child
from .validation import MASK, ExecutionResult, RecoveredMachine, UnsupportedExecution, arithmetic


@dataclass(frozen=True)
class RawView:
    data: bytes
    offset: int

    def load(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 32].ljust(32, b"\0"))

    def property(self, name: str) -> int:
        if name == "offset":
            return self.offset
        if name == "data_offset":
            return (self.offset + 32) & MASK
        if name == "length":
            return self.load(self.offset)
        raise UnsupportedExecution(f"Unknown raw view property: {name}")

    def call(self, name: str, index: int) -> int | RawView:
        word_offset = (self.offset + 32 * index) & MASK
        head_offset = (word_offset + 32) & MASK
        if name == "word_offset":
            return word_offset
        if name == "word":
            return self.load(word_offset)
        if name == "head_offset":
            return head_offset
        if name == "head_word":
            return self.load(head_offset)
        if name == "element":
            return RawView(self.data, (self.offset + 32 + self.load(head_offset)) & MASK)
        if name == "dynamic_field":
            return RawView(self.data, (self.offset + self.load(word_offset)) & MASK)
        raise UnsupportedExecution(f"Unknown raw view method: {name}")


@lru_cache(maxsize=4096)
def parse_expression(text: str) -> ast.expr:
    if len(text) > 16384:
        raise UnsupportedExecution("Printed expression exceeds validation size bound")
    # Solidity-like EVM helper names can be Python keywords.
    safe = re.sub(r"\bevm\.(not|and|or)\(", r"evm._\1(", text)
    try:
        tree = ast.parse(safe, mode="eval")
    except (SyntaxError, RecursionError) as exc:
        raise UnsupportedExecution(f"Unparseable printed expression: {text}") from exc
    if sum(1 for _ in ast.walk(tree)) > 4096:
        raise UnsupportedExecution("Printed expression exceeds validation node bound")
    return tree.body


def dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value)
        return prefix + "." + node.attr if prefix else ""
    return ""


def decode_revert_helper(text: str) -> bytes:
    """Strictly parse the emitted call, independently re-encoding its literals."""
    call = parse_expression(text.removesuffix(";"))
    if (
        not isinstance(call, ast.Call)
        or call.keywords
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Constant)
    ):
        raise UnsupportedExecution("Malformed printed revert helper")
    name, value = dotted(call.func), call.args[0].value
    if name == "evm.revert_error" and isinstance(value, str):
        raw = value.encode("utf-8")
        if len(raw) <= 4096:
            return (
                bytes.fromhex("08c379a0")
                + (32).to_bytes(32)
                + len(raw).to_bytes(32)
                + raw.ljust((len(raw) + 31) // 32 * 32, b"\0")
            )
    if name == "evm.revert_panic" and type(value) is int and 0 <= value <= MASK:
        return bytes.fromhex("4e487b71") + value.to_bytes(32)
    if name == "evm.revert_data" and isinstance(value, str) and value.startswith("0x"):
        try:
            data = bytes.fromhex(value[2:])
        except ValueError as error:
            raise UnsupportedExecution("Invalid printed revert byte literal") from error
        if len(data) <= 4096:
            return data
    raise UnsupportedExecution("Unsupported printed revert helper")


class PrintedExpressions:
    def __init__(self, names: dict[str, int | RawView], environment: dict[str, int], data: bytes):
        self.names, self.environment, self.data = names, environment, data

    def value(self, text: str) -> int:
        value = self._node(parse_expression(text))
        if not isinstance(value, int):
            raise UnsupportedExecution(f"Expected printed word: {text}")
        return value

    def _integer(self, node: ast.expr) -> int:
        result = self._node(node)
        if not isinstance(result, int):
            raise UnsupportedExecution("Expected a word in printed expression")
        return result

    def _node(self, node: ast.expr) -> int | RawView:
        name = dotted(node)
        if name in self.environment:
            return self.environment[name]
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id not in self.names:
                raise UnsupportedExecution(f"Printed temporary has no assignment: {node.id}")
            return self.names[node.id]
        if isinstance(node, ast.Attribute):
            receiver = self._node(node.value)
            if isinstance(receiver, RawView):
                return receiver.property(node.attr)
        if isinstance(node, ast.BinOp):
            left, right = self._integer(node.left), self._integer(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, (ast.LShift, ast.RShift)) and right >= 0:
                # Renderer shifts represent EVM words; avoid allocating 2**shift bits.
                if right >= 256:
                    return 0
                return left << right if isinstance(node.op, ast.LShift) else left >> right
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = self._integer(node.left), self._integer(node.comparators[0])
            op = node.ops[0]
            if isinstance(op, ast.Eq):
                return int(left == right)
            if isinstance(op, ast.NotEq):
                return int(left != right)
            if isinstance(op, ast.Lt):
                return int(left < right)
            if isinstance(op, ast.LtE):
                return int(left <= right)
            if isinstance(op, ast.Gt):
                return int(left > right)
            if isinstance(op, ast.GtE):
                return int(left >= right)
        if isinstance(node, ast.Call) and not node.keywords:
            args = [self._integer(arg) for arg in node.args]
            function = dotted(node.func)
            if function == "u256" and len(args) == 1:
                return args[0] & MASK
            if function == "word" and len(args) == 1:
                return int(bool(args[0]))
            if function == "address" and len(args) == 1:
                return args[0] & ((1 << 160) - 1)
            if function.startswith("evm."):
                opcode = function[4:].lstrip("_").upper()
                if opcode == "CALLDATALOAD" and len(args) == 1:
                    return int.from_bytes(self.data[args[0] : args[0] + 32].ljust(32, b"\0"))
                if opcode == "MOV" and len(args) == 1:
                    return args[0]
                return arithmetic(opcode, args)
            if isinstance(node.func, ast.Attribute) and len(args) == 1:
                receiver = self._node(node.func.value)
                if isinstance(receiver, RawView):
                    return receiver.call(node.func.attr, args[0])
        raise UnsupportedExecution(f"Unsupported printed expression node: {ast.dump(node)}")


class ProjectedMachine(RecoveredMachine):
    """Use the IR trace while checking expressions against a separate printed frame."""

    def __init__(self, program: Program, **kwargs: Any):
        super().__init__(program, **kwargs)
        self.interfaces = InternalInterfaces(program)
        current = proof_is_current(program)
        summaries = {r["statement"]: r for r in analyze_reverts(program)}
        self.revert_folds = {
            f.id: find_revert_folds(program, f, self.plans[f.id], summaries, current_proof=current)
            if self.structured
            else {}
            for f in program.functions
        }
        self.expressions = {
            f.id: Expressions(
                program,
                f,
                self.interfaces,
                hidden_statements=frozenset(
                    s for fold in self.revert_folds[f.id].values() for s in fold.ir_statements
                ),
            )
            for f in program.functions
        }
        self.names: dict[str, int | RawView] = {}
        self.active: Expressions | None = None
        self.expression_checks = 0
        self.storage_path_checks = 0
        self.storage_read_checks = 0
        self.storage_paths_unchecked = 0
        self.private_call_checks = 0
        self.private_interfaces_exercised: set[str] = set()
        self.folded_revert_checks = 0

    def execute(self, calldata: bytes, **kwargs: Any) -> ExecutionResult:
        self.expression_checks = self.storage_path_checks = self.storage_paths_unchecked = 0
        self.private_call_checks = self.storage_read_checks = 0
        self.private_interfaces_exercised.clear()
        self.folded_revert_checks = 0
        return super().execute(calldata, **kwargs)

    def projection_counts(self) -> dict[str, int]:
        return {
            "printed_expression_checks": self.expression_checks,
            "printed_storage_path_checks": self.storage_path_checks,
            "printed_storage_read_checks": self.storage_read_checks,
            "printed_storage_paths_unchecked": self.storage_paths_unchecked,
            "printed_private_call_checks": self.private_call_checks,
            "printed_revert_snapshot_checks": self.revert_snapshot_checks,
            "printed_revert_byte_checks": self.revert_byte_checks,
            "printed_folded_revert_checks": self.folded_revert_checks,
        }

    def evaluator(self) -> PrintedExpressions:
        environment = {
            "msg.sender": self.caller,
            "tx.origin": self.caller,
            "msg.value": self.callvalue,
            "msg.data.length": len(self.calldata),
            "this": self.address,
            **{"block." + op.lower(): value for op, value in self.block_environment.items()},
        }
        return PrintedExpressions(self.names, environment, self.calldata)

    def _check_value(self, variable: str, statement: str) -> int:
        assert self.active is not None
        expression = self.active.value(variable)
        value = self.evaluator().value(expression.text)
        actual = self._value(variable)
        if value != actual:
            raise UnsupportedExecution(
                f"Printed operand disagrees at {statement}: {expression.text} = {value}, IR = {actual}"
            )
        self.expression_checks += 1
        return value

    def _function(self, function: Function, args: list[int]) -> list[int]:
        previous = self.active, self.names
        self.active = self.expressions[function.id]
        self.names = {
            self.active.name(function.formal_variables[i]): args[i]
            for i in self.interfaces.visible(function)
        }
        semantics = self.program.semantics
        if semantics:
            formals = dict(zip(function.formal_variables, args, strict=True))
            for arg in semantics.arguments:
                if arg.function != function.id:
                    continue
                values = {formals[v] for v in arg.variables if v in formals}
                if len(values) == 1:
                    value = next(iter(values))
                elif function.selectors:
                    offset = 4 + 32 * arg.index
                    value = int.from_bytes(self.calldata[offset : offset + 32].ljust(32, b"\0"))
                    if arg.index in self.active.calldata.root_info:
                        value = (value + 4) & MASK
                else:
                    raise UnsupportedExecution(
                        f"Printed argument frame unresolved at {function.id}"
                    )
                self.names[f"arg{arg.index}"] = value
            for index in self.active.calldata.root_info:
                base = self.names[f"arg{index}"]
                assert isinstance(base, int)
                self.names[f"cd_arg{index}"] = RawView(self.calldata, base)
        try:
            return super()._function(function, args)
        finally:
            self.active, self.names = previous

    def _copies(self, copies):
        assert self.active is not None
        values = [self._check_value(copy.source, copy.phi) for copy in copies]
        self.names.update(
            (self.active.name(copy.destination), value)
            for copy, value in zip(copies, values, strict=True)
        )
        super()._copies(copies)

    def _block(self, block_id: str, plan: FlowPlan):
        super()._block(block_id, plan)
        transfer = plan.transfers[block_id]
        if transfer.kind == "if" and transfer.predicate:
            assert self.active is not None
            for nonzero in (False, True):
                expression = self.active.condition(transfer.predicate, nonzero)
                result = self.evaluator().value(expression.text)
                expected = bool(self._value(transfer.predicate)) == nonzero
                if result != expected:
                    raise UnsupportedExecution(
                        f"Printed condition disagrees at {block_id}: {expression.text} = {result}, "
                        f"IR predicate {transfer.predicate} = {self._value(transfer.predicate)}"
                    )
                self.expression_checks += 1

    def _storage_index(self, term: Term, statement: str) -> int | None:
        if term.constructor == "ConstantIndex":
            return int(atom(term, 0), 16)
        parent = self._storage_index(child(term), statement)
        if parent is None:
            return None
        if term.constructor == "OffsetIndex":
            return (parent + int(atom(term, 1))) & MASK
        if term.constructor in {"MappingAccessIndex", "ArrayDataStartIndex"}:
            from eth_hash.auto import keccak

            prefix = (
                self._check_value(atom(term, 1), statement).to_bytes(32)
                if term.constructor == "MappingAccessIndex"
                else b""
            )
            return int.from_bytes(keccak(prefix + parent.to_bytes(32)))
        # Array indexes can denote elements with inferred packing/stride. Do not
        # assume one word per element until those semantics are established.
        return None

    def _instruction(self, stmt: Instruction, block_id: str):
        assert self.active is not None
        fold = self.revert_folds[self.active.local_names.function].get(block_id)
        if fold is not None:
            if stmt.id == fold.statement:
                expected = decode_revert_helper(fold.helper)
                actual = self._range(*(self._value(v) for v in stmt.operands))
                if expected != actual or expected.hex() != fold.payload_hex[2:]:
                    raise UnsupportedExecution(f"Printed folded revert disagrees at {stmt.id}")
                self.folded_revert_checks += 1
            # Hidden operations execute only in the IR frame. They do not
            # create printed assignments or supply values to printed operands.
            super()._instruction(stmt, block_id)
            return
        elided = self.active.elides(stmt)
        read_checks = []
        if not elided:
            for variable in self.interfaces.operands(block_id, stmt):
                self._check_value(variable, stmt.id)
            if stmt.opcode == "CALLPRIVATE" and (callee := self.interfaces.callee(block_id, stmt)):
                if callee.formal_variables:
                    self.private_call_checks += 1
                    self.private_interfaces_exercised.add(callee.id)
            semantics = self.program.semantics
            if semantics:
                for access in semantics.storage_accesses:
                    if access.statement != stmt.id:
                        continue
                    slot = self._storage_index(access.index, stmt.id)
                    proof = self.active.storage_reads_analysis.proof(access, stmt)
                    load = None
                    if proof:
                        source_block, source_index = self.active.storage_reads_analysis.positions[
                            proof.source_load
                        ]
                        load = self.blocks[source_block].instructions[source_index]
                    if stmt.opcode in {"SSTORE", "TSTORE"}:
                        physical = self._value(stmt.operands[0])
                    elif proof and load:
                        physical = self._value(load.operands[0])
                    else:
                        physical = None
                    if slot is None or physical is None:
                        self.storage_paths_unchecked += 1
                    elif slot != physical:
                        raise UnsupportedExecution(f"Printed storage path disagrees at {stmt.id}")
                    else:
                        self.storage_path_checks += 1
                        matching = [a for a in semantics.storage_accesses if a.statement == stmt.id]
                        if proof and len(matching) == 1:
                            storage = (
                                self.storage if access.location == "storage" else self.transient
                            )
                            read_checks.append(
                                (
                                    access.loaded_variables[0],
                                    (storage.get(slot, 0) >> proof.shift) & proof.mask,
                                )
                            )
                    for write in access.written_values:
                        if write.constructor == "VariableWrite":
                            self._check_value(atom(write, 0), stmt.id)
                for call in semantics.external_calls:
                    if call.statement == stmt.id:
                        for arg in call.arguments:
                            if len(arg.variables) == 1:
                                self._check_value(arg.variables[0], stmt.id)
            for layout in self.program.return_layouts:
                if layout.statement == stmt.id and layout.status == "raw_words":
                    for variable in layout.words:
                        self._check_value(variable, stmt.id)
        super()._instruction(stmt, block_id)
        for variable, expected_read in read_checks:
            if self._value(variable) != expected_read:
                raise UnsupportedExecution(f"Printed storage read disagrees at {stmt.id}")
            self.storage_read_checks += 1
        if not elided:
            for variable in stmt.definitions:
                value = self._value(variable)
                if stmt.opcode in PURE:
                    # The renderer emits generic helpers for retained pure defs.
                    rhs = (
                        f"evm.{stmt.opcode.lower()}("
                        + ", ".join(self.active.value(v).text for v in stmt.operands)
                        + ")"
                    )
                    if self.evaluator().value(rhs) != value:
                        raise UnsupportedExecution(
                            f"Printed retained assignment disagrees at {stmt.id}"
                        )
                    self.expression_checks += 1
                self.names[self.active.name(variable)] = value
