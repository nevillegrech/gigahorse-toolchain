"""Lift recovered IR into tree statements, following the structured flow plan."""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..controlflow import FlowPlan, Region, structure_function
from ..model import Block, Function, Instruction, Program
from ..presentation import InternalInterfaces
from ..render import PURE
from ..revert_folding import RevertFold, find_revert_folds
from ..reverts import analyze_reverts
from ..semantics import StorageAccess, Term, atom, child
from ..storage_reads import StorageReads
from .ir import (
    Assign,
    Binary,
    Call,
    Comment,
    Const,
    Emit,
    Env,
    Expr,
    ExprStmt,
    ExternalCallExpr,
    Halt,
    If,
    Index,
    Jump,
    Member,
    ParallelAssign,
    Raw,
    RawBlock,
    Return,
    Revert,
    Slice,
    Stmt,
    Unary,
    Var,
    While,
)
from .simplify import simplify

BINARY = {
    "ADD": "+",
    "SUB": "-",
    "MUL": "*",
    "DIV": "/",
    "MOD": "%",
    "EXP": "**",
    "AND": "&",
    "OR": "|",
    "XOR": "^",
    "EQ": "==",
    "LT": "<",
    "GT": ">",
    "SLT": "s<",
    "SGT": "s>",
    "SDIV": "s/",
    "SMOD": "s%",
}
ENVIRONMENT = {
    "CALLER": ("msg.sender", 160),
    "ORIGIN": ("tx.origin", 160),
    "ADDRESS": ("address(this)", 160),
    "COINBASE": ("block.coinbase", 160),
    "CALLVALUE": ("msg.value", 256),
    "CALLDATASIZE": ("msg.data.length", 256),
    "NUMBER": ("block.number", 256),
    "TIMESTAMP": ("block.timestamp", 256),
    "CHAINID": ("block.chainid", 256),
    "GASPRICE": ("tx.gasprice", 256),
    "BASEFEE": ("block.basefee", 256),
    "DIFFICULTY": ("block.prevrandao", 256),
    "PREVRANDAO": ("block.prevrandao", 256),
    "GASLIMIT": ("block.gaslimit", 256),
    "BLOBBASEFEE": ("block.blobbasefee", 256),
}
# Reads with no side effects. Unused results can be dropped from the view.
SIDE_EFFECT_FREE_READS = {
    "MLOAD",
    "SLOAD",
    "TLOAD",
    "SHA3",
    "BALANCE",
    "SELFBALANCE",
    "EXTCODESIZE",
    "EXTCODEHASH",
    "BLOCKHASH",
    "BLOBHASH",
    "GAS",
    "RETURNDATASIZE",
    "MSIZE",
    "CODESIZE",
    "PC",
}
CALLS = {"CALL", "CALLCODE", "STATICCALL", "DELEGATECALL"}
BOOLEAN_OPS = {"ISZERO", "EQ", "LT", "GT", "SLT", "SGT"}
TERMINATORS = {"RETURN", "REVERT", "STOP", "INVALID", "THROW", "SELFDESTRUCT"}
MEM = Env("MEM")
# Pure values are inlined into every use. A value used several times is copied
# into each, so chained reuse (e.g. Newton steps in mulDiv) doubles the printed
# size per step. Past this many nodes the value is printed once as a local.
# The largest inlined value in the fixtures has 72 nodes.
INLINE_SIZE_LIMIT = 128
# EVM stack inputs of opcodes the lifter reads by position. The native analysis
# can leave a stack value unresolved (seen in dead Vyper code): such a statement
# stays a raw EVM operation, marked UNCERTAIN, instead of being misread.
OPERAND_COUNTS = {
    "MLOAD": 1,
    "MSTORE": 2,
    "MSTORE8": 2,
    "SLOAD": 1,
    "SSTORE": 2,
    "TLOAD": 1,
    "TSTORE": 2,
    "SHA3": 2,
    "CALL": 7,
    "CALLCODE": 7,
    "DELEGATECALL": 6,
    "STATICCALL": 6,
    "CREATE": 3,
    "CREATE2": 4,
    "RETURN": 2,
    "REVERT": 2,
    "SELFDESTRUCT": 1,
    "CALLDATACOPY": 3,
    "CODECOPY": 3,
    "RETURNDATACOPY": 3,
    "MCOPY": 3,
    "EXTCODECOPY": 4,
    **{f"LOG{n}": n + 2 for n in range(5)},
}


def number(text: str) -> int:
    return int(text, 16)


@dataclass
class ProgramContext:
    program: Program
    blocks: dict[str, Block]
    statements: dict[str, Instruction]
    block_of: dict[str, str]
    definitions: dict[str, Instruction]
    uses: dict[str, list[Instruction]]
    constants: dict[str, int]
    interfaces: InternalInterfaces
    accesses: dict[str, list[StorageAccess]]
    externals: dict
    reverts: dict[str, dict]
    returns: dict[str, object]
    memory_args: dict[str, dict[int, list[str]]]
    consumer_writers: dict[str, set[str]]
    writer_consumers: dict[str, set[str]]
    plans: dict[str, FlowPlan] = field(default_factory=dict)
    folds: dict[str, dict[str, RevertFold]] = field(default_factory=dict)
    function_names: dict[str, str] = field(default_factory=dict)
    event_names: dict[str, str] = field(default_factory=dict)
    storage_names: dict[str, str] = field(default_factory=dict)
    # Printed storage root name -> (location, slot, low byte, high byte).
    storage_roots: dict[str, tuple[str, str, int, int]] = field(default_factory=dict)
    # Selector -> unique hash-checked signature text, for external calls.
    external_signatures: dict[str, str] = field(default_factory=dict)
    # Error selector -> its unique hash-checked signature text.
    error_signatures: dict[int, str] = field(default_factory=dict)
    # Public function id -> its unique hash-checked signature text.
    function_signatures: dict[str, str] = field(default_factory=dict)
    # Public function id -> (dictionary signature, argument bytes the ABI decoder
    # requires, the signature's head bytes) for names the code contradicts.
    rejected_signatures: dict[str, tuple[str, int, int]] = field(default_factory=dict)
    # Field types of ABI-coded structs -> printed struct name (shared by all functions).
    structs: dict[tuple[str, ...], str] = field(default_factory=dict)

    @classmethod
    def build(cls, program: Program, relations: Path | None = None) -> ProgramContext:
        statements = {s.id: s for b in program.blocks for s in b.instructions}
        block_of = {s.id: b.id for b in program.blocks for s in b.instructions}
        definitions = {v: s for s in statements.values() for v in s.definitions}
        uses: defaultdict[str, list[Instruction]] = defaultdict(list)
        for stmt in statements.values():
            for operand in stmt.operands:
                uses[operand].append(stmt)
        raw_constants = program.semantics.constants if program.semantics else program.constants
        constants = {}
        for variable, value in raw_constants.items():
            try:
                constants[variable] = number(value)
            except ValueError:
                continue
        accesses: defaultdict[str, list[StorageAccess]] = defaultdict(list)
        externals = {}
        memory_args: dict[str, dict[int, list[str]]] = {}
        if program.semantics:
            for access in program.semantics.storage_accesses:
                accesses[access.statement].append(access)
            externals = {c.statement: c for c in program.semantics.external_calls}
            memory_args = program.semantics.memory_values
        consumer_writers: defaultdict[str, set[str]] = defaultdict(set)
        writer_consumers: defaultdict[str, set[str]] = defaultdict(set)
        for consumer, writer in memory_links(relations, statements):
            consumer_writers[consumer].add(writer)
            writer_consumers[writer].add(consumer)
        context = cls(
            program,
            {b.id: b for b in program.blocks},
            statements,
            block_of,
            definitions,
            dict(uses),
            constants,
            InternalInterfaces(program),
            dict(accesses),
            externals,
            {r["statement"]: r for r in analyze_reverts(program)},
            {r.statement: r for r in program.return_layouts},
            memory_args,
            dict(consumer_writers),
            dict(writer_consumers),
        )
        for function in program.functions:
            plan = structure_function(
                program,
                function,
                ignore_failure_paths=True,
                split_shared_returns=True,
                public_tail_jumps=True,
            )
            context.plans[function.id] = plan
            context.folds[function.id] = find_revert_folds(program, function, plan, context.reverts)
        return context


@dataclass
class LiftedFunction:
    function: Function
    body: list[Stmt]
    arguments: list[Var]
    structured: bool
    warnings: list[str]
    locals: dict[str, str]
    # Storage reads inlined at use sites need no assignment.
    notes: list[Stmt] = field(default_factory=list)


class FunctionLifter:
    def __init__(self, context: ProgramContext, function: Function):
        self.context = context
        self.program = context.program
        self.function = function
        self.plan = context.plans.get(function.id)
        self.folds = context.folds.get(function.id, {})
        self.members = set(function.blocks)
        self.names: dict[str, str] = {}
        self.cache: dict[str, Expr] = {}
        self.local_counter = 0
        self.arguments: list[Var] = []
        self.warnings: list[str] = []
        self.argument_evidence: set[str] = set()
        # Public argument name -> how the IR computes it from calldata.
        self.argument_definitions: dict[str, Expr] = {}
        self.argument_kinds: dict[str, str] = {}
        self.arity_note: str | None = None
        # Memory consumers (LOG/RETURN/SHA3/CALL ids) -> MSTOREs feeding them.
        self.consumer_writers: dict[str, set[str]] = defaultdict(set)
        for consumer, writers in context.consumer_writers.items():
            self.consumer_writers[consumer] |= writers
        # Consumers whose memory input is fully represented by the printed line.
        self.abstracted: set[str] = set()
        self.storage_reads = StorageReads(self.program, function)
        # MLOAD statement id -> external call whose returned word it reads.
        self.returned_words: dict[str, str] = {}
        self._proven: dict[str, tuple[Expr, frozenset[str]] | None] = {}
        # Pure values printed as locals because their inlined form is too large.
        self.size_limited: set[str] = set()
        self._bind_arguments()

    # --- naming -----------------------------------------------------------

    def _bind_arguments(self) -> None:
        semantics = self.program.semantics
        if self.function.selectors and semantics:
            by_index: dict[int, list[str]] = defaultdict(list)
            for argument in semantics.arguments:
                if argument.function == self.function.id:
                    by_index[argument.index].extend(argument.variables)
            kinds = {
                argument.index: argument.kind
                for argument in semantics.arguments
                if argument.function == self.function.id
            }
            inferred = max(by_index) + 1 if by_index else 0
            signature = self.context.function_signatures.get(self.function.id)
            count = inferred
            head = decoder_head_size(self.context, self.function)
            if signature is None and head is not None and head // 32 < inferred:
                # The ABI decoder checks a head of `head` bytes: words read beyond it
                # are in the tail of a dynamic argument, not parameters of their own.
                count = head // 32
                self.arity_note = (
                    f"calldata words beyond the {count}-word head the ABI decoder checks "
                    "are read (printed as msg.data[...])"
                )
            if signature is not None:
                # Head words, not parameters: a static tuple parameter spans several.
                params = head_params(signature_params(signature))
                if len(params) < inferred:
                    # Extra calldata words are read (e.g. by a logging modifier) but the
                    # hash-matched signature has fewer head words: print them as reads.
                    count = len(params)
                    self.arity_note = (
                        f"calldata words beyond the {len(params)} head word(s) of the matched "
                        f"signature {signature} are read (printed as msg.data[...])"
                    )
                elif len(params) > inferred:
                    count = len(params)
            for index in range(count):
                name = f"varg{index}"
                if index >= inferred:
                    self.argument_kinds[name] = "unread"
                    self.arguments.append(Var(name, None))
                    continue
                self.argument_kinds[name] = kinds.get(index, "word")
                # The native model can attach unrelated calldata reads to an
                # argument (e.g. a modifier reading the selector word); bind only
                # variables that load this argument's own head word.
                variables = [
                    v
                    for v in by_index.get(index, [])
                    if self._loads_argument(v, index, self.argument_kinds[name])
                ]
                rejected = sorted(set(by_index.get(index, [])) - set(variables))
                if rejected:
                    self.warnings.append(
                        f"{name}: native argument variables {rejected} do not load its head word"
                    )
                for variable in variables:
                    self.names[variable] = name
                self.arguments.append(Var(name, variables[0] if variables else None))
        elif not self.function.selectors:
            visible = self.context.interfaces.visible(self.function)
            for position, index in enumerate(visible):
                variable = self.function.formal_variables[index]
                name = f"varg{position}"
                self.names[variable] = name
                self.arguments.append(Var(name, variable))

    def _loads_argument(self, variable: str, index: int, kind: str) -> bool:
        head = 4 + 32 * index
        stmt = self.context.definitions.get(variable)
        if stmt is None:
            return False

        def is_head_load(var: str) -> bool:
            load = self.context.definitions.get(var)
            return (
                load is not None
                and load.opcode == "CALLDATALOAD"
                and len(load.operands) == 1
                and self.context.constants.get(load.operands[0]) == head
            )

        if kind == "word":
            return is_head_load(variable)
        # Dynamic arguments: 4 + the head word (an offset), in either operand order.
        return (
            stmt.opcode == "ADD" and any(is_head_load(v) for v in stmt.operands)
        ) or is_head_load(variable)

    def local(self, variable: str) -> Var:
        if variable not in self.names:
            self.names[variable] = f"v{self.local_counter}"
            self.local_counter += 1
        return Var(self.names[variable], variable)

    # --- expressions ------------------------------------------------------

    def expr(self, variable: str, depth: int = 0) -> Expr:
        if variable in self.cache:
            return self.cache[variable]
        result = self._expr(variable, depth)
        if depth == 0 or not isinstance(result, Var):
            self.cache[variable] = result
        return result

    def _expr(self, variable: str, depth: int) -> Expr:
        stmt = self.context.definitions.get(variable)
        evidence = frozenset({stmt.id}) if stmt else frozenset()
        if variable in self.names and (
            stmt is None or stmt.opcode not in PURE or self.names[variable].startswith("varg")
        ):
            return Var(self.names[variable], variable, evidence=evidence)
        if variable in self.context.constants:
            value = self.context.constants[variable]
            if stmt is not None and stmt.opcode in BOOLEAN_OPS and value in (0, 1):
                # e.g. `return true` encoded as iszero(iszero(1)) and folded natively.
                return Env(
                    "true" if value else "false", 1, evidence=self.constant_evidence(variable)
                )
            return Const(value, evidence=self.constant_evidence(variable))
        if stmt is None:
            return self.local(variable)
        if self.proven_read(variable) is not None:
            return Var(self.local(variable).name, variable, evidence=evidence)
        if (
            stmt.opcode not in PURE
            or len(stmt.definitions) != 1
            or depth > 40
            or variable in self.size_limited
        ):
            return Var(self.local(variable).name, variable, evidence=evidence)
        if variable in self.names:
            return Var(self.names[variable], variable, evidence=evidence)
        node = self.pure_node(stmt, [self.expr(v, depth + 1) for v in stmt.operands])
        if node is None:
            return Var(self.local(variable).name, variable, evidence=evidence)
        # Operands are at most INLINE_SIZE_LIMIT nodes each, so this stays bounded.
        result = simplify(node)
        if result.size() > INLINE_SIZE_LIMIT:
            self.size_limited.add(variable)
            return Var(self.local(variable).name, variable, evidence=evidence)
        return result

    def proven_read(self, variable: str) -> tuple[Expr, frozenset[str]] | None:
        """A pure extraction (AND/shift of an SLOAD) proven to equal a storage field read."""
        if variable in self._proven:
            return self._proven[variable]
        self._proven[variable] = None
        stmt = self.context.definitions.get(variable)
        if stmt is None or stmt.opcode not in PURE:
            return None
        for access in self.context.accesses.get(stmt.id, []):
            if access.loaded_variables != [variable]:
                continue
            proof = self.storage_reads.proof(access, stmt)
            path = self.storage_path(access) if proof else None
            if proof and path is not None:
                self._proven[variable] = (path, frozenset(proof.evidence) | {stmt.id})
                break
        return self._proven[variable]

    def constant_evidence(self, variable: str) -> frozenset[str]:
        """A natively folded constant depends on the pure computation that produced it."""
        result: set[str] = set()
        todo = [variable]
        while todo and len(result) < 256:
            current = todo.pop()
            stmt = self.context.definitions.get(current)
            if stmt is None or stmt.id in result:
                continue
            result.add(stmt.id)
            if stmt.opcode in PURE:
                todo.extend(stmt.operands)
        return frozenset(result)

    def pure_node(self, stmt: Instruction, args: list[Expr]) -> Expr | None:
        op = stmt.opcode
        ev = frozenset({stmt.id})
        if op in BINARY and len(args) == 2:
            return Binary(BINARY[op], args[0], args[1], evidence=ev)
        if op in {"SHL", "SHR", "SAR"} and len(args) == 2:
            symbol = {"SHL": "<<", "SHR": ">>", "SAR": "s>>"}[op]
            node: Expr = Binary(symbol, args[1], args[0], evidence=ev)
            if (
                op == "SHR"
                and isinstance(args[0], Const)
                and args[0].value == 224
                and isinstance(args[1], Index)
                and args[1].base == Env("msg.data")
                and isinstance(args[1].key, Const)
                and args[1].key.value == 0
            ):
                node = Env(
                    "msg.sig",
                    32,
                    evidence=ev | args[1].all_evidence() | args[0].evidence,
                    rules=frozenset({"selector"}),
                )
            return node
        if op == "ISZERO" and len(args) == 1:
            return Unary("!", args[0], evidence=ev)
        if op == "NOT" and len(args) == 1:
            return Unary("~", args[0], evidence=ev)
        if op in ENVIRONMENT and not args:
            name, width = ENVIRONMENT[op]
            return Env(name, width, evidence=ev)
        if op == "CALLDATALOAD" and len(args) == 1:
            return Index(Env("msg.data"), args[0], evidence=ev)
        if op == "MOV" and len(args) == 1:
            return args[0]
        if (
            op == "SIGNEXTEND"
            and len(args) == 2
            and isinstance(args[0], Const)
            and args[0].value < 31
        ):
            return Call(f"int{8 * (args[0].value + 1)}", (args[1],), evidence=ev)
        if op in {"BYTE", "SIGNEXTEND", "ADDMOD", "MULMOD"}:
            return Call(op.lower(), tuple(args), evidence=ev)
        return None

    def condition(self, variable: str, nonzero: bool = True) -> Expr:
        value = self.expr(variable)
        if nonzero:
            return value
        return simplify(Unary("!", value))

    # --- storage ------------------------------------------------------------

    def storage_path(self, access: StorageAccess) -> Expr | None:
        def index(term: Term) -> Expr:
            if term.constructor == "ConstantIndex":
                slot = hex(int(atom(term, 0), 16))
                return Var(storage_root_name(self.context, access.location, slot), None)
            parent = index(child(term))
            if term.constructor in {
                "MappingAccessIndex",
                "ArrayAccessIndex",
                "StaticArrayAccessIndex",
            }:
                key_var = atom(term, 2 if term.constructor == "StaticArrayAccessIndex" else 1)
                kind = {
                    "MappingAccessIndex": "mapping",
                    "ArrayAccessIndex": "array",
                    "StaticArrayAccessIndex": "static_array",
                }[term.constructor]
                key = self.expr(key_var)
                if kind != "mapping":
                    stride = self.array_stride(access, key)
                    if stride is not None:
                        kind = f"{kind}:{stride}"
                return Index(parent, key, kind=kind)
            if term.constructor == "OffsetIndex":
                return Member(parent, f"field{int(atom(term, 1))}")
            if term.constructor == "ArrayDataStartIndex":
                return Member(parent, "data")
            raise ValueError(term.constructor)

        try:
            result = index(access.index)
        except (ValueError, IndexError):
            return None
        construct = access.construct
        if construct.constructor == "TightlyPackedVariable":
            low, high = int(atom(construct, 1)), int(atom(construct, 2))
            if child(construct).constructor == "Constant":
                slot = hex(int(atom(child(construct), 0), 16))
                return Var(storage_field_name(self.context, access.location, slot, low, high), None)
            result = Call(f"packed_bytes_{low}_{high}", (result,))
        if access.kind == "LENGTH":
            result = Member(result, "length")
        return result

    def array_stride(self, access: StorageAccess, key: Expr) -> int | None:
        """Words per element, read off the accessed slot: base + key * k (+ field offset).

        Only the access instruction's own slot arithmetic is used; anything else
        leaves the stride unknown (the printed path is then not executable).
        """
        stmt = self.context.statements.get(access.statement)
        if stmt is None or not stmt.operands:
            return None
        slot = self.expr(stmt.operands[0])
        terms: list[Expr] = []

        def collect(node: Expr) -> None:
            if isinstance(node, Binary) and node.op == "+":
                collect(node.left)
                collect(node.right)
            else:
                terms.append(node)

        collect(slot)
        for term in terms:
            if term == key:
                return 1
            if isinstance(term, Binary) and term.op == "*":
                for a, b in ((term.left, term.right), (term.right, term.left)):
                    if a == key and isinstance(b, Const) and 0 < b.value < 1 << 32:
                        return b.value
            if isinstance(term, Binary) and term.op == "<<" and term.left == key:
                if isinstance(term.right, Const) and term.right.value < 32:
                    return 1 << term.right.value
        return None

    # --- statements -------------------------------------------------------

    def lift(self) -> LiftedFunction:
        plan = self.plan
        body: list[Stmt] = []
        structured = bool(plan and plan.region)
        if self.arity_note:
            body.append(Comment("UNCERTAIN: " + self.arity_note, uncertain=self.arity_note))
        if plan and plan.region:
            for warning in plan.warnings:
                body.append(Comment("UNCERTAIN: " + warning, uncertain=warning))
            if plan.entry_copies:
                body.append(
                    ParallelAssign(
                        tuple(self.local(c.destination) for c in plan.entry_copies),
                        tuple(self.expr(c.source) for c in plan.entry_copies),
                        evidence=frozenset(c.phi for c in plan.entry_copies),
                        note="function-entry PHI values",
                    )
                )
            body.extend(self.region(plan.region))
            reached = {plan.origin.get(n, n) for n in plan.reachable_blocks}
            unreachable = [b for b in self.function.blocks if b not in reached]
            for block_id in unreachable:
                body.append(
                    RawBlock(
                        f"unreachable_block_{block_id}",
                        self.block(block_id, raw=True),
                        uncertain="unreachable in the recovered CFG",
                    )
                )
        else:
            reason = "; ".join(plan.warnings) if plan else "no flow plan"
            body.append(
                Comment(
                    "UNCERTAIN: control flow not structured ("
                    + reason
                    + "); explicit blocks follow",
                    uncertain=reason,
                )
            )
            for block_id in self.function.entries + [
                b for b in self.function.blocks if b not in self.function.entries
            ]:
                body.append(RawBlock(f"block_{block_id}", self.block(block_id, raw=True)))
        return LiftedFunction(
            self.function, body, self.arguments, structured, self.warnings, self.names
        )

    def region(self, region: Region) -> list[Stmt]:
        plan = self.plan
        assert plan is not None
        kind = region.kind
        if kind == "sequence":
            result: list[Stmt] = []
            for nested in region.children:
                result.extend(self.region(nested))
            return result
        if kind == "block":
            assert region.block is not None
            return self.block(region.block)
        if kind == "edge":
            copies = plan.copies.get((region.source or "", region.target or ""), [])
            if not copies:
                return []
            return [
                ParallelAssign(
                    tuple(
                        replace(self.local(c.destination), evidence=frozenset({c.phi}))
                        for c in copies
                    ),
                    tuple(self.expr(c.source) for c in copies),
                    evidence=frozenset(c.phi for c in copies),
                )
            ]
        if kind == "if":
            assert region.block is not None
            transfer = plan.transfers[region.block]
            assert transfer.predicate is not None and transfer.statement is not None
            condition = self.condition(transfer.predicate, not region.inverted)
            return [
                If(
                    condition,
                    self.region(region.children[0]),
                    self.region(region.children[1]),
                    evidence=frozenset({transfer.statement}),
                )
            ]
        if kind == "loop":
            return [While(self.region(region.children[0]), rules=frozenset({"natural-loop"}))]
        if kind in {"break", "continue"}:
            transfer = plan.transfers.get(region.source or "")
            evidence = (
                frozenset({transfer.statement}) if transfer and transfer.statement else frozenset()
            )
            return [Jump(kind, evidence=evidence)]
        raise ValueError(f"Unknown region kind {kind}")

    def block(self, node: str, *, raw: bool = False) -> list[Stmt]:
        # Split plans duplicate shared regions as '<block>@<n>' nodes over the same IR.
        block_id = self.plan.origin.get(node, node) if self.plan else node
        self.current_node = node
        block = self.context.blocks[block_id]
        if not raw and node == block_id and block_id in self.folds:
            fold = self.folds[block_id]
            if block_id != fold.block:
                return []
            info = self.context.reverts[fold.statement]
            self.abstracted.add(fold.statement)
            return [
                Revert(
                    revert_payload(info, self.context.error_signatures),
                    evidence=frozenset({fold.statement}),
                    hidden=frozenset(fold.ir_statements),
                    rules=frozenset({"revert-payload-fold"}),
                )
            ]
        result: list[Stmt] = []
        resolved = self.plan.resolved_phis if self.plan else set()
        self._track_scratch_writes(block)
        for stmt in block.instructions:
            if stmt.opcode == "PHI" and stmt.id in resolved and not raw:
                continue
            if stmt.opcode in {"JUMP", "JUMPI"}:
                if raw:
                    result.append(self.raw_jump(block, stmt))
                elif (
                    self.plan
                    and (transfer := self.plan.transfers.get(node)) is not None
                    and transfer.callee is not None
                ):
                    # Jump into another public function's entry: it never comes back.
                    name = self.context.function_names.get(transfer.callee, f"fn_{transfer.callee}")
                    result.append(
                        Return(
                            (Call(name, ()),),
                            evidence=frozenset({stmt.id}),
                            rules=frozenset({"tail-call", "jump-to-public-entry"}),
                        )
                    )
                continue
            result.extend(self.statement(block, stmt))
        if (
            raw
            and block.fallthrough
            and (
                not block.instructions
                or block.instructions[-1].opcode not in TERMINATORS | {"JUMP"}
            )
        ):
            result.append(Comment(f"fallthrough to block_{block.fallthrough[0]}"))
        return result

    def _track_scratch_writes(self, block: Block) -> None:
        """Link constant-address MSTOREs to a later SHA3 over a constant range in the same block.

        This syntactic fallback is used when the native writer/consumer relation is
        absent. Any other memory write, copy or call in between resets the record.
        """
        latest: dict[int, str] = {}
        for stmt in block.instructions:
            op = stmt.opcode
            if op == "MSTORE" and stmt.operands and stmt.operands[0] in self.context.constants:
                latest[self.context.constants[stmt.operands[0]]] = stmt.id
            elif op == "SHA3" and len(stmt.operands) == 2:
                start = self.context.constants.get(stmt.operands[0])
                size = self.context.constants.get(stmt.operands[1])
                if start is None or size is None or size % 32 or size > 128:
                    continue
                words = [latest.get(start + offset) for offset in range(0, size, 32)]
                if all(words) and not self.context.consumer_writers.get(stmt.id):
                    self.consumer_writers[stmt.id] |= {w for w in words if w}
            elif (
                op
                in {
                    "MSTORE",
                    "MSTORE8",
                    "MCOPY",
                    "CALLDATACOPY",
                    "CODECOPY",
                    "RETURNDATACOPY",
                    "EXTCODECOPY",
                }
                or op in CALLS
                or op == "CALLPRIVATE"
            ):
                latest.clear()

    def raw_jump(self, block: Block, stmt: Instruction) -> Stmt:
        targets = ", ".join(f"block_{t}" for t in block.successors) or "unresolved"
        if stmt.opcode == "JUMPI" and len(stmt.operands) == 2:
            condition = self.condition(stmt.operands[1])
            return If(
                condition, [Comment(f"goto one of: {targets}")], evidence=frozenset({stmt.id})
            )
        return Comment(f"goto {targets}", evidence=frozenset({stmt.id}))

    def statement(self, block: Block, stmt: Instruction) -> list[Stmt]:
        result = self._statement(block, stmt)
        # A printed line depends on every IR value its instruction consumed,
        # including operands the high-level form does not print (e.g. revert(0, 0)).
        operand_evidence = (
            frozenset().union(*(self.expr(v).all_evidence() for v in stmt.operands))
            if stmt.operands
            else frozenset()
        )
        for item in result:
            if item.origin is None:
                item.origin = stmt.id
            if (item.origin == stmt.id and not isinstance(item, Revert)) or not item.hidden:
                item.evidence = item.evidence | operand_evidence
        return result

    def _statement(self, block: Block, stmt: Instruction) -> list[Stmt]:
        op = stmt.opcode
        ev = frozenset({stmt.id})
        args = [self.expr(v) for v in stmt.operands]
        expected = OPERAND_COUNTS.get(op)
        if expected is not None and len(args) != expected:
            call = Call(op.lower(), tuple(args))
            reason = (
                f"{op} has {len(args)} of its {expected} operands in the IR "
                "(a stack value the analysis did not resolve)"
            )
            if stmt.definitions:
                targets = tuple(self.local(d) for d in stmt.definitions)
                return [Assign(targets, call, evidence=ev, uncertain=reason)]
            return [ExprStmt(call, evidence=ev, uncertain=reason)]
        if op in PURE and len(stmt.definitions) == 1:
            proven = self.proven_read(stmt.definitions[0])
            if proven is not None:
                path, proof_evidence = proven
                return [
                    Assign(
                        (self.local(stmt.definitions[0]),),
                        path,
                        evidence=ev | proof_evidence,
                        rules=frozenset({"storage-field-read"}),
                    )
                ]
            if self.names.get(stmt.definitions[0], "").startswith("varg"):
                self.argument_evidence.add(stmt.id)
                for operand in stmt.operands:
                    self.argument_evidence |= self.expr(operand).all_evidence()
                definition = self.pure_node(stmt, [self.expr(v) for v in stmt.operands])
                if definition is not None:
                    self.argument_definitions[self.names[stmt.definitions[0]]] = simplify(
                        definition
                    )
                return []
            node = self.expr(stmt.definitions[0])
            if isinstance(node, Var) and node.ssa == stmt.definitions[0]:
                # A pure value that could not be expressed inline.
                fallback = self.pure_node(stmt, args)
                if fallback is not None:
                    if stmt.definitions[0] in self.size_limited:
                        return [
                            Assign(
                                (node,),
                                simplify(fallback),
                                evidence=ev,
                                rules=frozenset({"inline-size-limit"}),
                                note=f"not inlined: over {INLINE_SIZE_LIMIT} nodes",
                            )
                        ]
                    return [Assign((node,), simplify(fallback), evidence=ev)]
            return []
        if op == "CONST":
            return []
        if op == "PHI":
            target = self.local(stmt.definitions[0])
            return [
                Assign(
                    (target,),
                    Call("phi", tuple(args)),
                    evidence=ev,
                    uncertain="PHI inputs are not associated with predecessors",
                )
            ]
        accesses = self.context.accesses.get(stmt.id, [])
        if op in {"SLOAD", "TLOAD"}:
            path = self.storage_path(accesses[0]) if len(accesses) == 1 else None
            space = "STORAGE" if op == "SLOAD" else "TSTORAGE"
            value = path if path is not None else Index(Env(space), args[0])
            return [
                Assign(
                    (self.local(stmt.definitions[0]),),
                    value,
                    evidence=ev,
                    rules=frozenset({"storage-path"} if path is not None else set()),
                )
            ]
        if op in {"SSTORE", "TSTORE"}:
            return self.storage_write(stmt, accesses, args)
        if op == "MLOAD":
            if stmt.id in self.returned_words:
                # Defined by the external call that returned it (named at the call).
                return []
            return [Assign((self.local(stmt.definitions[0]),), Index(MEM, args[0]), evidence=ev)]
        if op in {"MSTORE", "MSTORE8"}:
            space = MEM if op == "MSTORE" else Env("MEM8")
            return [Assign((Index(space, args[0]),), args[1], evidence=ev)]
        if op == "SHA3":
            value = Call(
                "keccak256", (Slice("MEM", args[0], simplify(Binary("+", args[0], args[1]))),)
            )
            return [Assign((self.local(stmt.definitions[0]),), value, evidence=ev)]
        if op in CALLS:
            return self.external_call(stmt, args)
        if op in {"CREATE", "CREATE2"}:
            payload = Slice("MEM", args[1], simplify(Binary("+", args[1], args[2])))
            call_args = (args[0], payload) + ((args[3],) if op == "CREATE2" else ())
            return [
                Assign((self.local(stmt.definitions[0]),), Call(op.lower(), call_args), evidence=ev)
            ]
        if op.startswith("LOG"):
            return [self.log(stmt, args)]
        if op == "RETURN":
            return [self.return_statement(stmt, args)]
        if op == "REVERT":
            info = self.context.reverts.get(stmt.id)
            payload = (
                revert_payload(info, self.context.error_signatures)
                if info and info["status"] == "static"
                else None
            )
            if payload is None and not (isinstance(args[1], Const) and args[1].value == 0):
                payload = Slice("MEM", args[0], simplify(Binary("+", args[0], args[1])))
            return [Revert(payload, evidence=ev)]
        if op == "STOP":
            return [Halt("stop", evidence=ev)]
        if op in {"INVALID", "THROW"}:
            return [Halt("invalid", evidence=ev)]
        if op == "SELFDESTRUCT":
            return [Halt("selfdestruct", args[0], evidence=ev)]
        if op == "CALLPRIVATE":
            return self.private_call(block, stmt, args)
        if op == "RETURNPRIVATE":
            return [Return(tuple(args[1:]), evidence=ev, rules=frozenset({"internal-return"}))]
        if op in {"CALLDATACOPY", "CODECOPY", "RETURNDATACOPY", "EXTCODECOPY", "MCOPY"}:
            return [ExprStmt(Call(op, tuple(args)), evidence=ev)]
        value = self.read(op, args)
        if value is not None and len(stmt.definitions) == 1:
            return [Assign((self.local(stmt.definitions[0]),), value, evidence=ev)]
        # Anything else stays visible as an EVM operation.
        call = Call(op.lower(), tuple(args))
        if stmt.definitions:
            return [Assign(tuple(self.local(d) for d in stmt.definitions), call, evidence=ev)]
        return [ExprStmt(call, evidence=ev)]

    def read(self, op: str, args: list[Expr]) -> Expr | None:
        if op == "BALANCE":
            return Member(args[0], "balance")
        if op == "SELFBALANCE":
            return Member(Env("address(this)", 160), "balance")
        if op == "EXTCODESIZE":
            return Member(Member(args[0], "code"), "length")
        if op == "EXTCODEHASH":
            return Member(args[0], "codehash")
        if op == "BLOCKHASH":
            return Call("blockhash", tuple(args))
        if op == "BLOBHASH":
            return Call("blobhash", tuple(args))
        if op == "GAS":
            return Call("gasleft")
        if op == "RETURNDATASIZE":
            return Member(Env("returndata"), "length")
        if op == "MSIZE":
            return Call("msize")
        if op == "CODESIZE":
            return Member(Member(Env("address(this)", 160), "code"), "length")
        return None

    def storage_write(
        self, stmt: Instruction, accesses: list[StorageAccess], args: list[Expr]
    ) -> list[Stmt]:
        ev = frozenset({stmt.id})
        space = "STORAGE" if stmt.opcode == "SSTORE" else "TSTORAGE"
        if len(accesses) == 1 and len(accesses[0].written_values) == 1:
            access = accesses[0]
            path = self.storage_path(access)
            written = access.written_values[0]
            if path is not None:
                if access.construct.constructor == "Variable":
                    return [
                        Assign((path,), args[1], evidence=ev, rules=frozenset({"storage-path"}))
                    ]
                if access.construct.constructor == "TightlyPackedVariable":
                    value: Expr | None = None
                    if written.constructor == "VariableWrite":
                        value = self.expr(atom(written, 0))
                    elif written.constructor == "ConstantWrite":
                        value = Const(number(atom(written, 0)))
                    if value is not None:
                        return [
                            Assign(
                                (path,),
                                value,
                                evidence=ev,
                                hidden=args[1].all_evidence(),
                                rules=frozenset({"packed-storage-write"}),
                                note="packed field update (native storage model); other bytes of the slot are preserved",
                            )
                        ]
        return [Assign((Index(Env(space), args[0]),), args[1], evidence=ev)]

    def abi_call(
        self, stmt: Instruction, kind: str, target: Expr, value: Expr | None, gas: Expr
    ) -> Assign | None:
        """target.method(args) from the native ABI-encoding model, with returned words named."""
        info = self.context.externals.get(stmt.id)
        if info is None or not info.selector_resolved or len(info.selector_candidates) != 1:
            return None
        arguments = sorted(info.arguments, key=lambda a: a.index)
        if [a.index for a in arguments] != list(range(len(arguments))) or any(
            len(a.variables) != 1 for a in arguments
        ):
            return None
        selector = info.selector_candidates[0]
        signature = self.context.external_signatures.get(selector)
        method = signature.split("(", 1)[0] if signature else selector
        # One entry per head word: static tuples/fixed arrays are inlined word by word.
        params = head_params(signature_params(signature)) if signature else None
        static = params is not None and all(is_static_abi(p) for p in params)
        uncertain = None
        if info.input_word_count == len(arguments):
            size_rule = "abi-words-counted"
        elif static and len(params or []) == len(arguments):
            size_rule = "abi-words-match-signature"
        else:
            size_rule = "abi-words-unverified"
            uncertain = "ABI input length not verified; arguments beyond those shown may exist"
        args = tuple(self.expr(a.variables[0]) for a in arguments)
        if params is not None and len(params) == len(args):
            # The native model gives a dynamic argument as a pointer to its encoded
            # value (length word first), not as a word: print it as such.
            args = tuple(
                arg if is_static_abi(param) else Call(dynamic_marker(param), (arg,))
                for arg, param in zip(args, params, strict=True)
            )
        returns = sorted((i, v) for i, v in info.return_variables.items() if i >= 0)
        low_level = -1 in info.return_variables and not returns
        if [i for i, _ in returns] != list(range(len(returns))) or any(
            len(v) != 1 for _, v in returns
        ):
            returns = []
        targets: list[Expr] = [self.local(stmt.definitions[0]) if stmt.definitions else Var("_")]
        hidden: set[str] = set()
        for _, variables in returns:
            variable = variables[0]
            targets.append(self.local(variable))
            definition = self.context.definitions.get(variable)
            if definition is not None:
                self.returned_words[definition.id] = stmt.id
                hidden.add(definition.id)
                for operand in definition.operands:
                    hidden |= self.expr(operand).all_evidence()
        call = ExternalCallExpr(
            kind,
            target,
            method if not low_level else None,
            args,
            value=value,
            gas=None if isinstance(gas, Call) and gas.name == "gasleft" else gas,
            evidence=frozenset({stmt.id}) | frozenset(info.evidence),
        )
        if low_level:
            # Raw .call with an ABI payload: returned bytes are not decoded.
            encoded = Call(
                "abi.encodeWithSelector",
                (Raw(selector + (f" /* {signature} */" if signature else "")), *args),
            )
            call = replace(call, raw_input=encoded, args=())
        if uncertain is None:
            # Only a call whose printed arguments cover its whole input represents it.
            self.abstracted.add(stmt.id)
        assign = Assign(
            tuple(targets),
            call,
            evidence=frozenset({stmt.id}),
            hidden=frozenset(hidden),
            rules=frozenset(
                {"external-abi-call", size_rule} | ({"external-return-words"} if returns else set())
            ),
            uncertain=uncertain,
        )
        if signature:
            assign.note = f"{signature} [dict]"
        if kind == "staticcall":
            assign.note = "staticcall" + (f"; {assign.note}" if assign.note else "")
        return assign

    def external_call(self, stmt: Instruction, args: list[Expr]) -> list[Stmt]:
        op = stmt.opcode
        ev = frozenset({stmt.id})
        has_value = op in {"CALL", "CALLCODE"}
        start = 3 if has_value else 2
        gas, target = args[0], args[1]
        value = args[2] if has_value else None
        in_offset, in_size, out_offset, out_size = args[start : start + 4]
        payload = Slice("MEM", in_offset, simplify(Binary("+", in_offset, in_size)))
        kind = {
            "CALL": "call",
            "CALLCODE": "callcode",
            "STATICCALL": "staticcall",
            "DELEGATECALL": "delegatecall",
        }[op]
        value = value if not (isinstance(value, Const) and value.value == 0) else None
        if kind in {"call", "staticcall"}:
            abstracted = self.abi_call(stmt, kind, target, value, gas)
            if abstracted is not None:
                abstracted.meta["output"] = (out_offset, out_size)
                abstracted.meta["input"] = (in_offset, simplify(Binary("+", in_offset, in_size)))
                return [abstracted]
        call = ExternalCallExpr(
            kind, target, None, (), value=value, gas=gas, raw_input=payload, evidence=ev
        )
        success = self.local(stmt.definitions[0]) if stmt.definitions else Var("_")
        assign = Assign((success,), call, evidence=ev)
        assign.meta["output"] = (out_offset, out_size)
        if not (isinstance(out_size, Const) and out_size.value == 0):
            assign.note = (
                f"output buffer MEM[{out_offset_text(out_offset)}:+{out_offset_text(out_size)}]"
            )
        return [assign]

    def log(self, stmt: Instruction, args: list[Expr]) -> Stmt:
        ev = frozenset({stmt.id})
        topics = args[2:]
        data = Slice("MEM", args[0], simplify(Binary("+", args[0], args[1])))
        words = self.memory_words(stmt.id, args[1])
        if topics and isinstance(topics[0], Const):
            topic = f"0x{topics[0].value:064x}"
            name = self.context.event_names.get(topic) or f"Event_{topic[2:10]}"
            if words is not None:
                self.abstracted.add(stmt.id)
                emit = Emit(
                    name, (*topics[1:], *words), evidence=ev, rules=frozenset({"abi-encoded-log"})
                )
            else:
                emit = Emit(
                    name,
                    (*topics[1:], data),
                    evidence=ev,
                    uncertain="event data layout not decoded; raw memory shown",
                )
            emit.indexed = len(topics) - 1
            return emit
        return ExprStmt(Call(f"log{len(topics)}", (data, *topics)), evidence=ev)

    def memory_words(self, consumer: str, size: Expr, offset: int = 0) -> tuple[Expr, ...] | None:
        """Complete 32-byte ABI words for a memory consumer from the native memory model."""
        if not isinstance(size, Const) or (size.value - offset) % 32 or size.value > 32 * 64:
            return None
        count = (size.value - offset) // 32
        actual = self.context.memory_args.get(consumer, {})
        if set(actual) != set(range(count)) or any(len(v) != 1 for v in actual.values()):
            return None
        variables = [actual[i][0] for i in range(count)]
        if any(v not in self.context.definitions and v not in self.names for v in variables):
            return None
        return tuple(self.expr(v) for v in variables)

    def return_statement(self, stmt: Instruction, args: list[Expr]) -> Stmt:
        ev = frozenset({stmt.id})
        layout = self.context.returns.get(stmt.id)
        if layout is not None and getattr(layout, "status", None) == "raw_words":
            values = tuple(self.expr(v) for v in layout.words)
            self.abstracted.add(stmt.id)
            return Return(
                values, evidence=ev | frozenset(layout.evidence), rules=frozenset({"return-words"})
            )
        if isinstance(args[1], Const) and args[1].value == 0:
            return Return((), evidence=ev)
        return Return(
            (), Slice("MEM", args[0], simplify(Binary("+", args[0], args[1]))), evidence=ev
        )

    def private_call(self, block: Block, stmt: Instruction, args: list[Expr]) -> list[Stmt]:
        ev = frozenset({stmt.id})
        callee = self.context.interfaces.callee(block.id, stmt)
        if callee is None:
            targets = sorted(self.context.interfaces.targets.get(block.id, set()))
            name = "private_call_unresolved"
            call = Call(name, tuple(args))
            uncertain = (
                "callee unresolved: " + ", ".join(targets) if targets else "callee unresolved"
            )
        else:
            inputs = tuple(args[i + 1] for i in self.context.interfaces.visible(callee))
            call = Call(self.context.function_names.get(callee.id, f"fn_{callee.id}"), inputs)
            uncertain = None
        targets = tuple(self.local(v) for v in stmt.definitions)
        node = getattr(self, "current_node", block.id)
        tail = bool(
            self.plan
            and self.plan.region
            and self.plan.transfers.get(node)
            and self.plan.transfers[node].kind == "end"
        )
        if tail:
            # Execution ends inside the callee (it halts the transaction).
            return [
                Return((call,), evidence=ev, uncertain=uncertain, rules=frozenset({"tail-call"}))
            ]
        if targets:
            return [Assign(targets, call, evidence=ev, uncertain=uncertain)]
        return [ExprStmt(call, evidence=ev, uncertain=uncertain)]


def out_offset_text(expr: Expr) -> str:
    from .printer import expression

    return expression(expr)


def revert_payload(info: dict | None, signatures: dict[int, str] | None = None) -> Expr | None:
    if info is None or info["status"] != "static":
        return None
    encoding = info["encoding"]
    if encoding == "empty":
        return None
    if encoding == "Error(string)" and info["reason"] is not None:
        from .ir import Raw
        from .printer import quote

        return Call("Error", (Raw(quote(info["reason"])),))
    if encoding == "Panic(uint256)":
        return Call(
            "Panic",
            (
                Const(
                    int(info["panic_code"], 16)
                    if isinstance(info["panic_code"], str)
                    else info["panic_code"]
                ),
            ),
        )
    if signatures:
        from .errors import static_error_payload

        named = static_error_payload(info["payload_hex"], signatures)
        if named is not None:
            return named
    from .ir import Raw

    return Raw(info["payload_hex"])


def storage_root_name(context: ProgramContext, location: str, slot: str) -> str:
    key = f"{location}:{slot}"
    if key in context.storage_names:
        return context.storage_names[key]
    prefix = "stor" if location == "storage" else "tstor"
    name = f"{prefix}_{int(slot, 16):x}"
    context.storage_roots[name] = (location, slot, 0, 31)
    return name


def storage_field_name(
    context: ProgramContext, location: str, slot: str, low: int, high: int
) -> str:
    key = f"{location}:{slot}:{low}:{high}"
    if key in context.storage_names:
        return context.storage_names[key]
    prefix = "stor" if location == "storage" else "tstor"
    name = f"{prefix}_{int(slot, 16):x}_{low}_{high}"
    context.storage_roots[name] = (location, slot, low, high)
    return name


STATIC_ABI = {"address", "bool", "string", "bytes"}


def signature_params(signature: str) -> list[str]:
    from .naming import split_signature

    return split_signature(signature)[1]


DYNAMIC_MARKERS = {"bytesAt", "stringAt", "arrayAt", "tupleAt", "dataAt"}


def static_words(param: str) -> list[str] | None:
    """Head-word types of a statically encoded ABI type; None for a dynamic type."""
    from .naming import split_signature

    if is_static_abi(param):
        return [param]
    if param.startswith("(") and param.endswith(")"):
        words: list[str] = []
        for component in split_signature("tuple" + param)[1]:
            inner = static_words(component)
            if inner is None:
                return None
            words += inner
        return words
    if param.endswith("]") and "[" in param:
        element, _, count = param[:-1].rpartition("[")
        inner = static_words(element)
        if count.isdigit() and inner is not None:
            return inner * int(count)
    return None


def decoder_head_size(context: ProgramContext, function: Function) -> int | None:
    """Argument bytes the ABI decoder requires: the largest N it compares
    `calldatasize - 4` against (`slt(sub(calldatasize(), 4), N)` or, via-IR,
    `add(calldatasize(), not(3))`). solc never requires more than the head of
    the declared parameters. None when the function has no such check."""
    blocks = {b.id: b for b in context.program.blocks}
    statements = [s for b in function.blocks if b in blocks for s in blocks[b].instructions]
    sizes = {v for v, s in context.definitions.items() if s.opcode == "CALLDATASIZE"}
    not3 = (1 << 256) - 4
    minus4: set[str] = set()
    for stmt in statements:
        if len(stmt.definitions) != 1 or len(stmt.operands) != 2:
            continue
        a, b = stmt.operands
        ca, cb = context.constants.get(a), context.constants.get(b)
        if (stmt.opcode == "SUB" and a in sizes and cb == 4) or (
            stmt.opcode == "ADD" and ((a in sizes and cb == not3) or (b in sizes and ca == not3))
        ):
            minus4.add(stmt.definitions[0])
    found = []
    for stmt in statements:
        if stmt.opcode not in {"LT", "GT", "SLT", "SGT"} or len(stmt.operands) != 2:
            continue
        a, b = stmt.operands
        ca, cb = context.constants.get(a), context.constants.get(b)
        if a in minus4 and cb is not None:
            found.append(cb if stmt.opcode in {"LT", "SLT"} else cb + 1)
        elif b in minus4 and ca is not None:
            found.append(ca if stmt.opcode in {"GT", "SGT"} else ca + 1)
    found = [n for n in found if 0 < n <= 32 * 256 and n % 32 == 0]
    return max(found) if found else None


def head_params(params: list[str]) -> list[str]:
    """Parameters as head words: static aggregates flattened, dynamic types kept whole."""
    result: list[str] = []
    for param in params:
        words = static_words(param)
        result += words if words is not None else [param]
    return result


def dynamic_marker(param: str) -> str:
    """Printed form of a dynamic ABI argument given by its memory pointer."""
    if param == "bytes":
        return "bytesAt"
    if param == "string":
        return "stringAt"
    if param.endswith("]"):
        return "arrayAt"
    return "tupleAt"


def is_static_abi(param: str) -> bool:
    """True for ABI types encoded in exactly one head word."""
    if param in {"address", "bool"}:
        return True
    if param.startswith(("uint", "int")) and param.lstrip("uint").isdigit():
        return True
    if param.startswith("bytes") and param[5:].isdigit():
        return True
    return param in {"uint", "int"}


def memory_links(relations: Path | None, statements: dict) -> list[tuple[str, str]]:
    """(consumer, writer) pairs from the stable export, or the debug relation.

    Rows naming unknown statements are rejected rather than silently dropped.
    """
    if relations is None:
        return []
    stable = relations / "SemanticMemoryConsumerWrite.csv"
    debug = relations / "MemWriteToMemConsStmtResolved.csv"
    rows: list[tuple[str, str]] = []
    if stable.is_file():
        with stable.open() as stream:
            for row in csv.reader(stream, delimiter="\t"):
                if len(row) != 5:
                    raise ValueError("SemanticMemoryConsumerWrite: wrong column count")
                rows.append((row[0], row[1]))
    elif debug.is_file():
        with debug.open() as stream:
            for row in csv.reader(stream, delimiter="\t"):
                if len(row) != 5:
                    raise ValueError("MemWriteToMemConsStmtResolved: wrong column count")
                rows.append((row[1], row[0]))
    for consumer, writer in rows:
        if consumer not in statements or writer not in statements:
            raise ValueError(f"Memory link references an unknown statement: {writer} -> {consumer}")
    return rows
