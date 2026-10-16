"""When an inferred storage accessor can replace a captured IR value.

Bit extraction and lifetime are checked in the recovered CFG. Storage addresses
remain native inferences and are checked separately by bounded execution.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .controlflow import Unstructured, build_transfers, dominators
from .model import Function, Instruction, Program
from .render import PURE
from .semantics import StorageAccess, Term, atom

MASK = (1 << 256) - 1
STORAGE_PRESERVING = PURE | {
    "PHI",
    "JUMP",
    "JUMPI",
    "SLOAD",
    "TLOAD",
    "MLOAD",
    "MSTORE",
    "MSTORE8",
    "MCOPY",
    "CALLDATACOPY",
    "CODECOPY",
    "CODESIZE",
    "MSIZE",
    "GAS",
    "GASPRICE",
    "BALANCE",
    "SELFBALANCE",
    "EXTCODESIZE",
    "EXTCODEHASH",
    "EXTCODECOPY",
    "RETURNDATASIZE",
    "RETURNDATACOPY",
    "SHA3",
    "KECCAK256",
    "CLZ",
    "PC",
    "LOG0",
    "LOG1",
    "LOG2",
    "LOG3",
    "LOG4",
    "BLOCKHASH",
    "COINBASE",
    "DIFFICULTY",
    "PREVRANDAO",
    "BASEFEE",
    "BLOBHASH",
    "BLOBBASEFEE",
    "GASLIMIT",
}
# Writes, world/private calls and unknown operations are deliberately absent.


@dataclass(frozen=True)
class StorageReadProof:
    function: str
    statement: str
    source_load: str
    shift: int
    mask: int
    evidence: tuple[str, ...]
    scope: str = (
        "Bit extraction and read lifetime in recovered CFG; native path address remains inferred."
    )


class StorageReads:
    def __init__(self, program: Program, function: Function):
        self.program, self.function = program, function
        self.blocks = {b.id: b for b in program.blocks}
        self.constants = program.semantics.constants if program.semantics else program.constants
        definitions = defaultdict(list)
        self.positions = {}
        for block in program.blocks:
            for index, stmt in enumerate(block.instructions):
                self.positions[stmt.id] = (block.id, index)
                for variable in stmt.definitions:
                    definitions[variable].append(stmt)
        self.definitions = {v: ss[0] for v, ss in definitions.items() if len(ss) == 1}
        self.cache: dict[tuple, StorageReadProof | None] = {}

    def _slice(self, variable: str, seen: frozenset[str] = frozenset()):
        stmt = self.definitions.get(variable)
        if stmt is None or variable in seen or len(seen) >= 24:
            return None
        if stmt.opcode in {"SLOAD", "TLOAD"} and len(stmt.operands) == 1:
            return stmt, 0, MASK, {stmt.id}
        if stmt.opcode == "MOV" and len(stmt.operands) == 1:
            result = self._slice(stmt.operands[0], seen | {variable})
            if result:
                load, shift, mask, evidence = result
                return load, shift, mask, evidence | {stmt.id}
        if stmt.opcode not in {"AND", "DIV", "SHR"} or len(stmt.operands) != 2:
            return None
        for index in (0, 1) if stmt.opcode == "AND" else (1,) if stmt.opcode == "DIV" else (0,):
            raw = self.constants.get(stmt.operands[index])
            if raw is None:
                continue
            constant = int(raw, 16)
            result = self._slice(stmt.operands[1 - index], seen | {variable})
            if result is None:
                continue
            load, shift, mask, evidence = result
            definition = self.definitions.get(stmt.operands[index])
            evidence |= {stmt.id} | ({definition.id} if definition else set())
            if stmt.opcode == "AND":
                return load, shift, mask & constant, evidence
            if stmt.opcode == "DIV":
                if constant == 0 or constant & (constant - 1):
                    continue
                amount = constant.bit_length() - 1
            else:
                amount = constant
            return load, min(256, shift + amount), mask >> min(256, amount), evidence
        return None

    def _alive(self, load: Instruction, stmt: Instruction, index: Term) -> bool:
        start, first = self.positions[load.id]
        end, last = self.positions[stmt.id]
        # An accessor's key must also retain its value if an alias spans a loop.
        variables: set[str] = set()

        def keys(term: Term):
            for arg in term.arguments:
                if isinstance(arg, Term):
                    keys(arg)
                elif arg in self.definitions:
                    variables.add(arg)

        keys(index)
        pending = list(variables)
        while pending:
            for operand in self.definitions[pending.pop()].operands:
                if operand in self.definitions and operand not in variables:
                    variables.add(operand)
                    pending.append(operand)

        def unchanged(statements):
            return all(
                s.opcode in STORAGE_PRESERVING and not variables.intersection(s.definitions)
                for s in statements
            )

        if start == end:
            return first <= last and unchanged(self.blocks[start].instructions[first + 1 : last])
        if (
            len(self.function.entries) != 1
            or start not in self.function.blocks
            or end not in self.function.blocks
        ):
            return False
        try:
            transfers = build_transfers(self.program, self.function)
            edges = {b: t.targets for b, t in transfers.items()}
            dom = dominators(self.function.entries[0], edges)
        except (Unstructured, KeyError):
            return False
        if start not in dom.get(end, set()):
            return False
        predecessors = defaultdict(set)
        for source, targets in edges.items():
            for target in targets:
                predecessors[target].add(source)
        todo, visited = [end], set()
        while todo:
            block = todo.pop()
            if block in visited:
                continue
            visited.add(block)
            instructions = self.blocks[block].instructions
            if block == start:
                if not unchanged(instructions[first + 1 :]):
                    return False
                continue
            if not unchanged(instructions[:last] if block == end else instructions):
                return False
            todo.extend(predecessors[block])
        return True

    def proof(self, access: StorageAccess, stmt: Instruction) -> StorageReadProof | None:
        key = (
            stmt.id,
            access.kind,
            access.location,
            access.index,
            access.construct,
            tuple(access.loaded_variables),
        )
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = None
        if (
            access.kind != "ACCESS"
            or len(access.loaded_variables) != 1
            or stmt.definitions != access.loaded_variables
        ):
            return None
        construct = access.construct.constructor
        if construct == "Variable":
            low, high = 0, 31
        elif construct == "TightlyPackedVariable":
            low, high = int(atom(access.construct, 1)), int(atom(access.construct, 2))
            if not 0 <= low <= high <= 31:
                return None
        else:
            return None
        result = self._slice(access.loaded_variables[0])
        if result is None:
            return None
        load, shift, mask, evidence = result
        if load.opcode != ("SLOAD" if access.location == "storage" else "TLOAD"):
            return None
        if shift != low * 8 or mask != (1 << (8 * (high - low + 1))) - 1:
            return None
        if access.index.constructor == "ConstantIndex":
            address = self.constants.get(load.operands[0])
            if address is None or int(address, 16) != int(atom(access.index, 0), 16):
                return None
        if load.id != stmt.id and not self._alive(load, stmt, access.index):
            return None
        proof = StorageReadProof(
            self.function.id, stmt.id, load.id, shift, mask, tuple(sorted(evidence))
        )
        self.cache[key] = proof
        return proof
