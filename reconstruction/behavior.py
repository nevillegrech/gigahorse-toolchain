"""Observed storage roles and forwarding paths, without contract-name heuristics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .controlflow import Unstructured, build_transfers, dominators
from .render import ENVIRONMENT, INFIX

if TYPE_CHECKING:
    from .model import Function, Instruction, Program

MASK = (1 << 256) - 1
ADDRESS_MASK = (1 << 160) - 1
SAFE_MEMORY = (
    set(INFIX)
    | set(ENVIRONMENT)
    | {
        "CONST",
        "MOV",
        "PHI",
        "ISZERO",
        "EQ",
        "LT",
        "GT",
        "SLT",
        "SGT",
        "SHL",
        "SHR",
        "SAR",
        "NOT",
        "DIV",
        "SDIV",
        "MOD",
        "SMOD",
        "ADDMOD",
        "MULMOD",
        "EXP",
        "BYTE",
        "SIGNEXTEND",
        "CALLDATALOAD",
        "SLOAD",
        "SSTORE",
        "TLOAD",
        "TSTORE",
        "JUMP",
        "JUMPI",
        "GAS",
        "MLOAD",
        "KECCAK256",
    }
)


@dataclass(frozen=True)
class Source:
    kind: str
    mask: int
    slot: str | None = None
    evidence: frozenset[str] = frozenset()


@dataclass
class CallerCheck:
    function: str
    block: str
    statement: str
    slot: str
    caller_mask: str
    storage_mask: str
    equal_when_nonzero: bool
    evidence: list[str]


@dataclass
class StorageRole:
    slot: str
    roles: list[str]
    alias: str | None
    evidence: list[str]


@dataclass
class DelegateSite:
    function: str
    statement: str
    target_slot: str | None
    whole_calldata: bool | None
    return_data_forwarding: str
    caller_gates: list[dict]
    evidence: list[str]
    limitations: list[str] = field(default_factory=list)


@dataclass
class BehaviorInfo:
    storage_roles: list[StorageRole]
    caller_checks: list[CallerCheck]
    delegate_sites: list[DelegateSite]
    schema_version: int = 1
    limitations: list[str] = field(
        default_factory=lambda: [
            "Roles describe observed uses, not original declarations or established admin privileges.",
            "Caller comparisons refer to values loaded at the evidence statements, not a postcondition on mutable storage.",
            "Summaries cover recovered CFG paths; unmapped bytecode, reentrancy and implementation behavior remain unresolved.",
        ]
    )


class BehaviorAnalysis:
    def __init__(self, program: Program):
        self.program = program
        self.blocks = {b.id: b for b in program.blocks}
        grouped = defaultdict(list)
        for block in program.blocks:
            for stmt in block.instructions:
                for variable in stmt.definitions:
                    grouped[variable].append(stmt)
        self.definitions = {v: ss[0] for v, ss in grouped.items() if len(ss) == 1}
        self.ambiguous_variables = {v for v, ss in grouped.items() if len(ss) != 1}
        self.constants = program.semantics.constants if program.semantics else program.constants

    def constant(self, variable: str) -> int | None:
        value = self.constants.get(variable)
        return int(value, 16) if value is not None else None

    def source(self, variable: str, seen: frozenset[str] = frozenset()) -> Source | None:
        stmt = self.definitions.get(variable)
        if stmt is None or variable in seen or len(seen) >= 16:
            return None
        evidence = frozenset({stmt.id})
        if stmt.opcode == "CALLER":
            return Source("caller", ADDRESS_MASK, evidence=evidence)
        if stmt.opcode == "SLOAD" and len(stmt.operands) == 1:
            slot = self.constant(stmt.operands[0])
            if slot is not None:
                constant_stmt = self.definitions.get(stmt.operands[0])
                return Source(
                    "storage",
                    MASK,
                    hex(slot),
                    evidence | ({constant_stmt.id} if constant_stmt else set()),
                )
        if stmt.opcode == "MOV" and len(stmt.operands) == 1:
            parent = self.source(stmt.operands[0], seen | {variable})
            if parent:
                return Source(parent.kind, parent.mask, parent.slot, parent.evidence | evidence)
        if stmt.opcode == "AND" and len(stmt.operands) == 2:
            for index, mask_variable in enumerate(stmt.operands):
                mask = self.constant(mask_variable)
                parent = self.source(stmt.operands[1 - index], seen | {variable})
                if mask is not None and parent and mask & parent.mask:
                    constant_stmt = self.definitions.get(mask_variable)
                    sources = evidence | ({constant_stmt.id} if constant_stmt else set())
                    return Source(
                        parent.kind, parent.mask & mask, parent.slot, parent.evidence | sources
                    )
        return None

    def check(self, function: Function, block: str, stmt: Instruction) -> CallerCheck | None:
        if stmt.opcode != "JUMPI" or len(stmt.operands) != 2:
            return None
        variable, equal = stmt.operands[1], True
        evidence = {stmt.id}
        seen: set[str] = set()
        while variable not in seen and len(seen) < 16:
            seen.add(variable)
            definition = self.definitions.get(variable)
            if definition is None:
                break
            evidence.add(definition.id)
            if definition.opcode in {"ISZERO", "MOV"} and len(definition.operands) == 1:
                equal ^= definition.opcode == "ISZERO"
                variable = definition.operands[0]
                continue
            if definition.opcode == "EQ" and len(definition.operands) == 2:
                sources = [self.source(v) for v in definition.operands]
                caller = next((s for s in sources if s and s.kind == "caller"), None)
                stored = next((s for s in sources if s and s.kind == "storage"), None)
                if caller and stored and stored.slot:
                    return CallerCheck(
                        function.id,
                        block,
                        stmt.id,
                        stored.slot,
                        hex(caller.mask),
                        hex(stored.mask),
                        equal,
                        sorted(evidence | caller.evidence | stored.evidence),
                    )
            break
        return None

    def identity(self, variable: str, seen: frozenset[str] = frozenset()) -> tuple:
        if variable in self.ambiguous_variables:
            return ("ambiguous", variable)
        value = self.constant(variable)
        if value is not None:
            return ("constant", value)
        stmt = self.definitions.get(variable)
        if stmt and variable not in seen and len(seen) < 16:
            if stmt.opcode == "CALLDATASIZE":
                return ("calldatasize",)
            if stmt.opcode == "MOV" and len(stmt.operands) == 1:
                return self.identity(stmt.operands[0], seen | {variable})
        return ("variable", variable)

    def whole_calldata(self, block: str, call: Instruction) -> tuple[bool, set[str]]:
        instructions = self.blocks[block].instructions
        if len(call.operands) != 6:
            return False, set()
        offset, size = (self.identity(v) for v in call.operands[2:4])
        if size != ("calldatasize",) or offset[0] == "ambiguous":
            return False, set()
        for stmt in reversed(instructions[: instructions.index(call)]):
            if stmt.opcode == "CALLDATACOPY" and len(stmt.operands) == 3:
                destination, source, length = (self.identity(v) for v in stmt.operands)
                if destination == offset and source == ("constant", 0) and length == size:
                    return True, {stmt.id}
                return False, set()
            if stmt.opcode not in SAFE_MEMORY:
                return False, set()
        return False, set()

    def boolean(
        self, variable: str, success: str, value: int, seen: frozenset[str] = frozenset()
    ) -> int | None:
        if variable == success:
            return value
        constant = self.constant(variable)
        if constant is not None:
            return constant
        stmt = self.definitions.get(variable)
        if stmt is None or variable in seen or len(seen) >= 16:
            return None
        args = [self.boolean(v, success, value, seen | {variable}) for v in stmt.operands]
        if any(v is None for v in args):
            return None
        if stmt.opcode == "ISZERO" and len(args) == 1:
            return int(args[0] == 0)
        if stmt.opcode == "EQ" and len(args) == 2:
            return int(args[0] == args[1])
        if stmt.opcode == "MOV" and len(args) == 1:
            return args[0]
        return None

    def returns(self, function: Function, block: str, call: Instruction) -> tuple[bool, set[str]]:
        if len(call.definitions) != 1 or self.definitions.get(call.definitions[0]) is not call:
            return False, set()
        try:
            transfers = build_transfers(self.program, function)
        except (Unstructured, KeyError):
            return False, set()
        evidence: set[str] = {call.id}
        for outcome in (0, 1):
            pending: list[tuple[str, int, frozenset[str], bool, frozenset[str]]] = [
                (
                    block,
                    self.blocks[block].instructions.index(call) + 1,
                    frozenset(),
                    False,
                    frozenset(),
                )
            ]
            budget, terminals = 4096, 0
            while pending:
                current, start, sizes, copied, seen = pending.pop()
                if current in seen:
                    return False, set()
                seen = seen | {current}
                stopped = False
                for stmt in self.blocks[current].instructions[start:]:
                    budget -= 1
                    if budget < 0:
                        return False, set()
                    evidence.add(stmt.id)
                    if any(self.definitions.get(v) is not stmt for v in stmt.definitions):
                        return False, set()
                    if stmt.opcode == "RETURNDATASIZE":
                        sizes |= frozenset(stmt.definitions)
                    elif (
                        stmt.opcode == "MOV"
                        and len(stmt.operands) == 1
                        and stmt.operands[0] in sizes
                    ):
                        sizes |= frozenset(stmt.definitions)
                    elif stmt.opcode == "RETURNDATACOPY" and len(stmt.operands) == 3:
                        copied = (
                            self.identity(stmt.operands[0]) == ("constant", 0)
                            and self.identity(stmt.operands[1]) == ("constant", 0)
                            and stmt.operands[2] in sizes
                        )
                    elif stmt.opcode in {"RETURN", "REVERT"} and len(stmt.operands) == 2:
                        if not (
                            copied
                            and self.identity(stmt.operands[0]) == ("constant", 0)
                            and stmt.operands[1] in sizes
                            and stmt.opcode == ("RETURN" if outcome else "REVERT")
                        ):
                            return False, set()
                        terminals += 1
                        stopped = True
                        break
                    elif stmt.opcode not in SAFE_MEMORY:
                        return False, set()
                if stopped:
                    continue
                transfer = transfers[current]
                targets = transfer.targets
                if transfer.kind == "if":
                    condition = self.boolean(transfer.predicate or "", call.definitions[0], outcome)
                    if condition is not None:
                        targets = (targets[0 if condition else 1],)
                if not targets:
                    return False, set()
                pending.extend((t, 0, sizes, copied, seen) for t in targets)
            if not terminals:
                return False, set()
        return True, evidence

    def gates(self, function: Function, block: str, checks: list[CallerCheck]) -> list[dict]:
        try:
            transfers = build_transfers(self.program, function)
            edges = {b: t.targets for b, t in transfers.items()}
            if len(function.entries) != 1:
                return []
            dom = dominators(function.entries[0], edges)

            def reaches(start: str) -> bool:
                seen, todo = set(), [start]
                while todo:
                    node = todo.pop()
                    if node == block:
                        return True
                    if node not in seen:
                        seen.add(node)
                        todo.extend(edges[node])
                return False

            results = []
            for check in checks:
                transfer = transfers[check.block]
                if check.block not in dom.get(block, set()) or transfer.kind != "if":
                    continue
                reaches_call = [reaches(t) for t in transfer.targets]
                if reaches_call.count(True) != 1:
                    continue
                matches = check.equal_when_nonzero == reaches_call[0]
                results.append(
                    {
                        "slot": check.slot,
                        "comparison": "equal" if matches else "not-equal",
                        "caller_mask": check.caller_mask,
                        "storage_mask": check.storage_mask,
                        "statement": check.statement,
                        "evidence": check.evidence,
                    }
                )
            return results
        except (Unstructured, KeyError):
            return []

    def run(self) -> BehaviorInfo:
        checks, sites = [], []
        role_sources: defaultdict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        for function in self.program.functions:
            local_checks = []
            for block in function.blocks:
                for stmt in self.blocks[block].instructions:
                    check = self.check(function, block, stmt)
                    if check:
                        local_checks.append(check)
                        role_sources[check.slot]["caller_check"].update(check.evidence)
            checks.extend(local_checks)
            for block in function.blocks:
                for stmt in self.blocks[block].instructions:
                    if stmt.opcode != "DELEGATECALL" or len(stmt.operands) != 6:
                        continue
                    target = self.source(stmt.operands[1])
                    if target and not target.mask & ADDRESS_MASK:
                        target = None
                    slot = target.slot if target and target.kind == "storage" else None
                    whole, input_evidence = self.whole_calldata(block, stmt)
                    returns, output_evidence = self.returns(function, block, stmt)
                    evidence = {stmt.id} | input_evidence | output_evidence
                    if target:
                        evidence.update(target.evidence)
                    if slot:
                        role_sources[slot]["delegate_target"].update(evidence)
                    gates = self.gates(function, block, local_checks)
                    evidence.update(s for g in gates for s in g["evidence"])
                    limitations = []
                    if not whole:
                        limitations.append(
                            "Whole calldata input is not established by a direct same-block copy."
                        )
                    if not returns:
                        limitations.append(
                            "Return/revert forwarding is not established for every recovered path."
                        )
                    if slot is None:
                        limitations.append(
                            "Delegate target is not a resolved constant storage slot load."
                        )
                    sites.append(
                        DelegateSite(
                            function.id,
                            stmt.id,
                            slot,
                            True if whole else None,
                            "established_in_recovered_cfg" if returns else "unresolved",
                            gates,
                            sorted(evidence),
                            limitations,
                        )
                    )
        field_counts: defaultdict[str, int] = defaultdict(int)
        if self.program.semantics:
            for allocation in self.program.semantics.storage_fields:
                if allocation.location == "storage":
                    field_counts[allocation.slot] += 1
        eligible = (
            {
                f.slot
                for f in self.program.semantics.storage_fields
                if f.location == "storage"
                and f.kind == "Variable"
                and (f.byte_low, f.byte_high) == (0, 31)
                and field_counts[f.slot] == 1
            }
            if self.program.semantics
            else set()
        )
        role_names = {
            slot: "role_" + "_".join(sorted(roles)) + "_word"
            for slot, roles in role_sources.items()
        }
        counts: defaultdict[str, int] = defaultdict(int)
        for name in role_names.values():
            counts[name] += 1
        roles = []
        for slot, sources in sorted(role_sources.items()):
            name = role_names[slot]
            if counts[name] > 1:
                # Full hexadecimal slot avoids alias collisions and truncated IDs.
                name += "_" + slot
            roles.append(
                StorageRole(
                    slot,
                    sorted(sources),
                    name if slot in eligible else None,
                    sorted(set().union(*sources.values())),
                )
            )
        return BehaviorInfo(roles, checks, sites)


def analyze_behavior(program: Program) -> BehaviorInfo:
    return BehaviorAnalysis(program).run()
