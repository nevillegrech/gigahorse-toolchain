"""Bounded constant/byte-memory verification on recovered CFGs and private calls.

Missing values are unknown. Joins keep only equal facts; unknown-address writes
forget all memory facts. This pass establishes numeric values in recovered CFGs,
not full bytecode equivalence.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .byte_memory import ByteMemory
from .bytecode import code_context, executed_code
from .controlflow import FlowPlan, structure_function

if TYPE_CHECKING:
    from .model import Function, Program


class ProofLimit(ValueError):
    pass


@dataclass
class State:
    values: dict[str, int]
    memory: ByteMemory

    def copy(self) -> State:
        return State(dict(self.values), self.memory.copy())

    def join(self, other: State) -> State:
        return State(
            {k: v for k, v in self.values.items() if other.values.get(k) == v},
            self.memory.join(other.memory),
        )


@dataclass
class Summary:
    returns: bool
    values: tuple[int | None, ...]
    memory: ByteMemory


@dataclass
class Verification:
    proven_native: set[str]
    derived: dict[str, str]
    metadata: dict
    reverts: dict[str, MemorySnapshot] = field(default_factory=dict)


@dataclass
class MemorySnapshot:
    size: int | None
    known: dict[int, int]

    def join(self, other: MemorySnapshot) -> MemorySnapshot:
        return MemorySnapshot(
            self.size if self.size == other.size else None,
            {k: v for k, v in self.known.items() if other.known.get(k) == v},
        )

    def to_dict(self) -> dict:
        ranges: list[dict] = []
        for offset, value in sorted(self.known.items()):
            if ranges and offset == ranges[-1]["offset"] + len(ranges[-1]["data"]) // 2:
                ranges[-1]["data"] += f"{value:02x}"
            else:
                ranges.append({"offset": offset, "data": f"{value:02x}"})
        return {"byte_length": self.size, "known_ranges": ranges}


def ir_fingerprint(program: Program, calls=(), call_returns=()) -> str:
    """Bind facts to executable IR and provenance, independently of display names."""
    content = {
        "bytecode_sha256": code_context(program)["sha256"],
        "functions": [(f.id, f.entries, f.formal_variables, f.blocks) for f in program.functions],
        "blocks": [
            (
                b.id,
                b.successors,
                b.fallthrough,
                [
                    (s.id, s.opcode, s.definitions, s.operands, s.original_statements)
                    for s in b.instructions
                ],
            )
            for b in program.blocks
        ],
        "targets": program.block_targets,
        "phis": program.phi_inputs,
        "phi_entry_inputs": program.phi_entry_inputs,
        "calls": sorted(calls),
        "call_returns": sorted(call_returns or ()),
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def proof_is_current(program: Program) -> bool:
    proof = program.constant_verification
    if proof.get("status") != "bounded_analysis" or "ir_sha256" not in proof:
        return False
    semantics = program.semantics
    calls, returns = (semantics.calls, semantics.call_returns) if semantics else ((), ())
    if proof["ir_sha256"] != ir_fingerprint(program, calls, returns):
        return False
    if proof.get("bytecode_input") != code_context(program):
        return False
    if proof.get("revert_memory_sha256") != snapshot_fingerprint(program.revert_memory):
        return False
    if proof.get("code_copy_observations_sha256") != snapshot_fingerprint(
        proof.get("code_copy_observations", [])
    ):
        return False
    constants = semantics.constants if semantics else program.constants
    try:
        return all(
            v in constants and int(constants[v], 16) == int(value, 16)
            for v, value in proof.get("literal_inputs", {}).items()
        )
    except (ValueError, TypeError):
        return False


def snapshot_fingerprint(snapshots: dict) -> str:
    return hashlib.sha256(json.dumps(snapshots, sort_keys=True).encode()).hexdigest()


class ConstantMemory:
    def __init__(self, program: Program, candidates: dict[str, str], calls, call_returns):
        self.program, self.candidates = program, {v: int(x, 16) for v, x in candidates.items()}
        self.code = executed_code(program)
        self.code_copies: dict[tuple, dict] = {}
        self.code_copy_records_limited = False
        self.functions = {f.id: f for f in program.functions}
        self.blocks = {b.id: b for b in program.blocks}
        definitions = defaultdict(list)
        for block in program.blocks:
            for stmt in block.instructions:
                for variable in stmt.definitions:
                    definitions[variable].append(stmt)
        formals = {v for f in program.functions for v in f.formal_variables}
        self.literals = {
            v: value
            for v, value in self.candidates.items()
            if v not in formals
            and (
                v not in definitions
                or (len(definitions[v]) == 1 and definitions[v][0].opcode == "CONST")
            )
        }
        self.calls: defaultdict[str, set[str]] = defaultdict(set)
        self.literal_inputs = {
            **self.literals,
            **{
                v: self.candidates[v]
                for v, stmts in definitions.items()
                if v in self.candidates and any(s.opcode == "CONST" for s in stmts)
            },
        }
        for block, callee in calls:
            self.calls[block].add(callee)
        self.call_returns = call_returns
        self.plans: dict[str, FlowPlan] = {}
        self.cache: dict[tuple, Summary] = {}
        self.active: set[tuple] = set()
        self.good: set[str] = set()
        self.bad: set[str] = set()
        self.observed: dict[str, int] = {}
        self.unknown: set[str] = set()
        self.evidence: set[str] = set()
        self.opaque_functions: set[str] = set()
        self.opaque_reachable: set[str] = set()
        self.opaque_tail_calls: set[str] = set()
        self.reverts: dict[str, MemorySnapshot] = {}
        self.unknown_reverts: set[str] = set()
        self.limited_reverts: set[str] = set()
        self.steps = 0

    def record(self, variable: str, value: int | None):
        if variable in self.candidates:
            (self.good if value == self.candidates[variable] else self.bad).add(variable)
        if value is None or (variable in self.observed and self.observed[variable] != value):
            self.unknown.add(variable)
        elif value is not None:
            self.observed[variable] = value

    def value(self, state: State, variable: str) -> int | None:
        return state.values.get(variable, self.literals.get(variable))

    def forget(self, state: State, offset: int | None, length: int | None):
        state.memory.forget(offset, length)

    def codecopy(self, statement: str, args: list[int | None], state: State):
        destination, source, size = args if len(args) == 3 else (None, None, None)
        self.forget(state, destination, size)
        data = None
        status = "unresolved_range"
        if size == 0:
            data, status = b"", "zero_length_no_op"
        elif self.code is None:
            status = "bytecode_unavailable"
        elif size is not None and size > 4096:
            status = "copy_bound_exceeded"
        elif destination is not None and source is not None and size is not None:
            # CODECOPY source indexing does not wrap; reads beyond code are zero.
            data = self.code[source : source + size].ljust(size, b"\0")
            status = "established_bytes"
            state.memory.update((destination + i, value) for i, value in enumerate(data))
        key = statement, destination, source, size
        if len(self.code_copies) < 4096 or key in self.code_copies:
            code_length = len(self.code) if self.code is not None else None
            in_bounds = (
                min(size, max(0, code_length - source))
                if code_length is not None and source is not None and size is not None
                else None
            )
            self.code_copies[key] = {
                "statement": statement,
                "memory_offset": hex(destination) if destination is not None else None,
                "source_offset": hex(source) if source is not None else None,
                "byte_length": size,
                "status": status,
                "input_byte_range": [source, source + in_bounds]
                if source is not None and in_bounds
                else None,
                "zero_padded_bytes": size - in_bounds
                if size is not None and in_bounds is not None
                else None,
                "copied_bytes_sha256": hashlib.sha256(data).hexdigest()
                if data is not None
                else None,
            }
        else:
            self.code_copy_records_limited = True

    def invalidate_functions(self, functions: set[str]):
        pending = list(functions)
        visited: set[str] = set()
        while pending:
            ident = pending.pop()
            if ident in visited or ident not in self.functions:
                continue
            visited.add(ident)
            function = self.functions[ident]
            unknown = set(function.formal_variables)
            for block in function.blocks:
                for stmt in self.blocks[block].instructions:
                    unknown.update(stmt.definitions)
                    if stmt.opcode == "REVERT":
                        self.unknown_reverts.add(stmt.id)
                    if stmt.opcode == "CALLPRIVATE":
                        callees = self.calls[block]
                        if not callees and stmt.operands:
                            target = self.literals.get(stmt.operands[0])
                            callees = {
                                f.id
                                for f in self.functions.values()
                                if target is not None and hex(target) in f.entries
                            }
                        pending.extend(callees or self.functions.keys())
            self.bad.update(unknown)
            self.unknown.update(unknown)
        self.opaque_reachable.update(visited)

    def unknown_function(self, function: Function) -> Summary:
        self.opaque_functions.add(function.id)
        self.invalidate_functions({function.id})
        return Summary(True, (), ByteMemory())

    def capture_revert(self, statement: str, args: list[int | None], state: State):
        offset, size = args if len(args) == 2 else (None, None)
        snapshot = MemorySnapshot(size, {})
        if size is not None and 0 <= size <= 4096 and offset is not None:
            snapshot.known = {
                i: state.memory[offset + i] for i in range(size) if offset + i in state.memory
            }
        if statement in self.reverts:
            snapshot = self.reverts[statement].join(snapshot)
        total = sum(len(s.known) for key, s in self.reverts.items() if key != statement)
        if total + len(snapshot.known) > 65536:
            self.limited_reverts.add(statement)
            snapshot = MemorySnapshot(None, {})
        self.reverts[statement] = snapshot

    def function(
        self, function: Function, arguments: tuple[int | None, ...], memory: ByteMemory
    ) -> Summary:
        key = (function.id, arguments, memory.fingerprint())
        if key in self.cache:
            return self.cache[key]
        if key in self.active or len(self.active) >= 32 or len(self.cache) >= 512:
            return self.unknown_function(function)
        if len(function.entries) != 1 or len(arguments) != len(function.formal_variables):
            return self.unknown_function(function)
        if function.id not in self.plans:
            self.plans[function.id] = structure_function(
                self.program, function, call_returns=self.call_returns
            )
        plan = self.plans[function.id]
        if (
            set(plan.transfers) != set(function.blocks)
            or plan.unresolved_phis
            or any(t.kind not in {"goto", "if", "end"} for t in plan.transfers.values())
        ):
            return self.unknown_function(function)
        state = State({}, memory.copy())
        for variable, value in zip(function.formal_variables, arguments, strict=True):
            self.record(variable, value)
            if value is not None:
                state.values[variable] = value
        initial_values = [self.value(state, copy.source) for copy in plan.entry_copies]
        for copy, value in zip(plan.entry_copies, initial_values, strict=True):
            self.record(copy.destination, value)
            state.values.pop(copy.destination, None)
            if value is not None:
                state.values[copy.destination] = value
        incoming = {function.entries[0]: state}
        pending = deque([function.entries[0]])
        returned: State | None = None
        return_values: tuple[int | None, ...] | None = None
        self.active.add(key)
        try:
            while pending:
                block = pending.popleft()
                state = incoming[block].copy()
                halted = False
                for stmt in self.blocks[block].instructions:
                    self.steps += 1
                    self.evidence.add(stmt.id)
                    if self.steps > 200000:
                        raise ProofLimit("Constant verification step bound")
                    if stmt.id in plan.resolved_phis or stmt.opcode in {"JUMP", "JUMPI"}:
                        continue
                    args = [self.value(state, v) for v in stmt.operands]
                    op = stmt.opcode
                    results: list[int | None] = [None] * len(stmt.definitions)
                    from .validation import ARITHMETIC, arithmetic

                    if op == "CONST":
                        results = [self.candidates.get(v) for v in stmt.definitions]
                    elif op in ARITHMETIC and all(x is not None for x in args):
                        try:
                            results = [arithmetic(op, [int(x) for x in args if x is not None])]
                        except (ValueError, IndexError, OverflowError):
                            results = [None]
                    elif op in {"MOV", "MOV2"}:
                        results = args
                    elif op == "MLOAD" and len(args) == 1:
                        offset = args[0]
                        if offset is not None and all(
                            offset + i in state.memory for i in range(32)
                        ):
                            results = [
                                int.from_bytes(bytes(state.memory[offset + i] for i in range(32)))
                            ]
                    elif op in {"MSTORE", "MSTORE8"} and len(args) == 2:
                        offset, value = args
                        width = 32 if op == "MSTORE" else 1
                        self.forget(state, offset, width)
                        if offset is not None and value is not None:
                            data = value.to_bytes(32)[-width:]
                            state.memory.update((offset + i, x) for i, x in enumerate(data))
                    elif op == "MCOPY" and len(args) == 3:
                        destination, source, size = args
                        copied = (
                            {
                                i: state.memory[source + i]
                                for i in range(size)
                                if source + i in state.memory
                            }
                            if source is not None and size is not None and size <= 4096
                            else {}
                        )
                        self.forget(state, destination, size)
                        if destination is not None:
                            state.memory.update((destination + i, x) for i, x in copied.items())
                    elif op == "CODESIZE" and not args:
                        results = [len(self.code) if self.code is not None else None]
                    elif op == "CODECOPY":
                        self.codecopy(stmt.id, args, state)
                    elif op in {"CALLDATACOPY", "RETURNDATACOPY", "EXTCODECOPY"}:
                        start = 1 if op == "EXTCODECOPY" else 0
                        if len(args) >= start + 3:
                            self.forget(state, args[start], args[start + 2])
                        else:
                            state.memory.clear()
                    elif op in {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}:
                        start = 3 if op in {"CALL", "CALLCODE"} else 2
                        self.forget(state, args[start + 2], args[start + 3])
                    elif op == "CALLPRIVATE":
                        callees = self.calls[block]
                        if not callees and args and args[0] is not None:
                            callees = {
                                f.id for f in self.program.functions if hex(args[0]) in f.entries
                            }
                        if len(callees) == 1 and next(iter(callees)) in self.functions:
                            child = self.function(
                                self.functions[next(iter(callees))], tuple(args[1:]), state.memory
                            )
                            if not child.returns:
                                halted = True
                                break
                            state.memory = child.memory.copy()
                            results = (
                                list(child.values) if len(child.values) == len(results) else results
                            )
                        else:
                            self.invalidate_functions(
                                set(callees)
                                if callees and set(callees) <= self.functions.keys()
                                else set(self.functions)
                            )
                            state.memory.clear()
                    elif op == "RETURNPRIVATE":
                        values = tuple(args[1:])
                        if returned is None:
                            returned, return_values = state.copy(), values
                        else:
                            if return_values is None or len(return_values) != len(values):
                                return self.unknown_function(function)
                            returned = returned.join(state)
                            return_values = tuple(
                                a if a == b else None
                                for a, b in zip(return_values, values, strict=True)
                            )
                        halted = True
                        break
                    elif op in {"RETURN", "REVERT", "STOP", "INVALID", "THROW", "SELFDESTRUCT"}:
                        if op == "REVERT":
                            self.capture_revert(stmt.id, args, state)
                        halted = True
                        break
                    elif op not in ARITHMETIC | {
                        "CALLDATALOAD",
                        "CALLDATASIZE",
                        "CALLER",
                        "ORIGIN",
                        "ADDRESS",
                        "CALLVALUE",
                        "NUMBER",
                        "TIMESTAMP",
                        "CHAINID",
                        "BLOCKHASH",
                        "GAS",
                        "MSIZE",
                        "RETURNDATASIZE",
                        "SLOAD",
                        "SSTORE",
                        "TLOAD",
                        "TSTORE",
                        "EXTCODESIZE",
                        "EXTCODEHASH",
                        "BALANCE",
                        "SELFBALANCE",
                        "COINBASE",
                        "BASEFEE",
                        "GASPRICE",
                        "GASLIMIT",
                        "DIFFICULTY",
                        "PREVRANDAO",
                        "BLOBHASH",
                        "BLOBBASEFEE",
                        "CODESIZE",
                        "SHA3",
                        "LOG0",
                        "LOG1",
                        "LOG2",
                        "LOG3",
                        "LOG4",
                        "CREATE",
                        "CREATE2",
                        "PHI",
                    }:
                        state.memory.clear()
                    if len(results) != len(stmt.definitions):
                        return self.unknown_function(function)
                    for variable, value in zip(stmt.definitions, results, strict=True):
                        self.record(variable, value)
                        state.values.pop(variable, None)
                        if value is not None:
                            state.values[variable] = value
                    if len(state.memory) > 4096:
                        state.memory.clear()
                if halted:
                    continue
                transfer = plan.transfers[block]
                targets = transfer.targets
                if not targets:
                    if (
                        "0x0" in function.entries
                        and transfer.kind == "end"
                        and self.blocks[block].instructions[-1].opcode == "CALLPRIVATE"
                    ):
                        # An opaque dispatch tail has no modeled continuation.
                        # Its reachable callees were invalidated, but independent
                        # dispatcher branches must still be visited.
                        self.opaque_tail_calls.add(block)
                        continue
                    return self.unknown_function(function)
                if transfer.kind == "if" and transfer.predicate:
                    predicate = self.value(state, transfer.predicate)
                    if predicate is not None:
                        targets = (targets[0 if predicate else 1],)
                for target in targets:
                    successor = state.copy()
                    copies = plan.copies.get((block, target), [])
                    edge_values = [self.value(state, c.source) for c in copies]
                    for copy, value in zip(copies, edge_values, strict=True):
                        self.record(copy.destination, value)
                        successor.values.pop(copy.destination, None)
                        if value is not None:
                            successor.values[copy.destination] = value
                    previous = incoming.get(target)
                    merged = previous.join(successor) if previous is not None else successor
                    if previous is None or merged != previous:
                        incoming[target] = merged
                        pending.append(target)
            result = Summary(
                returned is not None,
                return_values or (),
                returned.memory if returned else ByteMemory(),
            )
            self.cache[key] = result
            return result
        finally:
            self.active.remove(key)


def verify_constants(
    program: Program, candidates: dict[str, str], calls, call_returns
) -> Verification:
    analysis = ConstantMemory(program, candidates, calls, call_returns)
    roots = [f for f in program.functions if "0x0" in f.entries]
    metadata: dict = {
        "method": "bounded_numeric_byte_memory",
        "scope": "recovered CFG and resolved private calls; not bytecode equivalence",
        "initial_memory": "zero_filled_frame" if analysis.code is not None else "unknown",
        "bytecode_input": code_context(program),
        "limits": {
            "steps": 200000,
            "contexts": 512,
            "depth": 32,
            "memory_bytes": 4096,
            "revert_bytes": 4096,
            "total_known_revert_bytes": 65536,
            "unknown_zero_memory_ranges": 128,
            "code_copy_observations": 4096,
        },
        "evidence_scope": "shared visited IR statements, including write/branch checks",
        "ir_sha256": ir_fingerprint(program, calls, call_returns),
        "literal_inputs": {v: hex(value) for v, value in sorted(analysis.literal_inputs.items())},
    }
    if len(roots) != 1:
        return Verification(set(), {}, {**metadata, "status": "no_unique_root"})
    try:
        analysis.function(roots[0], (), ByteMemory(zero_default=analysis.code is not None))
    except (ProofLimit, ValueError, IndexError, KeyError) as error:
        return Verification(set(), {}, {**metadata, "status": "incomplete", "reason": str(error)})
    derived = {
        v: hex(value)
        for v, value in sorted(analysis.observed.items())
        if v not in analysis.unknown and analysis.candidates.get(v) != value
    }
    ids = sorted(analysis.evidence)
    offsets = sorted(
        {
            offset
            for block in program.blocks
            for stmt in block.instructions
            if stmt.id in analysis.evidence
            for offset in stmt.original_statements
        }
    )
    metadata.update(
        status="bounded_analysis",
        root=roots[0].id,
        steps=analysis.steps,
        ir_statements=ids,
        bytecode_offsets=offsets,
        opaque_functions=sorted(analysis.opaque_functions),
        opaque_reachable_functions=sorted(analysis.opaque_reachable),
        opaque_tail_calls=sorted(analysis.opaque_tail_calls),
        limited_revert_snapshots=sorted(analysis.limited_reverts),
        code_copy_observations=list(analysis.code_copies.values()),
        code_copy_records_limited=analysis.code_copy_records_limited,
    )
    reverts = {
        s: snapshot
        for s, snapshot in sorted(analysis.reverts.items())
        if s not in analysis.unknown_reverts
    }
    metadata["code_copy_observations_sha256"] = snapshot_fingerprint(
        metadata["code_copy_observations"]
    )
    metadata["revert_memory_sha256"] = snapshot_fingerprint(
        {s: v.to_dict() for s, v in reverts.items()}
    )
    return Verification(analysis.good - analysis.bad, derived, metadata, reverts)


def proven_constants(program: Program, candidates: dict[str, str], calls, call_returns) -> set[str]:
    return verify_constants(program, candidates, calls, call_returns).proven_native
