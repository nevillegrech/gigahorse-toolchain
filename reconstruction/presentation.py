"""Generated local names and proven control-only private-call arguments.

Names describe recovered IR roles, never original source identifiers. The raw IR
and private-call arity remain intact; only the inferred views omit return PCs.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from .render import identifier

if TYPE_CHECKING:
    from .model import Function, Instruction, Program


class InternalInterfaces:
    def __init__(self, program: Program):
        self.functions = {f.id: f for f in program.functions}
        self.targets: defaultdict[str, set[str]] = defaultdict(set)
        self.hidden: dict[str, int] = {}
        self.proofs: dict[str, dict] = {}
        if program.semantics is None:
            return
        for block_id, callee in program.semantics.calls:
            self.targets[block_id].add(callee)
        continuations: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
        for block_id, callee, target in program.semantics.call_returns:
            continuations[block_id, callee].add(target)
        blocks = {b.id: b for b in program.blocks}
        owners: defaultdict[str, list[set[str]]] = defaultdict(list)
        for function in program.functions:
            members = set(function.blocks)
            for block_id in members:
                owners[block_id].append(members)
        calls: defaultdict[str, list[tuple[str, Instruction]]] = defaultdict(list)
        for block in program.blocks:
            for stmt in block.instructions:
                if stmt.opcode == "CALLPRIVATE":
                    for callee in self.targets[block.id]:
                        calls[callee].append((block.id, stmt))
        for function in program.functions:
            formals = function.formal_variables
            if function.selectors or "0x0" in function.entries or len(formals) != len(set(formals)):
                continue
            instructions = [s for b in function.blocks for s in blocks[b].instructions]
            returns = [s for s in instructions if s.opcode == "RETURNPRIVATE"]
            if not returns or any(not s.operands for s in returns):
                continue
            controls = {s.operands[0] for s in returns}
            if len(controls) != 1 or not controls <= set(formals):
                continue
            variable = next(iter(controls))
            if any(
                variable in s.definitions
                or any(
                    v == variable and (s.opcode != "RETURNPRIVATE" or i != 0)
                    for i, v in enumerate(s.operands)
                )
                for s in instructions
            ):
                continue
            sites = []
            for block_id, stmt in calls[function.id]:
                targets = continuations[block_id, function.id]
                if (
                    self.targets[block_id] != {function.id}
                    or len(stmt.operands) != len(formals) + 1
                    or len(targets) != 1
                    or not targets <= blocks.keys()
                    or (set(blocks[block_id].successors) - targets)
                    or not owners[block_id]
                    or any(not targets <= members for members in owners[block_id])
                ):
                    break
                sites.append(
                    {"block": block_id, "statement": stmt.id, "continuation": next(iter(targets))}
                )
            else:
                if not sites:
                    continue
                self.hidden[function.id] = formals.index(variable)
                evidence = sorted({s.id for s in returns} | {s["statement"] for s in sites})
                self.proofs[function.id] = {
                    "function": function.id,
                    "omitted_index": formals.index(variable),
                    "ir_variable": variable,
                    "reason": "Used only as RETURNPRIVATE control, with resolved callers/continuations",
                    "call_sites": sorted(sites, key=lambda s: s["statement"]),
                    "ir_statements": evidence,
                    "bytecode_offsets": sorted(
                        {
                            offset
                            for b in program.blocks
                            for s in b.instructions
                            if s.id in evidence
                            for offset in s.original_statements
                        }
                    ),
                }

    def visible(self, function: Function) -> tuple[int, ...]:
        return tuple(
            i for i in range(len(function.formal_variables)) if i != self.hidden.get(function.id)
        )

    def callee(self, block: str, stmt: Instruction) -> Function | None:
        targets = self.targets[block]
        if len(targets) != 1:
            return None
        function = self.functions.get(next(iter(targets)))
        if function is None or len(stmt.operands) != len(function.formal_variables) + 1:
            return None
        return function

    def operands(self, block: str, stmt: Instruction) -> list[str]:
        if stmt.opcode == "RETURNPRIVATE":
            return stmt.operands[1:]
        if stmt.opcode == "CALLPRIVATE" and (callee := self.callee(block, stmt)):
            return [stmt.operands[i + 1] for i in self.visible(callee)]
        return stmt.operands

    def metadata(self) -> list[dict]:
        return [self.proofs[f] for f in sorted(self.proofs)]


class LocalNames:
    def __init__(self, program: Program, function: Function, interfaces: InternalInterfaces):
        self.names: dict[str, str] = {}
        self.definitions: defaultdict[str, list[Instruction]] = defaultdict(list)
        self.function = function.id
        if not function.selectors:
            self.names.update((v, f"input{i}") for i, v in enumerate(function.formal_variables))
        counts: defaultdict[str, int] = defaultdict(int)
        roles = {
            "MLOAD": "memory_word",
            "SLOAD": "state_word",
            "TLOAD": "transient_word",
            "CALL": "call_success",
            "STATICCALL": "call_success",
            "DELEGATECALL": "call_success",
            "CALLCODE": "call_success",
            "CALLPRIVATE": "result",
            "PHI": "merge",
            "RETURNDATASIZE": "return_size",
        }
        for block in program.blocks:
            if block.id not in function.blocks:
                continue
            for stmt in block.instructions:
                for variable in stmt.definitions:
                    self.definitions[variable].append(stmt)
                    if variable not in self.names:
                        role = roles.get(stmt.opcode, "temp")
                        counts[role] += 1
                        self.names[variable] = f"{role}{counts[role]}"
        hidden = interfaces.hidden.get(function.id)
        if hidden is not None:
            self.names[function.formal_variables[hidden]] = "return_pc"

    def name(self, variable: str) -> str:
        return self.names.get(variable, identifier(variable, "v_"))

    def metadata(self) -> dict:
        return {
            "function": self.function,
            "origin": "generated IR-role names, not source identifiers",
            "variables": [
                {
                    "ir_variable": v,
                    "name": name,
                    "ir_definitions": [s.id for s in self.definitions[v]],
                    "bytecode_offsets": sorted(
                        {offset for s in self.definitions[v] for offset in s.original_statements}
                    ),
                }
                for v, name in self.names.items()
            ],
        }
