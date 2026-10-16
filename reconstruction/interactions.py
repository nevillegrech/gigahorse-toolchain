"""Conservative descriptions of external calls and ABI-shaped input words."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Program


# Local hints, never a claim about the code or ABI at the destination. A selector
# can collide with another signature. No signature service or target ABI is used.
SIGNATURE_HINTS = {
    "0x06fdde03": ["name()"],
    "0x095ea7b3": ["approve(address,uint256)"],
    "0x18160ddd": ["totalSupply()"],
    "0x23b872dd": ["transferFrom(address,address,uint256)"],
    "0x313ce567": ["decimals()"],
    "0x70a08231": ["balanceOf(address)"],
    "0x8da5cb5b": ["owner()"],
    "0x95d89b41": ["symbol()"],
    "0xa9059cbb": ["transfer(address,uint256)"],
    "0xdd62ed3e": ["allowance(address,address)"],
}

EXTERNAL_TABLES = {"ExternalSelector": 2, "ExternalReturn": 3, "ExternalMemory": 5}
COPY_TABLES = {"CallDataFragment": 5, "CallDataEvidence": 2}
CALL_ARITIES = {"CALL": 7, "CALLCODE": 7, "STATICCALL": 6, "DELEGATECALL": 6}


@dataclass
class CallArgument:
    index: int
    variables: list[str]


@dataclass
class ExternalCall:
    statement: str
    opcode: str
    target: str
    gas: str
    value: str | None
    input_offset: str
    input_size: str
    output_offset: str
    output_size: str
    success_variables: list[str]
    selector_variables: list[str]
    selector_candidates: list[str]
    selector_resolved: bool
    signature_hints: list[str]
    input_word_count: int | None
    arguments: list[CallArgument]
    return_variables: dict[int, list[str]]
    evidence: list[str]
    warnings: list[str]
    abi_sources: list[str]


def selector_value(value: str) -> str | None:
    number = int(value, 16)
    if number < 1 << 32:
        return f"0x{number:08x}"
    if number & ((1 << 224) - 1) == 0:
        return f"0x{number >> 224:08x}"
    return None


def load_external_calls(
    program: Program,
    tables: dict[str, list[tuple[str, ...]]],
    memory: dict[str, dict[int, list[str]]],
    constants: dict[str, str],
) -> list[ExternalCall]:
    statements = {s.id: s for b in program.blocks for s in b.instructions}
    variables = {v for s in statements.values() for v in s.definitions}
    variables.update(v for f in program.functions for v in f.formal_variables)
    definitions: defaultdict[str, set[str]] = defaultdict(set)
    for instruction in statements.values():
        for variable in instruction.definitions:
            definitions[variable].add(instruction.id)
    calls = {s.id: s for s in statements.values() if s.opcode in CALL_ARITIES}
    selectors: defaultdict[str, set[str]] = defaultdict(set)
    returns: defaultdict[str, dict[int, list[str]]] = defaultdict(dict)
    evidence: defaultdict[str, set[str]] = defaultdict(set)
    fragments: defaultdict[str, list[tuple[int, int, str, str]]] = defaultdict(list)
    for stmt_id, raw_offset, raw_width, variable, encoding in tables.get("CallDataFragment", []):
        if (
            stmt_id not in calls
            or variable not in variables
            or not raw_offset.isdecimal()
            or raw_width not in {"4", "32"}
            or encoding not in {"exact", "prefix32"}
            or (raw_width == "32" and encoding != "exact")
            or int(raw_offset) + int(raw_width) > 65536
        ):
            raise ValueError("Invalid semantic calldata fragment")
        fragments[stmt_id].append((int(raw_offset), int(raw_width), variable, encoding))
    for stmt_id, writer in tables.get("CallDataEvidence", []):
        if stmt_id not in calls or writer not in statements:
            raise ValueError("Invalid semantic calldata evidence")
        evidence[stmt_id].add(writer)
    for stmt_id, variable in tables.get("ExternalSelector", []):
        if stmt_id not in calls or variable not in variables:
            raise ValueError("Semantic selector references an unknown external call")
        selectors[stmt_id].add(variable)
    for stmt_id, variable, index in tables.get("ExternalReturn", []):
        if (
            stmt_id not in calls
            or variable not in variables
            or not index.lstrip("-").isdecimal()
            or int(index) < -1
        ):
            raise ValueError("Invalid semantic external return")
        returns[stmt_id].setdefault(int(index), []).append(variable)
    for stmt_id, writer, offset, low, high in tables.get("ExternalMemory", []):
        if (
            stmt_id not in calls
            or writer not in statements
            or not offset.lstrip("-").isdecimal()
            or not low.isdecimal()
            or not high.isdecimal()
            or not 0 <= int(low) < int(high)
        ):
            raise ValueError(
                f"Invalid semantic external memory evidence: {(stmt_id, writer, offset, low, high)!r}"
            )
        evidence[stmt_id].add(writer)
    result = []
    for stmt in sorted(calls.values(), key=lambda s: s.id):
        if len(stmt.operands) != CALL_ARITIES[stmt.opcode] or len(stmt.definitions) != 1:
            raise ValueError(f"Invalid recovered {stmt.opcode} arity at {stmt.id}")
        has_value = stmt.opcode in {"CALL", "CALLCODE"}
        start = 3 if has_value else 2
        args = stmt.operands
        candidates = set()
        unresolved = False
        for variable in selectors[stmt.id]:
            candidate = selector_value(constants[variable]) if variable in constants else None
            if candidate is None:
                unresolved = True
            else:
                candidates.add(candidate)
        abi_sources = ["gigahorse-memory"] if selectors[stmt.id] else []
        copied_words: defaultdict[int, set[str]] = defaultdict(set)
        # Existing ABI facts retain their uncertainty. Copy tracking fills gaps;
        # it never selects one alternative from contradictory ABI facts.
        if not selectors[stmt.id]:
            for fragment_offset, width, variable, encoding in fragments[stmt.id]:
                if fragment_offset == 0:
                    selectors[stmt.id].add(variable)
                    if variable not in constants:
                        unresolved = True
                        continue
                    number = int(constants[variable], 16)
                    if encoding == "prefix32" or width == 32:
                        number >>= 224
                    if number >= 1 << 32:
                        unresolved = True
                        continue
                    candidates.add(f"0x{number:08x}")
                elif fragment_offset >= 4 and (fragment_offset - 4) % 32 == 0 and width == 32:
                    copied_words[(fragment_offset - 4) // 32].add(variable)
            if selectors[stmt.id]:
                abi_sources.append("memory-fragments")
        warnings = []
        if not selectors[stmt.id]:
            warnings.append("Calldata ABI is unresolved; input may be arbitrary bytes or empty.")
        elif unresolved or len(candidates) != 1:
            warnings.append("Selector is unresolved or ambiguous; no candidate is selected.")
        size = int(constants[args[start + 1]], 16) if args[start + 1] in constants else None
        count = (
            (size - 4) // 32
            if size is not None and 4 <= size <= 4 + 32 * 1024 and (size - 4) % 32 == 0
            else None
        )
        words = dict(memory.get(stmt.id, {})) if abi_sources == ["gigahorse-memory"] else {}
        if "memory-fragments" in abi_sources:
            words = {i + 1: sorted(values) for i, values in copied_words.items()}
        indices = set(range(count)) if count is not None and selectors[stmt.id] else set()
        indices.update(index - 1 for index in words if index > 0)
        arguments = [CallArgument(i, sorted(set(words.get(i + 1, [])))) for i in sorted(indices)]
        if any(v not in variables for a in arguments for v in a.variables):
            raise ValueError(f"External call {stmt.id} references an unknown ABI word variable")
        if selectors[stmt.id] and (count is None or any(len(a.variables) != 1 for a in arguments)):
            warnings.append(
                "ABI word recovery is partial; offsets and dynamic values are not decoded."
            )
        conflicts = (
            selectors[stmt.id]
            and size is not None
            and (size < 4 or any(4 + (a.index + 1) * 32 > size for a in arguments))
        )
        if conflicts:
            warnings.append(
                "ABI inference conflicts with the input length; inspect the raw memory slice."
            )
        hints = (
            SIGNATURE_HINTS.get(next(iter(candidates)), [])
            if len(candidates) == 1 and not unresolved and not conflicts
            else []
        )
        if hints:
            warnings.append("Signature hints can collide and do not establish target behavior.")
        for variable in selectors[stmt.id] | {v for a in arguments for v in a.variables}:
            evidence[stmt.id].update(definitions[variable])
        result.append(
            ExternalCall(
                statement=stmt.id,
                opcode=stmt.opcode,
                target=args[1],
                gas=args[0],
                value=args[2] if has_value else None,
                input_offset=args[start],
                input_size=args[start + 1],
                output_offset=args[start + 2],
                output_size=args[start + 3],
                success_variables=stmt.definitions,
                selector_variables=sorted(selectors[stmt.id]),
                selector_candidates=sorted(candidates),
                selector_resolved=len(candidates) == 1 and not unresolved and not conflicts,
                signature_hints=list(hints),
                input_word_count=count,
                arguments=arguments,
                return_variables={i: sorted(set(v)) for i, v in sorted(returns[stmt.id].items())},
                evidence=sorted(evidence[stmt.id] | {stmt.id}),
                warnings=warnings,
                abi_sources=abi_sources,
            )
        )
    return result
