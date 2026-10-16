"""Decode established revert bytes, without inferring their source or authority.

Wire formats and standard panic codes:
https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions
https://docs.soliditylang.org/en/latest/abi-spec.html#errors
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from .constant_memory import proof_is_current

if TYPE_CHECKING:
    from .model import Program

ERROR = "0x08c379a0"
PANIC = "0x4e487b71"
PANICS = {
    0x00: "generic compiler panic",
    0x01: "failed assertion",
    0x11: "integer overflow or underflow",
    0x12: "division or modulo by zero",
    0x21: "enum conversion out of range",
    0x22: "invalid storage byte-array encoding",
    0x31: "pop of an empty array",
    0x32: "array index out of range",
    0x41: "excessive memory allocation",
    0x51: "uninitialized internal function",
}


def byte_facts(snapshot: dict) -> dict[int, int]:
    facts: dict[int, int] = {}
    for fragment in snapshot.get("known_ranges", []):
        offset, data = fragment["offset"], bytes.fromhex(fragment["data"])
        if not isinstance(offset, int) or offset < 0 or offset + len(data) > 4096:
            raise ValueError("Revert snapshot exceeds its byte bound")
        for index, byte in enumerate(data, offset):
            if index in facts and facts[index] != byte:
                raise ValueError("Conflicting revert snapshot bytes")
            facts[index] = byte
    return facts


def decode_payload(data: bytes) -> dict:
    result: dict = {
        "encoding": "raw_bytes",
        "selector": "0x" + data[:4].hex() if len(data) >= 4 else None,
        "reason": None,
        "reason_hex": None,
        "panic_code": None,
        "panic_meaning": None,
        "raw_words": [],
        "limitations": ["Payload shape does not establish its origin or source-level cause."],
    }
    if not data:
        result["encoding"] = "empty"
        return result
    if result["selector"] == ERROR and len(data) >= 68:
        offset, size = int.from_bytes(data[4:36]), int.from_bytes(data[36:68])
        padded = (size + 31) // 32 * 32
        if offset == 32 and len(data) == 68 + padded and not any(data[68 + size :]):
            reason = data[68 : 68 + size]
            result.update(encoding="Error(string)", reason_hex="0x" + reason.hex())
            try:
                result["reason"] = reason.decode("utf-8")
            except UnicodeDecodeError:
                result["limitations"].append(
                    "Reason bytes are not valid UTF-8; the hex bytes are authoritative."
                )
            return result
    if result["selector"] == PANIC and len(data) == 36:
        code = int.from_bytes(data[4:])
        result.update(
            encoding="Panic(uint256)",
            panic_code=hex(code),
            panic_meaning=PANICS.get(code, "unrecognized standard panic code"),
        )
        return result
    if result["selector"] in {ERROR, PANIC}:
        result["limitations"].append(
            "Standard selector matched, but the full payload is not canonical for that encoding."
        )
    if len(data) >= 4 and (len(data) - 4) % 32 == 0:
        result.update(
            encoding="selector_and_raw_words",
            raw_words=[hex(int.from_bytes(data[i : i + 32])) for i in range(4, len(data), 32)],
        )
        result["limitations"].append(
            "Error name and argument types are unresolved; selectors can collide."
        )
    return result


def analyze_reverts(program: Program) -> list[dict]:
    stale = "ir_sha256" in program.constant_verification and not proof_is_current(program)
    owners: defaultdict[str, list[str]] = defaultdict(list)
    for function in program.functions:
        for block_id in function.blocks:
            owners[block_id].append(function.id)
    result = []
    for block in program.blocks:
        for stmt in block.instructions:
            if stmt.opcode != "REVERT":
                continue
            snapshot = None if stale else program.revert_memory.get(stmt.id)
            info = {
                "statement": stmt.id,
                "functions": sorted(owners[block.id]),
                "status": "unresolved",
                "byte_length": None,
                "payload_hex": None,
                "selector": None,
                "encoding": None,
                "reason": None,
                "reason_hex": None,
                "panic_code": None,
                "panic_meaning": None,
                "raw_words": [],
                "evidence": [stmt.id],
                "proof_reference": "constant_verification" if snapshot is not None else None,
                "limitations": [
                    "Revert range or bytes were not established by bounded memory analysis."
                ],
            }
            if snapshot is not None:
                facts, size = byte_facts(snapshot), snapshot["byte_length"]
                info["byte_length"] = size
                if size is not None and 0 <= size <= 4096 and set(facts) == set(range(size)):
                    data = bytes(facts[i] for i in range(size))
                    info.update(
                        decode_payload(data), status="static", payload_hex="0x" + data.hex()
                    )
                elif all(i in facts for i in range(4)):
                    info.update(
                        status="partial",
                        selector="0x" + bytes(facts[i] for i in range(4)).hex(),
                        encoding="selector_only",
                        limitations=[
                            "Only listed bytes are established; full payload and argument types remain unresolved."
                        ],
                    )
            if stale:
                info["limitations"] = [
                    "Memory proof does not match the current IR/literal inputs; payload withheld."
                ]
            result.append(info)
    return result


def describe(info: dict, *, limit: int = 180) -> str:
    encoding = info["encoding"]
    if encoding == "Error(string)":
        text = (
            "Error(" + json.dumps(info["reason"]) + ")"
            if info["reason"] is not None
            else "Error(string), reason bytes: " + info["reason_hex"]
        )
    elif encoding == "Panic(uint256)":
        text = f"Panic({info['panic_code']}); standard code meaning: {info['panic_meaning']}"
    elif encoding == "empty":
        text = "empty bytes"
    elif encoding == "selector_and_raw_words":
        text = f"selector {info['selector']}, raw words ({', '.join(info['raw_words'])}); name/types unresolved"
    elif info["status"] == "partial":
        text = f"selector {info['selector']}; remaining payload unresolved"
    else:
        text = info["payload_hex"] or "unresolved bytes"
    return text if len(text) <= limit else text[:limit] + "... (full bytes in analysis.json)"


def guard_payloads(program: Program, summaries: list[dict]) -> dict[str, dict]:
    """A guard gets a payload only when every modeled failure path agrees.

    Calls to private functions, cycles and paths without established REVERT bytes
    do not provide a single failure-payload annotation. Bodies remain in output.
    """
    if program.semantics is None:
        return {}
    blocks = {b.id: b for b in program.blocks}
    summaries_by_id = {r["statement"]: r for r in summaries if r["status"] == "static"}
    result = {}
    for function in program.functions:
        members = set(function.blocks)
        known: dict[str, tuple[str, set[str]]] = {}
        predecessors: defaultdict[str, set[str]] = defaultdict(set)
        pending: deque[str] = deque()
        for block in function.blocks:
            body = blocks[block].instructions
            if not body:
                continue
            for target in blocks[block].successors:
                predecessors[target].add(block)
            if body[-1].opcode == "REVERT" and body[-1].id in summaries_by_id:
                info = summaries_by_id[body[-1].id]
                known[block] = (info["payload_hex"], {body[-1].id})
                pending.append(block)
        while pending:
            target = pending.popleft()
            for block in sorted(predecessors[target]):
                if block in known:
                    continue
                body, targets = blocks[block].instructions, set(blocks[block].successors)
                if (
                    not targets
                    or not targets <= members
                    or not targets <= known.keys()
                    or any(
                        s.opcode
                        in {
                            "CALLPRIVATE",
                            "RETURNPRIVATE",
                            "RETURN",
                            "STOP",
                            "INVALID",
                            "THROW",
                            "SELFDESTRUCT",
                            "REVERT",
                        }
                        for s in body
                    )
                ):
                    continue
                payloads = {known[t][0] for t in targets}
                if len(payloads) != 1:
                    continue
                known[block] = (next(iter(payloads)), set().union(*(known[t][1] for t in targets)))
                pending.append(block)
        for guard in program.semantics.guards:
            if guard.block not in members or guard.failure not in known:
                continue
            payload, sites = known[guard.failure]
            if payload == "0x":
                continue
            result[guard.statement] = {
                "payload_hex": payload,
                "revert_statements": sorted(sites),
                "description": describe(summaries_by_id[min(sites)]),
                "proof_reference": "constant_verification",
            }
    return result
