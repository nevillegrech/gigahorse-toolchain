"""Payload-only abstractions for proven, straight-line terminal memory blocks.

The detailed inferred view and raw IR retain every operation. These structured
view helpers preserve established payloads; gas/resource behavior is outside
their contract. State/world effects and values exposed elsewhere stay expanded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .constant_memory import proof_is_current
from .render import PURE
from .semantics import Term

if TYPE_CHECKING:
    from .controlflow import FlowPlan
    from .model import Function, Program


HELPERS = {
    "evm.revert_error(text)": "Revert with canonical Error(string), using the UTF-8 bytes of text.",
    "evm.revert_panic(code)": "Revert with canonical Panic(uint256); this does not establish its origin/cause.",
    "evm.revert_data(hex_bytes)": "Revert with exactly the supplied bytes.",
}


@dataclass(frozen=True)
class RevertFold:
    function: str
    block: str
    blocks: tuple[str, ...]
    statement: str
    helper: str
    payload_hex: str
    ir_statements: tuple[str, ...]
    bytecode_offsets: tuple[str, ...]
    hidden_definitions: tuple[str, ...]
    proof_reference: str = "constant_verification"
    scope: str = (
        "Terminal pure/memory encoding only; gas and resource behavior are not represented."
    )


def render_helper(info: dict) -> str | None:
    if info["status"] != "static" or not info["byte_length"]:
        return None
    if info["encoding"] == "Error(string)" and info["reason"] is not None:
        text = f"evm.revert_error({json.dumps(info['reason'])});"
    elif info["encoding"] == "Panic(uint256)":
        text = f"evm.revert_panic({info['panic_code']});"
    else:
        text = f"evm.revert_data({json.dumps(info['payload_hex'])});"
    return text if len(text) <= 512 else None


def term_variables(term: Term) -> set[str]:
    return set().union(*(term_variables(v) if isinstance(v, Term) else {v} for v in term.arguments))


def shape_variables(value) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(*(shape_variables(v) for v in value.values()))
    if isinstance(value, (list, tuple)):
        return set().union(*(shape_variables(v) for v in value))
    return set()


def exposed_variables(program: Program, block_ids: set[str]) -> set[str]:
    """Include semantic expressions as well as raw SSA uses outside the block."""
    ids = {s.id for b in program.blocks if b.id in block_ids for s in b.instructions}
    exposed = {
        v
        for b in program.blocks
        if b.id not in block_ids
        for s in b.instructions
        for v in s.operands
    }
    exposed.update(v for _, _, v in program.phi_inputs)
    for layout in program.return_layouts:
        if layout.statement not in ids:
            exposed.update(layout.words)
            exposed.update(shape_variables(layout.shape))
    if program.semantics:
        for guard in program.semantics.guards:
            if guard.statement not in ids:
                exposed.add(guard.predicate)
        for access in program.semantics.storage_accesses:
            if access.statement not in ids:
                exposed.update(term_variables(access.index))
                for write in access.written_values:
                    exposed.update(term_variables(write))
        for call in program.semantics.external_calls:
            if call.statement not in ids:
                exposed.update(v for arg in call.arguments for v in arg.variables)
    return exposed


def find_revert_folds(
    program: Program,
    function: Function,
    plan: FlowPlan,
    summaries: dict[str, dict],
    *,
    current_proof: bool | None = None,
) -> dict[str, RevertFold]:
    if (
        not plan.region
        or plan.unresolved_phis
        or not (proof_is_current(program) if current_proof is None else current_proof)
    ):
        return {}
    result: dict[str, RevertFold] = {}
    blocks = {b.id: b for b in program.blocks}
    predecessors: dict[str, set[str]] = {b: set() for b in plan.reachable_blocks}
    for source in plan.reachable_blocks:
        for target in plan.transfers[source].targets:
            predecessors[target].add(source)
    allowed = PURE | {"MLOAD", "MSTORE", "MSTORE8", "MCOPY", "CODECOPY", "CODESIZE"}
    for block in program.blocks:
        if block.id not in plan.reachable_blocks or not block.instructions:
            continue
        body = block.instructions
        info = summaries.get(body[-1].id)
        if body[-1].opcode != "REVERT" or info is None:
            continue
        helper = render_helper(info)
        if helper is None or any(s.opcode not in allowed for s in body[:-1]):
            continue
        chain = [block.id]
        while chain[0] not in function.entries and len(predecessors[chain[0]]) == 1:
            predecessor = next(iter(predecessors[chain[0]]))
            if predecessor not in blocks:
                break  # a duplicated node of a split plan: stop the chain here
            before = blocks[predecessor].instructions
            transfer = plan.transfers[predecessor]
            if (
                predecessor in chain
                or transfer.kind != "goto"
                or transfer.targets != (chain[0],)
                or not before
                or plan.copies.get((predecessor, chain[0]))
            ):
                break
            contents = before[:-1] if before[-1].opcode == "JUMP" else before
            if any(s.opcode not in allowed for s in contents):
                break
            chain.insert(0, predecessor)
        # Prefer the longest safe chain; escaping definitions can force a
        # shorter suffix to remain expanded.
        while chain:
            instructions = [s for b in chain for s in blocks[b].instructions]
            definitions = {v for s in instructions for v in s.definitions}
            if any(
                s.opcode in {"MSTORE", "MSTORE8", "MCOPY", "CODECOPY"} for s in instructions
            ) and not definitions & exposed_variables(program, set(chain)):
                fold = RevertFold(
                    function.id,
                    chain[0],
                    tuple(chain),
                    body[-1].id,
                    helper,
                    info["payload_hex"],
                    tuple(s.id for s in instructions),
                    tuple(sorted({pc for s in instructions for pc in s.original_statements})),
                    tuple(sorted(definitions)),
                )
                result.update((b, fold) for b in chain)
                break
            chain.pop(0)
    return result
