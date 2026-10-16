"""Keep native facts that depend on reads/calls/inputs as unverified hints."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from .constant_memory import Verification, verify_constants
from .render import ENVIRONMENT, PURE

if TYPE_CHECKING:
    from .model import Program


def unverified_constant_hints(
    program: Program,
    candidates: dict[str, str],
    calls=(),
    call_returns=None,
    *,
    verification: Verification | None = None,
) -> dict[str, str]:
    """A constant fact alone does not establish the value of a memory snapshot.

    Native memory heuristics can fold through an aliased write. Propagate that
    uncertainty through SSA consumers rather than turning those facts into
    literal substitutions. Function inputs/call returns also need a separate
    interprocedural proof; a callee-local constant fact is insufficient.
    Original facts remain available in the exported relations and hint map.
    """
    consumers: defaultdict[str, set[str]] = defaultdict(set)
    unverified = {v for f in program.functions for v in f.formal_variables}
    for block in program.blocks:
        for stmt in block.instructions:
            if (
                stmt.opcode not in PURE
                or stmt.opcode in ENVIRONMENT
                or stmt.opcode == "CALLDATALOAD"
            ):
                unverified.update(stmt.definitions)
            for operand in stmt.operands:
                consumers[operand].update(stmt.definitions)
    pending = list(unverified)
    while pending:
        source = pending.pop()
        for dependent in consumers[source] - unverified:
            unverified.add(dependent)
            pending.append(dependent)
    proven = (
        verification or verify_constants(program, candidates, calls, call_returns)
    ).proven_native
    return {v: value for v, value in candidates.items() if v in unverified and v not in proven}


def resolve_constants(program: Program, candidates: dict[str, str], calls=(), call_returns=None):
    verification = verify_constants(program, candidates, calls, call_returns)
    program.constant_hints = unverified_constant_hints(
        program, candidates, calls, call_returns, verification=verification
    )
    program.derived_constants = verification.derived
    program.constant_verification = verification.metadata
    program.revert_memory = {s: snapshot.to_dict() for s, snapshot in verification.reverts.items()}
    return {
        **{v: value for v, value in candidates.items() if v not in program.constant_hints},
        **verification.derived,
    }
