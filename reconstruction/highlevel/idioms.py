"""Compiler idioms recognized by *executing* the lifted code.

A candidate summary (e.g. "returns the string stored at slot S") replaces a
function body only when running the lifted body on a set of chosen states gives
exactly the summary's result on every one. The test states cover the encoding
branches (empty, short, 31/32/33-byte boundary, multi-slot). This is checked
behaviour on those states, not a proof; the rule and the number of states are
recorded on the printed line, and the replaced statements stay in the map.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..keccak import keccak256
from ..validation import UnsupportedExecution
from .ir import Assign, Emit, ExprStmt, ExternalCallExpr, Index, Member, Return, Slice, Stmt, Var
from .passes import Elision, iter_expr, iter_statements, read_expressions, statement_ids

STRING_LENGTHS = (0, 1, 5, 31, 32, 33, 63, 64, 65, 100)


def storage_string(slot: int, data: bytes) -> dict[int, int]:
    """Solidity's storage encoding of a string/bytes value at `slot`."""
    if len(data) < 32:
        word = int.from_bytes(data.ljust(31, b"\0"), "big") << 8 | (2 * len(data))
        return {slot: word}
    result = {slot: 2 * len(data) + 1}
    start = int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")
    for index in range(0, len(data), 32):
        result[start + index // 32] = int.from_bytes(
            data[index : index + 32].ljust(32, b"\0"), "big"
        )
    return result


def abi_bytes(data: bytes) -> bytes:
    padded = data + b"\0" * (-len(data) % 32)
    return (32).to_bytes(32, "big") + len(data).to_bytes(32, "big") + padded


def sample(length: int, salt: int) -> bytes:
    return bytes((i * 37 + length * 11 + salt) % 251 + 1 for i in range(length))


@dataclass
class Recognition:
    function: str
    rule: str
    states: int
    detail: str


def _roots(body: list[Stmt]) -> set[str]:
    roots = set()
    for stmt in iter_statements(body):
        exprs = list(read_expressions(stmt))
        if isinstance(stmt, Assign):
            exprs.extend(stmt.targets)
        for expr in exprs:
            for node in iter_expr(expr):
                if (
                    isinstance(node, Var)
                    and node.ssa is None
                    and node.name.startswith(("stor_", "tstor_"))
                ):
                    roots.add(node.name)
    return roots


def _has_effects(body: list[Stmt]) -> bool:
    for stmt in iter_statements(body):
        if isinstance(stmt, Emit):
            return True
        if isinstance(stmt, (Assign, ExprStmt)):
            exprs = [stmt.value] if isinstance(stmt, Assign) else [stmt.expr]
            for expr in exprs:
                for node in iter_expr(expr):
                    if isinstance(node, ExternalCallExpr):
                        return True
                    if type(node).__name__ == "Call" and (
                        node.name.startswith("fn_") or node.name in {"CALLDATACOPY", "CODECOPY"}
                    ):
                        return True
        if isinstance(stmt, Assign):
            for target in stmt.targets:
                if isinstance(target, Var) and target.ssa is None:
                    return True
                if isinstance(target, Index) and isinstance(target.base, type(target.base)):
                    base = target.base
                    if getattr(base, "name", "") in {"STORAGE", "TSTORAGE"}:
                        return True
    return False


def recognize_string_getters(decompiled) -> list[Recognition]:
    """Replace bodies that return a storage string with `return root;`."""
    from .interpreter import DecompiledMachine

    results = []
    for view in decompiled.views:
        if not view.function.selectors or view.arguments or view.name == "fallback":
            continue
        returns = [s for s in iter_statements(view.body) if isinstance(s, Return)]
        if not returns or any(r.raw is None for r in returns) or _has_effects(view.body):
            continue
        roots = _roots(view.body)
        if len(roots) != 1:
            continue
        root = next(iter(roots))
        location = decompiled.storage_root(root)
        if location is None or location[0] != "storage" or location[2:] != (0, 31):
            continue
        slot = int(location[1], 16)
        machine = DecompiledMachine(decompiled)
        selector = bytes.fromhex(view.function.selectors[0][2:])
        checked = 0
        try:
            for length in STRING_LENGTHS:
                data = sample(length, slot)
                storage = storage_string(slot, data)
                storage[slot + 1] = 0xA5  # an unrelated neighbour must not leak in
                # Through the real dispatcher: it sets up memory as the function expects.
                result = machine.execute(selector, storage=storage)
                if result.reverted or result.output != abi_bytes(data):
                    break
                checked += 1
        except UnsupportedExecution:
            continue
        if checked != len(STRING_LENGTHS):
            continue
        hidden = frozenset().union(*(statement_ids(s) for s in iter_statements(view.body)))
        root_var = next(
            node
            for stmt in iter_statements(view.body)
            for expr in read_expressions(stmt)
            for node in iter_expr(expr)
            if isinstance(node, Var) and node.name == root
        )
        statement = Return(
            (Var(root_var.name, None),),
            evidence=frozenset(),
            hidden=hidden,
            rules=frozenset({"storage-string-getter"}),
            note=f"returns the string/bytes at STORAGE[{location[1]}]; checked by executing the lifted body on {checked} storage encodings",
        )
        view.body = [statement]
        view.state.body = view.body
        view.returns = ["string"]
        view.state.elided.append(
            Elision(frozenset(), f"string getter recognized ({checked} states)")
        )
        results.append(Recognition(view.name, "storage-string-getter", checked, root))
    return results


__all__ = ["Member", "Slice", "abi_bytes", "recognize_string_getters", "storage_string"]
