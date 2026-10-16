"""Per-function behaviour summaries: caller checks, storage writes, calls, events.

Each summary line is derived from the printed statement trees (including the
private functions a public function calls, transitively), and maps back to the
statements it summarizes. A summary describes recovered code paths; it does not
prove the absence of other effects in unstructured or unresolved code, which is
stated explicitly when present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ir import (
    Assign,
    Call,
    Emit,
    Env,
    Expr,
    ExternalCallExpr,
    If,
    Index,
    Member,
    RawBlock,
    Require,
    Return,
    Var,
    is_local,
)
from .passes import iter_expr, iter_statements, read_expressions, statement_ids
from .printer import expression

SENDER_NAMES = {"msg.sender", "tx.origin"}
LOCAL_NAME = re.compile(r"\b(?:v|varg)\d+\b")


@dataclass
class Summary:
    checks: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    branches: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    writes: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    calls: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    events: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    value_transfers: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    via: list[str] = field(default_factory=list)
    incomplete: bool = False
    selfdestruct: bool = False


def _mentions_sender(expr: Expr) -> bool:
    return any(isinstance(node, Env) and node.name in SENDER_NAMES for node in iter_expr(expr))


def _is_sender(expr: Expr) -> bool:
    while isinstance(expr, Call) and expr.name in {"address", "uint160"} and len(expr.args) == 1:
        expr = expr.args[0]
    return isinstance(expr, Env) and expr.name in SENDER_NAMES


def _access_check(expr: Expr) -> bool:
    """Caller identity compared for equality, or a storage lookup keyed by the caller."""
    from .ir import Binary, Unary

    for node in iter_expr(expr):
        if isinstance(node, Binary) and node.op in {"==", "!="}:
            if _is_sender(node.left) or _is_sender(node.right):
                return True
        if isinstance(node, Index) and not isinstance(node.base, Env) and _is_sender(node.key):
            # e.g. require(isAdmin[msg.sender]) used as a truth value (not a balance compare)
            parent_is_compare = any(
                isinstance(other, Binary)
                and other.op in {"<", ">", "<=", ">=", "s<", "s>", "s<=", "s>=", "-", "+"}
                and (other.left is node or other.right is node)
                for other in iter_expr(expr)
            )
            if not parent_is_compare:
                return True
        if isinstance(node, Unary):
            continue
    return False


def _storage_target(target: Expr) -> bool:
    node = target
    while isinstance(node, (Index, Member, Call)):
        if isinstance(node, Index) and isinstance(node.base, Env):
            return node.base.name in {"STORAGE", "TSTORAGE"}
        node = (
            node.base
            if isinstance(node, (Index, Member))
            else (node.args[0] if node.args else node)
        )
        if isinstance(node, Call) and not node.args:
            break
    return isinstance(node, Var) and not is_local(node)


def _shape(expr: Expr) -> str:
    """Storage path with keys abstracted: _allowance[msg.sender][varg0] stays exact."""
    return expression(expr)


def summarize(views) -> dict[str, Summary]:
    by_name = {view.name: view for view in views}
    local: dict[str, Summary] = {}
    callees: dict[str, set[str]] = {}
    for view in views:
        summary = Summary()
        called: set[str] = set()
        aliases: dict[str, Expr] = {}
        for stmt in iter_statements(view.body):
            if isinstance(stmt, Assign) and len(stmt.targets) == 1 and is_local(stmt.targets[0]):
                value = stmt.value
                while (
                    isinstance(value, Call) and value.name in {"address", "uint160"} and value.args
                ):
                    value = value.args[0]
                if isinstance(value, (Var, Index, Member)) and not isinstance(
                    value, ExternalCallExpr
                ):
                    aliases.setdefault(stmt.targets[0].name, value)

        def shown(expr: Expr, aliases: dict[str, Expr] = aliases) -> str:
            seen = 0
            while seen < 4:
                inner = expr
                while (
                    isinstance(inner, Call) and inner.name in {"address", "uint160"} and inner.args
                ):
                    inner = inner.args[0]
                if isinstance(inner, Var) and inner.name in aliases:
                    expr = aliases[inner.name]
                    seen += 1
                    continue
                break
            return expression(expr)

        for stmt in iter_statements(view.body):
            ids = statement_ids(stmt)
            if isinstance(stmt, RawBlock) or stmt.uncertain:
                summary.incomplete = summary.incomplete or isinstance(stmt, RawBlock)
            if isinstance(stmt, Require) and _access_check(stmt.condition):
                text = expression(stmt.condition)
                if (
                    stmt.payload is not None
                    and isinstance(stmt.payload, Call)
                    and stmt.payload.name == "Error"
                ):
                    text += f" ({expression(stmt.payload.args[0])})"
                summary.checks.append((f"require({text})", ids))
            if isinstance(stmt, If) and _access_check(stmt.condition):
                summary.branches.append(
                    (f"if ({expression(stmt.condition)})", frozenset(stmt.evidence))
                )
            if isinstance(stmt, Assign):
                for target in stmt.targets:
                    if _storage_target(target):
                        summary.writes.append((_shape(target), ids))
            if isinstance(stmt, Emit):
                summary.events.append((stmt.event, ids))
            for expr in read_expressions(stmt):
                for node in iter_expr(expr):
                    if isinstance(node, ExternalCallExpr):
                        target = shown(node.target)
                        if node.kind in {"eth-transfer", "eth-send"}:
                            summary.value_transfers.append(
                                (f"{target}.{node.method}({expression(node.args[0])})", ids)
                            )
                            continue
                        method = node.method or node.kind
                        label = f"{target}.{method}(...)"
                        raw = node.raw_input
                        if (
                            node.method is None
                            and isinstance(raw, Call)
                            and raw.name == "abi.encodeWithSelector"
                        ):
                            label = f"{target}.call({expression(raw.args[0])})"
                        if node.kind not in {"call", "staticcall"}:
                            label = f"{node.kind} {target}"
                        elif node.kind == "staticcall":
                            label += " [staticcall]"
                        if node.value is not None:
                            label += f" with value {expression(node.value)}"
                        summary.calls.append((label, ids))
                    elif isinstance(node, Call) and node.name in by_name and node.name != view.name:
                        called.add(node.name)
                    elif isinstance(node, Call) and node.name in {"create", "create2"}:
                        summary.calls.append((f"{node.name}(...)", ids))
            if isinstance(stmt, Return) and "tail-call" in stmt.rules:
                for value in stmt.values:
                    if isinstance(value, Call) and value.name in by_name:
                        called.add(value.name)
            if type(stmt).__name__ == "Halt" and getattr(stmt, "kind", "") == "selfdestruct":
                summary.selfdestruct = True
        local[view.name] = summary
        callees[view.name] = called
    result: dict[str, Summary] = {}
    for view in views:
        if not view.function.selectors:
            continue
        merged = Summary()
        seen: set[str] = set()
        todo = [view.name]
        while todo:
            name = todo.pop()
            if name in seen or name not in local:
                continue
            seen.add(name)
            part = local[name]

            def tagged(items, name=name, owner=view.name):
                # Effects of a private callee are in the callee's own variable names.
                if name == owner:
                    return list(items)
                return [
                    (f"{name}: {text}" if LOCAL_NAME.search(text) else text, ids)
                    for text, ids in items
                ]

            merged.checks += tagged(part.checks)
            merged.branches += tagged(part.branches)
            merged.writes += tagged(part.writes)
            merged.calls += tagged(part.calls)
            merged.events += part.events
            merged.value_transfers += tagged(part.value_transfers)
            merged.incomplete |= part.incomplete
            merged.selfdestruct |= part.selfdestruct
            for callee in sorted(callees.get(name, ()), reverse=True):
                if not by_name[callee].function.selectors:
                    todo.append(callee)
        merged.via = sorted(seen - {view.name})
        result[view.name] = merged
    return result


def _unique(items: list[tuple[str, frozenset[str]]], limit: int = 6) -> tuple[str, frozenset[str]]:
    order: dict[str, frozenset[str]] = {}
    for text, ids in items:
        order[text] = order.get(text, frozenset()) | ids
    texts = list(order)
    shown = texts[:limit]
    more = len(texts) - len(shown)
    evidence = frozenset().union(*order.values()) if order else frozenset()
    return "; ".join(shown) + (f"; +{more} more" if more > 0 else ""), evidence


def summary_lines(summary: Summary, writes_state: bool) -> list[tuple[str, frozenset[str]]]:
    lines = []
    if summary.checks:
        text, ids = _unique(summary.checks, 3)
        lines.append((f"caller checks: {text}", ids))
    elif summary.writes or summary.calls or summary.value_transfers or summary.selfdestruct:
        lines.append(("caller checks: none on recovered paths (callable by anyone)", frozenset()))
    if summary.branches:
        text, ids = _unique(summary.branches, 3)
        lines.append((f"caller-dependent branches: {text}", ids))
    if summary.writes:
        text, ids = _unique(summary.writes)
        lines.append((f"writes: {text}", ids))
    if summary.value_transfers:
        text, ids = _unique(summary.value_transfers)
        lines.append((f"sends ETH: {text}", ids))
    if summary.calls:
        text, ids = _unique(summary.calls)
        lines.append((f"calls: {text}", ids))
    if summary.events:
        text, ids = _unique(summary.events)
        lines.append((f"emits: {text}", ids))
    if summary.selfdestruct:
        lines.append(("SELFDESTRUCT reachable", frozenset()))
    if summary.via and lines:
        lines.append(("(includes effects of " + ", ".join(summary.via) + ")", frozenset()))
    if summary.incomplete:
        lines.append(
            ("UNCERTAIN: unstructured code present; summary may be incomplete", frozenset())
        )
    _ = writes_state
    return lines
