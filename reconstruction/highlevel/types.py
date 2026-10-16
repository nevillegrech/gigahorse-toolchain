"""Argument/return typing and storage naming from observed uses.

Types are claimed only from bytecode behavior: every use masked to the same
width, or a compiler ABI validator `require(x == cast(x))`. Otherwise values
stay `uint256` (the raw 32-byte word), as Dedaub prints them, and the evidence
for each typed argument is recorded in the map.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from .ir import (
    Assign,
    Binary,
    Call,
    Const,
    Emit,
    Env,
    Expr,
    ExprStmt,
    Halt,
    If,
    Index,
    ParallelAssign,
    Require,
    Return,
    Revert,
    Stmt,
    Unary,
    Var,
    While,
)
from .passes import (
    FunctionState,
    iter_statements,
    map_bodies,
    read_expressions,
    statement_ids,
)
from .simplify import is_boolean, simplify, value_width

CAST_TYPES = (
    {"address", "bool"}
    | {f"uint{n}" for n in range(8, 256, 8)}
    | {f"bytes{n}" for n in range(1, 32)}
    | {f"int{n}" for n in range(8, 257, 8)}
)


def map_expr(expr: Expr, fn: Callable[[Expr], Expr]) -> Expr:
    children = expr.children()
    if children:
        new = tuple(map_expr(child, fn) for child in children)
        if any(a is not b for a, b in zip(new, children, strict=True)):
            expr = expr.with_children(new)
    return fn(expr)


def map_statement_exprs(stmt: Stmt, fn: Callable[[Expr], Expr]) -> None:
    def m(expr: Expr) -> Expr:
        return simplify(map_expr(expr, fn))

    if isinstance(stmt, Assign):
        stmt.targets = tuple(t if isinstance(t, Var) else m(t) for t in stmt.targets)
        stmt.value = m(stmt.value)
    elif isinstance(stmt, ParallelAssign):
        stmt.values = tuple(m(v) for v in stmt.values)
    elif isinstance(stmt, ExprStmt):
        stmt.expr = m(stmt.expr)
    elif isinstance(stmt, Require):
        stmt.condition = m(stmt.condition)
        if stmt.payload is not None:
            stmt.payload = m(stmt.payload)
    elif isinstance(stmt, (If,)):
        stmt.condition = m(stmt.condition)
    elif isinstance(stmt, While) and stmt.condition is not None:
        stmt.condition = m(stmt.condition)
    elif isinstance(stmt, Return):
        stmt.values = tuple(m(v) for v in stmt.values)
        if stmt.raw is not None:
            stmt.raw = m(stmt.raw)
    elif isinstance(stmt, Revert) and stmt.payload is not None:
        stmt.payload = m(stmt.payload)
    elif isinstance(stmt, Emit):
        stmt.args = tuple(m(a) for a in stmt.args)
    elif isinstance(stmt, Halt) and stmt.operand is not None:
        stmt.operand = m(stmt.operand)


def map_body(statements: list[Stmt], fn: Callable[[Expr], Expr]) -> None:
    for stmt in iter_statements(statements):
        map_statement_exprs(stmt, fn)


@dataclass
class TypedValue:
    name: str
    type: str
    evidence: frozenset[str] = frozenset()
    reason: str = "no width evidence; raw 32-byte word"


def _occurrences(statements: list[Stmt], name: str) -> list[Expr | None]:
    """Parent of each occurrence of Var(name) (None when it is a whole expression)."""
    parents: list[Expr | None] = []

    def scan(expr: Expr, parent: Expr | None) -> None:
        if isinstance(expr, Var) and expr.name == name:
            parents.append(parent)
            return
        for child in expr.children():
            scan(child, expr)

    for stmt in iter_statements(statements):
        for expr in read_expressions(stmt):
            scan(expr, None)
        if isinstance(stmt, Assign):
            for target in stmt.targets:
                if isinstance(target, Var) and target.name == name:
                    parents.append(None)
    return parents


def _validator(stmt: Stmt, name: str) -> str | None:
    """require(x == cast(x)) as emitted by solc's ABI decoder (0.5+)."""
    if not isinstance(stmt, Require) or stmt.payload is not None:
        return None
    condition = stmt.condition
    if not (isinstance(condition, Binary) and condition.op == "=="):
        return None
    for left, right in ((condition.left, condition.right), (condition.right, condition.left)):
        if (
            isinstance(left, Var)
            and left.name == name
            and isinstance(right, Call)
            and right.name in CAST_TYPES
            and len(right.args) == 1
            and right.args[0] == left
        ):
            return right.name
    return None


def type_variables(state: FunctionState, names: list[str]) -> dict[str, TypedValue]:
    result: dict[str, TypedValue] = {}
    for name in names:
        typed = TypedValue(name, "uint256")
        validators = [s for s in iter_statements(state.body) if _validator(s, name)]
        casts = {_validator(s, name) for s in validators}
        if len(casts) == 1 and validators:
            cast = next(iter(casts))
            assert cast is not None
            typed = TypedValue(
                name,
                cast,
                frozenset().union(*(statement_ids(s) for s in validators)),
                f"ABI decoder check require({name} == {cast}({name}))",
            )
            removed = {id(s) for s in validators}
            state.body = map_bodies(
                state.body, lambda body, removed=removed: [s for s in body if id(s) not in removed]
            )
        else:
            parents = _occurrences(state.body, name)
            kinds = {
                p.name
                for p in parents
                if isinstance(p, Call) and p.name in CAST_TYPES and len(p.args) == 1
            }
            if (
                parents
                and len(kinds) == 1
                and all(isinstance(p, Call) and p.name in kinds for p in parents)
            ):
                cast = next(iter(kinds))
                typed = TypedValue(name, cast, frozenset(), f"every use is masked by {cast}(...)")
            elif parents and all(isinstance(p, Unary) and p.op == "!" for p in parents):
                typed = TypedValue(name, "bool", frozenset(), "used only as a truth value")
        if typed.type != "uint256":
            cast_name = typed.type

            def strip(expr: Expr, name: str = name, cast_name: str = cast_name) -> Expr:
                if (
                    isinstance(expr, Call)
                    and expr.name == cast_name
                    and len(expr.args) == 1
                    and isinstance(expr.args[0], Var)
                    and expr.args[0].name == name
                ):
                    return replace(expr.args[0], evidence=expr.args[0].evidence | expr.evidence)
                if isinstance(expr, Var) and expr.name == name:
                    return replace(expr, typed=cast_name)
                return expr

            map_body(state.body, strip)
        result[name] = typed
    return result


def expression_type(expr: Expr) -> str:
    """Best-effort static type of a printed value (for declarations/returns)."""
    if isinstance(expr, Var) and expr.typed:
        return expr.typed
    if isinstance(expr, Env) and expr.width == 160:
        return "address"
    if isinstance(expr, Call) and expr.name in CAST_TYPES:
        return expr.name
    if is_boolean(expr) and not isinstance(expr, Const):
        return "bool"
    width = value_width(expr)
    if width == 160 and isinstance(expr, Var):
        return "address"
    return "uint256"


@dataclass
class StorageInfo:
    root: str
    key_types: list[set[str]] = field(default_factory=list)
    value_types: set[str] = field(default_factory=set)
    getters: list[str] = field(default_factory=list)


def storage_root(expr: Expr) -> tuple[str, list[Expr]] | None:
    keys: list[Expr] = []
    while isinstance(expr, Index):
        keys.insert(0, expr.key)
        expr = expr.base
    if (
        isinstance(expr, Var)
        and expr.ssa is None
        and expr.name.startswith(("stor_", "tstor_", "_"))
    ):
        return expr.name, keys
    return None
