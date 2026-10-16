"""160-bit values used as numbers print as uint160, not address.

A 160-bit mask prints as `address(x)`, but uint160 values (Uniswap's
sqrtPriceX96, seconds-per-liquidity accumulators) are masked the same way. A
returned `address(x)` is printed `uint160(x)` (the same mask) when a source
of x is used in arithmetic somewhere in the contract and none as an address:

- sources are traced through locals (every definition, including merge
  copies), memory-object words (literal values and every field write), casts
  and shifts, to a computed value, a public argument, a private function's
  parameter, or a storage word (root and shift);
- arithmetic (+ - * / % **) on a value marks all its sources numeric; a
  private function's numeric parameter marks its callers' arguments (to a
  fixpoint);
- a call target, a `msg.sender` / `tx.origin` comparison or `.balance` /
  `.code` / `.codehash` marks sources as addresses, which always wins.

Shifts are not evidence (addresses are shifted when packed into words).
"""

from __future__ import annotations

from collections import defaultdict

from .ir import (
    Allocation,
    Assign,
    Binary,
    Call,
    Const,
    Env,
    Expr,
    ExternalCallExpr,
    Field,
    Index,
    Member,
    ParallelAssign,
    Return,
    Unary,
    Var,
    is_local,
)
from .passes import iter_expr, iter_statements

ARITHMETIC = {"+", "-", "*", "/", "%", "s/", "s%", "**"}
CASTS = {"address", "uint160"}
COMPUTED = ("computed",)
Key = tuple


class _Function:
    def __init__(self, view) -> None:
        self.view = view
        self.name = view.name
        self.definitions: defaultdict[str, list[Expr]] = defaultdict(list)
        self.fields: defaultdict[tuple[str, int], list[Expr]] = defaultdict(list)
        for stmt in iter_statements(view.body):
            if isinstance(stmt, Assign):
                if len(stmt.targets) == 1:
                    target = stmt.targets[0]
                    if is_local(target):
                        self.definitions[target.name].append(stmt.value)
                    elif isinstance(target, Field) and isinstance(target.base, Var):
                        self.fields[(target.base.name, target.offset)].append(stmt.value)
            elif isinstance(stmt, ParallelAssign):
                for target, value in zip(stmt.targets, stmt.values, strict=False):
                    if is_local(target):
                        self.definitions[target.name].append(value)
        self.parameters = {a.name: i for i, a in enumerate(view.arguments)}
        self.public = bool(view.function.selectors)


def _constant_part(expr: Expr) -> int | None:
    if isinstance(expr, Const):
        return expr.value
    if isinstance(expr, Binary) and expr.op == "+":
        for side in (expr.left, expr.right):
            if isinstance(side, Const):
                return side.value
    return None


def sources(expr: Expr, fn: _Function, shift: int = 0, seen: frozenset = frozenset()) -> set[Key]:
    """Where a value can come from (see the module docstring)."""
    if isinstance(expr, Call) and expr.name in CASTS and len(expr.args) == 1:
        return sources(expr.args[0], fn, shift, seen)
    if isinstance(expr, Binary) and expr.op == ">>" and isinstance(expr.right, Const):
        return sources(expr.left, fn, shift + expr.right.value, seen)
    if isinstance(expr, Binary) and expr.op in ARITHMETIC:
        return {COMPUTED}
    if isinstance(expr, Var):
        if expr.name in fn.parameters:
            kind = "argument" if fn.public else "parameter"
            return {(kind, fn.name, fn.parameters[expr.name], shift)}
        if is_local(expr):
            if expr.name in seen:
                return set()
            result: set[Key] = set()
            for value in fn.definitions.get(expr.name, []):
                result |= sources(value, fn, shift, seen | {expr.name})
            return result
        return {("storage", expr.name, shift)}
    if isinstance(expr, Index) and isinstance(expr.base, Env) and expr.base.name == "STORAGE":
        constant = _constant_part(expr.key)
        return {("storage", f"STORAGE+{constant}", shift)} if constant is not None else set()
    if isinstance(expr, Field) and isinstance(expr.base, Var):
        name = f"{expr.base.name}@{expr.offset}"
        if name in seen:
            return set()
        result = set()
        for literal in fn.definitions.get(expr.base.name, []):
            if isinstance(literal, Allocation) and literal.values and expr.offset % 32 == 0:
                index = expr.offset // 32
                if index < len(literal.values):
                    result |= sources(literal.values[index], fn, shift, seen | {name})
        for value in fn.fields.get((expr.base.name, expr.offset), []):
            result |= sources(value, fn, shift, seen | {name})
        return result
    return set()


def _truth_tests(stmt) -> set[int]:
    """`a - b` used only as a truth value is `a != b` (compiled equality), not arithmetic:
    a condition, or under `!` / `&&` / `||` in one."""
    found: set[int] = set()

    def visit(expr) -> None:
        if isinstance(expr, Binary) and expr.op == "-":
            found.add(id(expr))
        elif isinstance(expr, Unary) and expr.op == "!":
            visit(expr.operand)
        elif isinstance(expr, Binary) and expr.op in {"&&", "||"}:
            visit(expr.left)
            visit(expr.right)

    condition = getattr(stmt, "condition", None)
    if isinstance(condition, Expr):
        visit(condition)
    for expr in stmt.expressions():
        for node in iter_expr(expr):
            if isinstance(node, Unary) and node.op == "!":
                visit(node.operand)
    return found


def refine_160_bit_returns(views) -> int:
    """Retype `address` arguments and returned `address(x)` values that are numbers as
    uint160 (the same 160-bit mask); returns the number of changes."""
    functions = {view.name: _Function(view) for view in views}
    numeric: set[Key] = {COMPUTED}
    addresses: set[Key] = set()
    calls: list[tuple[_Function, Call]] = []
    for fn in functions.values():
        for stmt in iter_statements(fn.view.body):
            tests = _truth_tests(stmt)
            for expr in stmt.expressions():
                for node in iter_expr(expr):
                    if isinstance(node, Binary) and node.op in ARITHMETIC and id(node) not in tests:
                        for operand in (node.left, node.right):
                            numeric |= sources(operand, fn)
                    elif isinstance(node, Binary) and node.op in {"==", "!="}:
                        sides = (node.left, node.right)
                        if any(
                            isinstance(s, Env) and s.name in {"msg.sender", "tx.origin"}
                            for s in sides
                        ):
                            for side in sides:
                                addresses |= sources(side, fn)
                    elif isinstance(node, Member) and node.name in {"balance", "code", "codehash"}:
                        addresses |= sources(node.base, fn)
                    elif isinstance(node, ExternalCallExpr):
                        addresses |= sources(node.target, fn)
                    elif isinstance(node, Call) and node.name in functions:
                        calls.append((fn, node))
    # A private function's numeric (or address) parameter marks its callers' arguments.
    changed = True
    while changed:
        changed = False
        for fn, call in calls:
            for index, argument in enumerate(call.args):
                parameter = ("parameter", call.name, index, 0)
                found = sources(argument, fn)
                if parameter in numeric and not found <= numeric:
                    numeric |= found
                    changed = True
                if parameter in addresses and not found <= addresses:
                    addresses |= found
                    changed = True
    rewritten = 0
    for fn in functions.values():
        # Arguments typed `address` from masks or validators, used only as numbers.
        kind = "argument" if fn.public else "parameter"
        for index, argument in enumerate(fn.view.arguments):
            key = (kind, fn.name, index, 0)
            if argument.type == "address" and key in numeric and key not in addresses:
                argument.type = "uint160"
                argument.reason += (
                    "; a 160-bit value used in arithmetic (rule uint160-used-as-number)"
                )
                rewritten += 1
        for stmt in iter_statements(fn.view.body):
            if not isinstance(stmt, Return):
                continue
            values = list(stmt.values)
            for position, value in enumerate(values):
                if not (
                    isinstance(value, Call) and value.name == "address" and len(value.args) == 1
                ):
                    continue
                found = sources(value.args[0], fn)
                if found & numeric and not found & addresses:
                    values[position] = Call(
                        "uint160",
                        value.args,
                        evidence=value.evidence,
                        rules=value.rules | {"uint160-used-as-number"},
                    )
                    rewritten += 1
            stmt.values = tuple(values)
    return rewritten
