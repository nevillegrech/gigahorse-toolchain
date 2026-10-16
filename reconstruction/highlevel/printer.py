"""Print the tree IR as Solidity-like text with a per-line evidence map."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .ir import (
    Assign,
    Binary,
    Call,
    Comment,
    Const,
    Emit,
    Env,
    Expr,
    ExprStmt,
    ExternalCallExpr,
    Halt,
    If,
    Index,
    Jump,
    Member,
    ParallelAssign,
    Raw,
    RawBlock,
    Require,
    Return,
    Revert,
    Slice,
    Stmt,
    Unary,
    Var,
    While,
)

# Solidity precedence, larger binds tighter.
PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "==": 3,
    "!=": 3,
    "<": 4,
    ">": 4,
    "<=": 4,
    ">=": 4,
    "s<": 4,
    "s>": 4,
    "s<=": 4,
    "s>=": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "<<": 8,
    ">>": 8,
    "s>>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
    "s/": 10,
    "s%": 10,
    "**": 11,
}
FAMILY = {
    **dict.fromkeys(["+", "-", "*", "/", "%", "s/", "s%", "**"], "arith"),
    **dict.fromkeys(["&", "|", "^"], "bit"),
    **dict.fromkeys(["<<", ">>", "s>>"], "shift"),
}
SIGNED = {"s<": "<", "s>": ">", "s<=": "<=", "s>=": ">=", "s/": "/", "s%": "%", "s>>": ">>"}
UNARY_PRECEDENCE = 12


def expression(expr: Expr) -> str:
    return _expr(expr, 0)


def _child(expr: Expr, parent: str, side: str) -> str:
    if isinstance(expr, Binary):
        mine, theirs = PRECEDENCE[expr.op], PRECEDENCE[parent]
        clarify = (
            FAMILY.get(expr.op) != FAMILY.get(parent)
            and FAMILY.get(expr.op) is not None
            and FAMILY.get(parent) is not None
        ) or (
            # `a & b == c` is valid Solidity but misreads as C/JS precedence.
            FAMILY.get(expr.op) in {"bit", "shift"} and PRECEDENCE[parent] <= 4
        )
        # Non-associative right operands (a - (b - c)) need parentheses too.
        needs = mine < theirs or (
            mine == theirs
            and side == "right"
            and parent not in {"+", "*", "&", "|", "^", "&&", "||"}
        )
        if needs or clarify:
            return "(" + _expr(expr, 0) + ")"
    return _expr(expr, PRECEDENCE[parent])


def _expr(expr: Expr, context: int) -> str:
    if isinstance(expr, Const):
        return expr.text
    if isinstance(expr, (Var, Env)):
        return expr.name
    if isinstance(expr, Raw):
        return expr.text
    if isinstance(expr, Unary):
        inner = _expr(expr.operand, UNARY_PRECEDENCE)
        if isinstance(expr.operand, Binary):
            inner = "(" + _expr(expr.operand, 0) + ")"
        return expr.op + inner
    if isinstance(expr, Binary):
        op = expr.op
        if op in {"==", "!="}:
            # Selector comparisons read best as 8-digit selectors.
            for a, b in ((expr.left, expr.right), (expr.right, expr.left)):
                if (
                    isinstance(a, Env)
                    and a.name == "msg.sig"
                    and isinstance(b, Const)
                    and b.value < (1 << 32)
                ):
                    return f"msg.sig {op} 0x{b.value:08x}"
        left, right = _child(expr.left, op, "left"), _child(expr.right, op, "right")
        if op in SIGNED:
            if op == "s>>":
                return f"int256({left}) >> {right}"

            def signed(operand: Expr, text: str) -> str:
                # Small non-negative constants read the same signed or unsigned.
                if isinstance(operand, Const) and operand.value < (1 << 255):
                    return text
                return f"int256({_expr(operand, 0)})"

            return f"{signed(expr.left, left)} {SIGNED[op]} {signed(expr.right, right)}"
        return f"{left} {op} {right}"
    if isinstance(expr, Call):
        return f"{expr.name}({', '.join(_expr(arg, 0) for arg in expr.args)})"
    if isinstance(expr, Index):
        return f"{_postfix(expr.base)}[{_expr(expr.key, 0)}]"
    if isinstance(expr, Member):
        return f"{_postfix(expr.base)}.{expr.name}"
    if isinstance(expr, Slice):
        if expr.start == expr.end:
            return '""'
        return f"{expr.space}[{_expr(expr.start, 0)}:{_expr(expr.end, 0)}]"
    if isinstance(expr, ExternalCallExpr):
        options = []
        if expr.value is not None:
            options.append("value: " + _expr(expr.value, 0))
        if expr.gas is not None and not (isinstance(expr.gas, Call) and expr.gas.name == "gasleft"):
            options.append("gas: " + _expr(expr.gas, 0))
        target = _postfix(expr.target)
        braces = "{" + ", ".join(options) + "}" if options else ""
        if expr.method is not None:
            args = ", ".join(_expr(arg, 0) for arg in expr.args)
            prefix = (
                ""
                if expr.kind in {"call", "staticcall", "eth-transfer", "eth-send"}
                else f"/* {expr.kind} */ "
            )
            return f"{prefix}{target}.{expr.method}{braces}({args})"
        payload = _expr(expr.raw_input, 0) if expr.raw_input is not None else ""
        return f"{target}.{expr.kind}{braces}({payload})"
    raise TypeError(f"Unprintable expression: {expr!r}")


def _postfix(expr: Expr) -> str:
    text = _expr(expr, 99)
    if isinstance(expr, (Binary, Unary)):
        return "(" + text + ")"
    return text


@dataclass
class Printed:
    lines: list[str] = field(default_factory=list)
    entries: list[dict] = field(default_factory=list)
    offsets: dict[str, list[str]] = field(default_factory=dict)

    def emit(
        self,
        text: str,
        indent: int,
        *,
        evidence: frozenset[str] = frozenset(),
        hidden: frozenset[str] = frozenset(),
        rules: frozenset[str] = frozenset(),
        kind: str | None = None,
        uncertain: str | None = None,
    ) -> None:
        self.lines.append("    " * indent + text)
        if evidence or hidden or rules or uncertain or kind:
            ids = sorted(evidence | hidden)
            entry: dict = {"line": len(self.lines), "ir_statements": ids}
            entry["bytecode_offsets"] = sorted(
                {offset for sid in ids for offset in self.offsets.get(sid, [])},
                key=lambda value: int(value.split("0x")[-1], 16) if "0x" in value else -1,
            )
            if hidden:
                entry["abstracted_ir_statements"] = sorted(hidden)
            if rules:
                entry["rules"] = sorted(rules)
            if kind:
                entry["kind"] = kind
            if uncertain:
                entry["uncertainty"] = uncertain
            self.entries.append(entry)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def statement_evidence(stmt: Stmt) -> tuple[frozenset[str], frozenset[str]]:
    evidence = set(stmt.evidence)
    rules = set(stmt.rules)
    for expr in (*stmt.expressions(), *stmt.meta.get("output", ())):
        evidence |= expr.all_evidence()
        rules |= expr.all_rules()
    return frozenset(evidence), frozenset(rules)


def print_statements(out: Printed, statements: list[Stmt], indent: int) -> None:
    for stmt in statements:
        print_statement(out, stmt, indent)


def _suffix(stmt: Stmt) -> str:
    parts = []
    if stmt.note:
        parts.append(stmt.note)
    if stmt.uncertain:
        parts.append("UNCERTAIN: " + stmt.uncertain)
    return " // " + "; ".join(parts) if parts else ""


def print_statement(out: Printed, stmt: Stmt, indent: int) -> None:
    evidence, rules = statement_evidence(stmt)
    common = {
        "evidence": evidence,
        "hidden": stmt.hidden,
        "rules": rules,
        "uncertain": stmt.uncertain,
    }
    suffix = _suffix(stmt)
    if isinstance(stmt, Assign):
        lhs = ", ".join(expression(t) for t in stmt.targets)
        if len(stmt.targets) > 1:
            lhs = "(" + lhs + ")"
        out.emit(f"{lhs} = {expression(stmt.value)};{suffix}", indent, kind="assign", **common)
    elif isinstance(stmt, ParallelAssign):
        lhs = ", ".join(expression(t) for t in stmt.targets)
        rhs = ", ".join(expression(v) for v in stmt.values)
        if len(stmt.targets) == 1:
            out.emit(f"{lhs} = {rhs};{suffix}", indent, kind="phi-copy", **common)
        else:
            out.emit(f"({lhs}) = ({rhs});{suffix}", indent, kind="phi-copy", **common)
    elif isinstance(stmt, ExprStmt):
        out.emit(f"{expression(stmt.expr)};{suffix}", indent, kind="effect", **common)
    elif isinstance(stmt, Require):
        args = expression(stmt.condition)
        if stmt.payload is not None:
            args += ", " + expression(stmt.payload)
        out.emit(f"{stmt.kind}({args});{suffix}", indent, kind=stmt.kind, **common)
    elif isinstance(stmt, If):
        out.emit(f"if ({expression(stmt.condition)}) {{{suffix}", indent, kind="if", **common)
        print_statements(out, stmt.then, indent + 1)
        otherwise = stmt.otherwise
        while len(otherwise) == 1 and isinstance(otherwise[0], If):
            nested = otherwise[0]
            nested_evidence, nested_rules = statement_evidence(nested)
            out.emit(
                f"}} else if ({expression(nested.condition)}) {{{_suffix(nested)}",
                indent,
                evidence=nested_evidence,
                hidden=nested.hidden,
                rules=nested_rules,
                kind="if",
                uncertain=nested.uncertain,
            )
            print_statements(out, nested.then, indent + 1)
            otherwise = nested.otherwise
        if otherwise:
            out.emit("} else {", indent)
            print_statements(out, otherwise, indent + 1)
        out.emit("}", indent)
    elif isinstance(stmt, While):
        condition = expression(stmt.condition) if stmt.condition is not None else "true"
        out.emit(f"while ({condition}) {{{suffix}", indent, kind="loop", **common)
        print_statements(out, stmt.body, indent + 1)
        out.emit("}", indent)
    elif isinstance(stmt, Jump):
        out.emit(f"{stmt.kind};{suffix}", indent, kind=stmt.kind, **common)
    elif isinstance(stmt, Return):
        if stmt.values:
            values = ", ".join(expression(v) for v in stmt.values)
            text = f"return {values};" if len(stmt.values) == 1 else f"return ({values});"
        elif stmt.raw is not None:
            text = f"return {expression(stmt.raw)};"
        else:
            text = "return;"
        out.emit(text + suffix, indent, kind="return", **common)
    elif isinstance(stmt, Revert):
        text = f"revert({expression(stmt.payload)});" if stmt.payload is not None else "revert();"
        if (
            isinstance(stmt.payload, Call)
            and stmt.payload.name not in {"Error", "Panic"}
            and stmt.payload.name[:1].isupper()
        ):
            text = f"revert {expression(stmt.payload)};"
        out.emit(text + suffix, indent, kind="revert", **common)
    elif isinstance(stmt, Emit):
        out.emit(
            f"emit {stmt.event}({', '.join(expression(a) for a in stmt.args)});{suffix}",
            indent,
            kind="emit",
            **common,
        )
    elif isinstance(stmt, Halt):
        if stmt.kind == "stop":
            text = "stop();"
        elif stmt.kind == "selfdestruct":
            text = f"selfdestruct({expression(stmt.operand) if stmt.operand else ''});"
        else:
            text = "invalid(); // INVALID opcode: consumes all remaining gas"
        out.emit(text + suffix, indent, kind=stmt.kind, **common)
    elif isinstance(stmt, Comment):
        for line in stmt.text.splitlines() or [""]:
            out.emit("// " + line, indent, kind="comment", **common)
    elif isinstance(stmt, RawBlock):
        out.emit(f"{stmt.label}:{suffix}", indent, kind="raw-block", **common)
        print_statements(out, stmt.body, indent + 1)
    else:
        raise TypeError(f"Unprintable statement: {stmt!r}")


def quote(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)
