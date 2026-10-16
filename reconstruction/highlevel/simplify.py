"""Semantics-preserving expression rewrites for the readable view.

Every rewrite here is an identity on 256-bit EVM words (given the stated
widths of environment values). Each applied rule is recorded on the result
node so the line map can say which presentation rules produced a line.
"""

from __future__ import annotations

from dataclasses import replace

from .ir import Binary, Call, Const, Env, Expr, Index, Unary, Var, annotate

WORD = (1 << 256) - 1
ADDRESS_MASK = (1 << 160) - 1

# Casts that keep the low N bits (zero-extension), keyed by mask width in bits.
LOW_MASK_CASTS = {
    160: "address",
    **{bits: f"uint{bits}" for bits in range(8, 256, 8) if bits != 160},
}

COMPARISON_NEGATION = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    ">=": "<",
    ">": "<=",
    "<=": ">",
    "s<": "s>=",
    "s>=": "s<",
    "s>": "s<=",
    "s<=": "s>",
}
COMMUTATIVE = {"+", "*", "&", "|", "^", "=="}


def low_mask_width(value: int) -> int | None:
    if value and value & (value + 1) == 0:
        bits = value.bit_length()
        if bits % 8 == 0 and bits < 256:
            return bits
    return None


def high_mask_bytes(value: int) -> int | None:
    """bytesN mask: N leading 0xff bytes followed by zeros."""
    if not value or value == WORD:
        return None
    inverted = WORD ^ value
    width = low_mask_width(inverted)
    if width is None:
        return None
    return (256 - width) // 8


def value_width(expr: Expr) -> int:
    """Upper bound on the number of significant bits, proven syntactically."""
    if isinstance(expr, Const):
        return max(expr.value.bit_length(), 1)
    if isinstance(expr, Env):
        return expr.width
    if isinstance(expr, Var) and expr.typed:
        return type_width(expr.typed)
    if isinstance(expr, Call):
        if expr.name == "address":
            return 160
        if expr.name.startswith("uint") and expr.name[4:].isdigit():
            return int(expr.name[4:])
        if expr.name == "bool":
            return 1
    if isinstance(expr, Unary) and expr.op == "!":
        return 1
    if isinstance(expr, Binary):
        if expr.op in COMPARISON_NEGATION or expr.op in {"&&", "||"}:
            return 1
        if expr.op == "&":
            return min(value_width(expr.left), value_width(expr.right))
        if expr.op in {"|", "^"}:
            return max(value_width(expr.left), value_width(expr.right))
        if expr.op == ">>" and isinstance(expr.right, Const):
            return max(value_width(expr.left) - expr.right.value, 1)
    return 256


def type_width(name: str) -> int:
    if name == "address":
        return 160
    if name == "bool":
        return 1
    if name.startswith("uint") and name[4:].isdigit():
        return int(name[4:])
    return 256


def is_boolean(expr: Expr) -> bool:
    return value_width(expr) == 1


def cast(name: str, operand: Expr, evidence: frozenset[str], rule: str) -> Expr:
    return Call(name, (operand,), evidence=evidence, rules=frozenset({rule}))


def simplify(expr: Expr) -> Expr:
    """Bottom-up rewriting; never loses IR evidence of removed nodes."""
    before = expr.all_evidence()
    result = _simplify(expr)
    missing = before - result.all_evidence()
    if missing:
        result = annotate(result, missing)
    return result


def _simplify(expr: Expr) -> Expr:
    """Bottom-up rewriting to a fixpoint for each node."""
    children = tuple(_simplify(child) for child in expr.children())
    if children:
        expr = expr.with_children(children)
    for _ in range(8):
        rewritten = _rewrite(expr)
        if rewritten is expr:
            return expr
        expr = rewritten
    return expr


def _rewrite(expr: Expr) -> Expr:
    if isinstance(expr, Binary):
        return _rewrite_binary(expr)
    if isinstance(expr, Unary):
        return _rewrite_unary(expr)
    if isinstance(expr, Call):
        return _rewrite_call(expr)
    return expr


def _linear_terms(
    expr: Expr, sign: int, terms: list[tuple[int, Expr]], constant: list[int]
) -> None:
    if isinstance(expr, Binary) and expr.op in {"+", "-"}:
        _linear_terms(expr.left, sign, terms, constant)
        _linear_terms(expr.right, sign if expr.op == "+" else -sign, terms, constant)
    elif isinstance(expr, Const):
        constant[0] += sign * expr.value
    else:
        terms.append((sign, expr))


def _normalize_linear(expr: Binary) -> Expr | None:
    """Cancel equal terms and fold constants in +/- chains (a ring mod 2**256)."""
    terms: list[tuple[int, Expr]] = []
    constant = [0]
    _linear_terms(expr, 1, terms, constant)
    if len(terms) > 12:
        return None
    remaining: list[tuple[int, Expr]] = []
    for sign, term in terms:
        for index, (other_sign, other) in enumerate(remaining):
            if other_sign == -sign and other == term and not _reads_state(term):
                del remaining[index]
                break
        else:
            remaining.append((sign, term))
    folded = constant[0] % (1 << 256)
    changed = (
        len(remaining) != len(terms) or sum(isinstance(c, Const) for c in _constants(expr)) > 1
    )
    if not changed:
        return None
    evidence = expr.all_evidence()
    positives = [t for s, t in remaining if s > 0]
    negatives = [t for s, t in remaining if s < 0]
    if not positives and not negatives:
        return Const(folded, evidence=evidence, rules=frozenset({"linear-arithmetic"}))
    if positives:
        result: Expr = positives[0]
        for term in positives[1:]:
            result = Binary("+", result, term)
    else:
        result = Binary("-", Const(0), negatives[0])
        negatives = negatives[1:]
    for term in negatives:
        result = Binary("-", result, term)
    if folded:
        if folded > (1 << 255):
            result = Binary("-", result, Const((1 << 256) - folded))
        else:
            result = Binary("+", result, Const(folded))
    return annotate(result, evidence, {"linear-arithmetic"})


def _constants(expr: Expr) -> list[Expr]:
    if isinstance(expr, Binary) and expr.op in {"+", "-"}:
        return _constants(expr.left) + _constants(expr.right)
    return [expr] if isinstance(expr, Const) else []


def _rewrite_binary(expr: Binary) -> Expr:
    op, left, right = expr.op, expr.left, expr.right
    ev = expr.evidence
    if op in {"+", "-"} and (
        (isinstance(left, Binary) and left.op in {"+", "-"})
        or (isinstance(right, Binary) and right.op in {"+", "-"})
    ):
        normalized = _normalize_linear(expr)
        if normalized is not None and normalized != expr:
            return normalized
    # Keep constants on the right for commutative operators: x & MASK, x == 5.
    if op in COMMUTATIVE and isinstance(left, Const) and not isinstance(right, Const):
        return replace(expr, left=right, right=left)
    if isinstance(left, Const) and isinstance(right, Const):
        folded = _fold(op, left.value, right.value)
        if folded is not None:
            return Const(
                folded,
                evidence=ev | left.evidence | right.evidence,
                rules=frozenset({"fold-constant"}),
            )
    # The function selector: calldata word 0 shifted down to its top 4 bytes.
    if (
        op == ">>"
        and isinstance(right, Const)
        and right.value == 224
        and isinstance(left, Index)
        and isinstance(left.base, Env)
        and left.base.name == "msg.data"
        and isinstance(left.key, Const)
        and left.key.value == 0
    ):
        return Env(
            "msg.sig",
            32,
            evidence=ev | left.all_evidence() | right.evidence,
            rules=frozenset({"selector"}),
        )
    # x == x holds for every word value (no NaN on the EVM).
    if op == "==" and left == right and not _reads_state(left):
        return Const(1, evidence=ev | left.all_evidence(), rules=frozenset({"reflexive-equality"}))
    if op == "&" and isinstance(right, Const):
        mask = right.value
        if mask == WORD:
            return annotate(left, ev | right.evidence, {"identity-mask"})
        width = low_mask_width(mask)
        if width is not None:
            if value_width(left) <= width:
                return annotate(left, ev | right.evidence, {"redundant-mask"})
            return cast(LOW_MASK_CASTS[width], left, ev | right.evidence, "mask-to-cast")
        nbytes = high_mask_bytes(mask)
        if nbytes is not None:
            return cast(f"bytes{nbytes}", left, ev | right.evidence, "high-mask-to-bytes")
    if op in {"+", "|", "^", "-", "<<", ">>"} and isinstance(right, Const) and right.value == 0:
        return annotate(left, ev | right.evidence, {"identity"})
    if op in {"+", "|", "^"} and isinstance(left, Const) and left.value == 0:
        return annotate(right, ev | left.evidence, {"identity"})
    if op in {"*", "/"} and isinstance(right, Const) and right.value == 1:
        return annotate(left, ev | right.evidence, {"identity"})
    # x / 2**k  ==  x >> k for unsigned words (EVM DIV), including k = 0.
    if (
        op == "/"
        and isinstance(right, Const)
        and right.value
        and right.value & (right.value - 1) == 0
    ):
        shift = right.value.bit_length() - 1
        if shift >= 8:
            return Binary(
                ">>",
                left,
                Const(shift, evidence=right.evidence),
                evidence=ev,
                rules=frozenset({"div-pow2-to-shr"}),
            )
    # x * 2**k  ==  x << k modulo 2**256.
    if (
        op == "*"
        and isinstance(right, Const)
        and right.value
        and right.value & (right.value - 1) == 0
    ):
        shift = right.value.bit_length() - 1
        if shift >= 8:
            return Binary(
                "<<",
                left,
                Const(shift, evidence=right.evidence),
                evidence=ev,
                rules=frozenset({"mul-pow2-to-shl"}),
            )
    # (x >> 224) on a 4-byte selector word stays as-is; uint32(x >> 224) is redundant.
    if op == "-" and isinstance(right, Const) and right.value > (1 << 255):
        # x - (2**256 - k) == x + k (mod 2**256): solc emits additions of negatives.
        return Binary(
            "+",
            left,
            Const((1 << 256) - right.value, evidence=right.evidence),
            evidence=ev,
            rules=frozenset({"negative-constant"}),
        )
    if op == "+" and isinstance(right, Const) and right.value > (1 << 255):
        return Binary(
            "-",
            left,
            Const((1 << 256) - right.value, evidence=right.evidence),
            evidence=ev,
            rules=frozenset({"negative-constant"}),
        )
    return expr


def _rewrite_unary(expr: Unary) -> Expr:
    operand = expr.operand
    if expr.op == "!" and isinstance(operand, Const):
        return Const(
            int(operand.value == 0),
            evidence=expr.evidence | operand.evidence,
            rules=frozenset({"fold-constant"}),
        )
    if expr.op == "!":
        # !!x is x when x is already 0/1; otherwise bool(x).
        if isinstance(operand, Unary) and operand.op == "!":
            inner = operand.operand
            ev = expr.evidence | operand.evidence
            if is_boolean(inner):
                return annotate(inner, ev, {"double-negation"})
            return cast("bool", inner, ev, "double-negation-to-bool")
        if isinstance(operand, Binary) and operand.op in COMPARISON_NEGATION:
            return replace(
                operand,
                op=COMPARISON_NEGATION[operand.op],
                evidence=operand.evidence | expr.evidence,
                rules=operand.rules | {"negate-comparison"},
            )
        if isinstance(operand, Call) and operand.name == "bool":
            return replace(expr, operand=operand.args[0], rules=expr.rules | {"negate-bool"})
    if expr.op == "~" and isinstance(operand, Const):
        return Const(
            WORD ^ operand.value,
            evidence=expr.evidence | operand.evidence,
            rules=frozenset({"fold-constant"}),
        )
    return expr


def _rewrite_call(expr: Call) -> Expr:
    if len(expr.args) != 1:
        return expr
    (operand,) = expr.args
    name = expr.name
    target_width = (
        160
        if name == "address"
        else int(name[4:])
        if name.startswith("uint") and name[4:].isdigit()
        else None
    )
    if target_width is not None:
        # address(address(x)) / uint8(uint8(x)) / address(msg.sender).
        if isinstance(operand, Call) and operand.name == name:
            return annotate(operand, expr.evidence, {"repeated-cast"})
        if not isinstance(operand, Const) and value_width(operand) <= target_width:
            return annotate(operand, expr.evidence, {"redundant-cast"})
        if (
            isinstance(operand, Const)
            and operand.value.bit_length() <= target_width
            and name != "address"
        ):
            return annotate(operand, expr.evidence, {"redundant-cast"})
        # uint8(address(x)) == uint8(x): the narrower mask subsumes the wider one.
        if isinstance(operand, Call) and len(operand.args) == 1:
            inner_width = value_width(operand)
            if inner_width >= target_width and operand.name.startswith(("uint", "address")):
                return replace(
                    expr,
                    args=(operand.args[0],),
                    evidence=expr.evidence | operand.evidence,
                    rules=expr.rules | {"nested-cast"},
                )
    if name == "bool" and is_boolean(operand):
        return annotate(operand, expr.evidence, {"redundant-bool"})
    return expr


def _fold(op: str, a: int, b: int) -> int | None:
    if op == "+":
        return (a + b) & WORD
    if op == "-":
        return (a - b) & WORD
    if op == "*":
        return (a * b) & WORD
    if op == "/":
        return a // b if b else 0
    if op == "%":
        return a % b if b else 0
    if op == "&":
        return a & b
    if op == "|":
        return a | b
    if op == "^":
        return a ^ b
    if op == "<<":
        return (a << b) & WORD if b < 256 else 0
    if op == ">>":
        return a >> b if b < 256 else 0
    if op == "**":
        return pow(a, b, 1 << 256)
    if op == "==":
        return int(a == b)
    if op == "!=":
        return int(a != b)
    if op == "<":
        return int(a < b)
    if op == ">":
        return int(a > b)
    if op == "<=":
        return int(a <= b)
    if op == ">=":
        return int(a >= b)
    if op in {"s<", "s>", "s<=", "s>="}:
        sa = a - (1 << 256) if a >> 255 else a
        sb = b - (1 << 256) if b >> 255 else b
        return int({"s<": sa < sb, "s>": sa > sb, "s<=": sa <= sb, "s>=": sa >= sb}[op])
    return None


def _reads_state(expr: Expr) -> bool:
    """Conservative: comparisons of the same text are only equal for pure values."""
    from .ir import ExternalCallExpr

    if isinstance(expr, ExternalCallExpr):
        return True
    if isinstance(expr, Call) and expr.name in {"gasleft", "msize"}:
        return True
    return any(_reads_state(child) for child in expr.children())


def is_atom(expr: Expr) -> bool:
    """Cheap to repeat at every use: printing it twice adds no reading cost."""
    if isinstance(expr, (Const, Env, Var)):
        return True
    if (
        isinstance(expr, Call)
        and len(expr.args) == 1
        and expr.name in {"address", "bool", "msg.sig"}
    ):
        return is_atom(expr.args[0])
    if isinstance(expr, Call) and expr.name.startswith(("uint", "bytes")) and len(expr.args) == 1:
        return is_atom(expr.args[0])
    return False
