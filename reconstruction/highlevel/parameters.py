"""Static struct parameters, from the ABI decoder's own bounds checks.

A statically sized struct parameter is encoded in place: its k words sit in
the head like k separate parameters, so without more evidence the view prints
k parameters (an arity the source does not have). solc's ABI decoder (v2, and
via-IR) checks such a struct separately:

    require(int256(msg.data.length - H) >= S)   // H = 4 + 32 * i, S = 32 * k

nested inside the head check `msg.data.length - 4 >= N`. Each such check that
is strictly inside the head marks head words i .. i + k - 1 as one struct
parameter. The words stay separate values (the interpreter binds them by head
position); the struct is presentation: one parameter `S<n> varg<i>` with
fields `varg<i>.f0` ... in the body, typed per word.
"""

from __future__ import annotations

from .ir import Binary, Const, Env, Expr, If, Member, Require, Var
from .passes import FunctionState, iter_statements
from .types import TypedValue, map_body, validator_cast

MAX_WORDS = 64


MIRROR = {
    "<=": ">=",
    "s<=": "s>=",
    ">": "<",
    "s>": "s<",
    ">=": "<=",
    "s>=": "s<=",
    "<": ">",
    "s<": "s>",
}


def _length_check(condition: Expr) -> tuple[int, int] | None:
    """(H, S) of `msg.data.length - H >= S` or `< S` (signed or unsigned, either
    operand order): a require, or a branch in code whose control flow is not
    structured."""
    if (
        isinstance(condition, Binary)
        and isinstance(condition.left, Const)
        and condition.op in MIRROR
        and not isinstance(condition.right, Const)
    ):
        condition = Binary(MIRROR[condition.op], condition.right, condition.left)
    if not (
        isinstance(condition, Binary)
        and condition.op in {">=", "s>=", "<", "s<"}
        and isinstance(condition.right, Const)
    ):
        return None
    left = condition.left
    if (
        isinstance(left, Binary)
        and left.op == "-"
        and isinstance(left.left, Env)
        and left.left.name == "msg.data.length"
        and isinstance(left.right, Const)
    ):
        return left.right.value, condition.right.value
    return None


def struct_checks(statements) -> set[tuple[int, int]]:
    checks = set()
    for stmt in iter_statements(statements):
        if (isinstance(stmt, Require) and stmt.kind == "require") or isinstance(stmt, If):
            check = _length_check(stmt.condition)
            if check is not None:
                checks.add(check)
    return checks


def validated_word(stmt, names: set[str]) -> tuple[str, str] | None:
    """(word, cast) of an ABI-decoder validator on one of the head words."""
    for name in names:
        cast = validator_cast(stmt, name)
        if cast is not None:
            return name, cast
    return None


def lazy_whole_head(statements, arguments: list[Var]) -> tuple[int, int] | None:
    """The whole head as one calldata struct, from where its words are validated.

    The ABI decoder validates separate parameters at entry, before any of the
    body; a calldata struct's members are validated where they are read (after
    other code, or on one branch). A struct that is not the whole head has a
    bounds check of its own, so with only the head check, words validated
    late and none at entry make the head one struct. Two different validated
    types are required (a static array's elements share one)."""
    names = {argument.name for argument in arguments}
    checks = struct_checks(statements)
    if len(arguments) < 2 or checks != {(4, 32 * len(arguments))}:
        return None
    entry: dict[str, str] = {}
    prefix = True
    for stmt in statements:
        found = validated_word(stmt, names)
        if prefix and found is not None:
            entry[found[0]] = found[1]
            continue
        if prefix and (
            type(stmt).__name__ == "Comment"
            or (isinstance(stmt, Require) and _length_check(stmt.condition) is not None)
        ):
            continue
        prefix = False
    if entry:
        return None
    late = {found for stmt in iter_statements(statements) if (found := validated_word(stmt, names))}
    if len({cast for _, cast in late}) < 2:
        return None
    return 0, len(arguments)


def signature_intervals(params: list[str]) -> list[tuple[int, int]]:
    """Head-word intervals of the static tuple parameters of a signature."""
    from .lift import static_words

    intervals = []
    position = 0
    for param in params:
        words = static_words(param)
        count = len(words) if words is not None else 1
        if words is not None and param.startswith("(") and count >= 2:
            intervals.append((position, count))
        position += count
    return intervals


def struct_intervals(
    statements,
    signature_params: list[str] | None = None,
    known: list[tuple[int, int]] = (),
) -> list[tuple[int, int]]:
    """(first head word, words) of each static struct parameter.

    With a hash-matched signature its static tuples decide (a decoder check it
    does not explain is ignored); otherwise the decoder's struct checks do,
    with structs `known` otherwise: returned as pointers by a decoder helper,
    or a lazily validated whole head (a struct that is the whole head has no
    check of its own besides the head check)."""
    if signature_params is not None:
        return signature_intervals(signature_params)
    intervals = [(first, count) for first, count in known if 2 <= count <= MAX_WORDS]
    checks = struct_checks(statements)
    heads = [size for start, size in checks if start == 4]
    head = max(heads, default=0)
    for start, size in checks:
        if not heads or (start - 4) % 32 or size % 32 or not 64 <= size <= 32 * MAX_WORDS:
            continue
        first, count = (start - 4) // 32, size // 32
        if start == 4 and size >= head:
            continue  # the head check itself: it proves nothing about grouping
        if first * 32 + size > head:
            continue
        intervals.append((first, count))
    # Outermost intervals; one partly overlapping another is not a struct layout.
    intervals.sort(key=lambda item: (item[0], -item[1]))
    chosen: list[tuple[int, int]] = []
    for first, count in intervals:
        if any(f <= first and first + count <= f + c for f, c in chosen):
            continue
        if any(first < f + c and f < first + count for f, c in chosen):
            return []
        chosen.append((first, count))
    return chosen


def group_struct_parameters(
    state: FunctionState,
    arguments: list[Var],
    typed: dict[str, TypedValue],
    structs: dict[tuple[str, ...], str],
    intervals: list[tuple[int, int]],
) -> list[tuple[str, list[str], str, list[str]]]:
    """(struct parameter, its head-word arguments, struct name, field types) for
    each interval of `struct_intervals`; renames uses to fields."""
    return _apply(state, arguments, typed, structs, intervals) if intervals else []


def _apply(
    state: FunctionState,
    arguments: list[Var],
    typed: dict[str, TypedValue],
    structs: dict[tuple[str, ...], str],
    chosen: list[tuple[int, int]],
) -> list[tuple[str, list[str], str, list[str]]]:
    names = [argument.name for argument in arguments]
    groups: list[tuple[str, list[str], str, list[str]]] = []
    for first, count in chosen:
        if first + count > len(names):
            continue
        words = names[first : first + count]
        if any(typed[word].kind not in {"word", "unread"} for word in words):
            continue
        types = tuple(typed[word].type for word in words)
        struct = structs.setdefault(types, f"S{len(structs)}")
        groups.append((words[0], words, struct, list(types)))
    if not groups:
        return []
    fields = {
        word: (group, index) for group, words, _, _ in groups for index, word in enumerate(words)
    }

    def rename(expr: Expr) -> Expr:
        if isinstance(expr, Var) and expr.name in fields:
            group, index = fields[expr.name]
            return Member(
                Var(group, None, evidence=expr.evidence),
                f"f{index}",
                evidence=expr.evidence,
                rules=expr.rules | {"struct-parameter"},
            )
        return expr

    map_body(state.body, rename)
    return groups
