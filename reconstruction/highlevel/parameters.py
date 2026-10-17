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
from .passes import FunctionState, iter_expr, iter_statements
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


def memory_whole_head(statements, arguments: list[Var]) -> tuple[int, int] | None:
    """The whole head as one memory struct, from the decoder's copy.

    solc decodes a `memory` struct parameter by copying its words into a new
    object at the free pointer before the body, and its modifiers, run; the
    body building a struct from separate parameters comes after them. So when
    the entry, after the head check, allocates the head's size and stores every
    head word into it in order (each validated as it is copied), the head is
    one struct (MetaMorpho's `MarketParams memory`)."""
    from .abi_codec import _pointer_read, _pointer_update, _store

    names = [argument.name for argument in arguments]
    if len(names) < 2:
        return None

    def offset(address: Expr, pointer: str) -> int | None:
        if isinstance(address, Var) and address.name == pointer:
            return 0
        if isinstance(address, Binary) and address.op == "+":
            for base, step in ((address.left, address.right), (address.right, address.left)):
                if isinstance(base, Var) and base.name == pointer and isinstance(step, Const):
                    return step.value
        if isinstance(address, Const) and address.value >= 0x80:
            # The analysis folded the pointer: the object starts at solc's initial
            # free pointer, as memory objects assume (checked when executed).
            return address.value - 0x80
        return None

    pointer: str | None = None
    stored = 0
    allocated = False
    for stmt in statements:
        if pointer is None:
            if (
                validated_word(stmt, set(names)) is not None
                or type(stmt).__name__ == "Comment"
                or (isinstance(stmt, Require) and _length_check(stmt.condition) is not None)
            ):
                continue
            read = _pointer_read(stmt)
            if read is None:
                return None
            pointer = read.name
            continue
        update = _pointer_update(stmt)
        if update is not None:
            allocated = offset(update, pointer) == 32 * len(names)
            continue
        if validated_word(stmt, set(names)) is not None:
            continue  # each word is validated as it is copied
        if isinstance(stmt, Require) and any(
            isinstance(node, Var) and node.name == pointer
            for expr in stmt.expressions()
            for node in iter_expr(expr)
        ):
            continue  # the allocation's own overflow check
        store = _store(stmt)
        if store is None or stored == len(names):
            break
        address, value = store
        if offset(address, pointer) != 32 * stored:
            break
        if not (isinstance(value, Var) and value.name == names[stored]):
            break
        stored += 1
    return (0, len(names)) if allocated and stored == len(names) else None


def signature_intervals(params: list[str]) -> list[tuple[int, int, str | None]]:
    """Head-word intervals of the static tuples and one-dimensional static arrays
    of a signature: (first word, words, the array type or None for a tuple)."""
    from .lift import is_static_abi, static_words

    intervals = []
    position = 0
    for param in params:
        words = static_words(param)
        count = len(words) if words is not None else 1
        if words is not None and param.startswith("(") and count >= 2:
            intervals.append((position, count, None))
        elif words is not None and param.endswith("]") and count >= 2:
            element = param[: param.rindex("[")]
            if is_static_abi(element) and "[" not in element:
                intervals.append((position, count, param))
        position += count
    return intervals


def member(kind: str, index: int) -> str:
    """Member name of a parameter group's word: `[i]` of an array, `f<i>` of a struct."""
    return f"[{index}]" if kind.endswith("]") else f"f{index}"


def struct_intervals(
    statements,
    signature_params: list[str] | None = None,
    known: list[tuple[int, int]] = (),
) -> list[tuple[int, int, str | None]]:
    """(first head word, words, array type or None) of each static struct or array parameter.

    With a hash-matched signature its static tuples decide (a decoder check it
    does not explain is ignored); otherwise the decoder's struct checks do,
    with structs `known` otherwise: returned as pointers by a decoder helper,
    or a lazily validated whole head (a struct that is the whole head has no
    check of its own besides the head check)."""
    if signature_params is not None:
        return signature_intervals(signature_params)
    intervals = [(first, count, None) for first, count in known if 2 <= count <= MAX_WORDS]
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
        intervals.append((first, count, None))
    # Outermost intervals; one partly overlapping another is not a struct layout.
    intervals.sort(key=lambda item: (item[0], -item[1]))
    chosen: list[tuple[int, int, str | None]] = []
    for first, count, array in intervals:
        if any(f <= first and first + count <= f + c for f, c, _ in chosen):
            continue
        if any(first < f + c and f < first + count for f, c, _ in chosen):
            return []
        chosen.append((first, count, array))
    return chosen


def group_struct_parameters(
    state: FunctionState,
    arguments: list[Var],
    typed: dict[str, TypedValue],
    structs: dict[tuple[str, ...], str],
    intervals: list[tuple[int, int, str | None]],
) -> list[tuple[str, list[str], str, list[str]]]:
    """(group parameter, its head-word arguments, struct name or array type, word types)
    for each interval of `struct_intervals`; renames uses to members."""
    return _apply(state, arguments, typed, structs, intervals) if intervals else []


def _apply(
    state: FunctionState,
    arguments: list[Var],
    typed: dict[str, TypedValue],
    structs: dict[tuple[str, ...], str],
    chosen: list[tuple[int, int, str | None]],
) -> list[tuple[str, list[str], str, list[str]]]:
    names = [argument.name for argument in arguments]
    groups: list[tuple[str, list[str], str, list[str]]] = []
    for first, count, array in chosen:
        if first + count > len(names):
            continue
        words = names[first : first + count]
        if any(typed[word].kind not in {"word", "unread"} for word in words):
            continue
        types = tuple(typed[word].type for word in words)
        kind = array if array is not None else structs.setdefault(types, f"S{len(structs)}")
        groups.append((words[0], words, kind, list(types)))
    if not groups:
        return []
    fields = {
        word: (group, member(kind, index))
        for group, words, kind, _ in groups
        for index, word in enumerate(words)
    }

    def rename(expr: Expr) -> Expr:
        if isinstance(expr, Var) and expr.name in fields:
            group, name = fields[expr.name]
            return Member(
                Var(group, None, evidence=expr.evidence),
                name,
                evidence=expr.evidence,
                rules=expr.rules | {"struct-parameter"},
            )
        return expr

    map_body(state.body, rename)
    return groups
