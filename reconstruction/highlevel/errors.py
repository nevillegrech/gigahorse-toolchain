"""Revert payloads written to memory: custom errors, Panic and selector-only errors.

solc encodes `revert E(a, b)` (and inline Panic codes) as

    p = MEM[64];                 // or scratch space at 0
    MEM[p] = selector << 224;
    MEM[p + 4] = a;
    MEM[p + 36] = b;
    revert(MEM[p:p + 68]);       // the pointer may be read again for the start

The sequence becomes one `revert(payload)`: a CustomError (named when a
hash-checked dictionary signature has exactly these one-word static
parameters) or Panic(code). The match requires the selector word first, then
argument words filling exactly p+4 .. p+4+32k, the free pointer unchanged
throughout, and arguments that neither read memory nor have effects, so the
payload bytes equal the bytes the code reverts with. The interpreter encodes
those bytes again when it executes the line.
"""

from __future__ import annotations

import re
from collections import Counter

from .abi_codec import (
    Cursor,
    Form,
    NoMatch,
    Tracker,
    _pointer_read,
    _store,
    _walk,
    add,
    constant_of,
    expect,
)
from .ir import (
    AbiCodec,
    Assign,
    Call,
    Const,
    CustomError,
    Env,
    Expr,
    ExternalCallExpr,
    Index,
    Revert,
    Slice,
    Stmt,
    Var,
    is_local,
)
from .naming import split_signature
from .passes import FunctionState, has_effect, iter_statements, map_bodies, statement_ids

PANIC = 0x4E487B71
ERROR_STRING = 0x08C379A0
ONE_WORD = re.compile(r"(u?int\d*|address|bool|bytes([1-9]|[12]\d|3[0-2]))")


def error_payload(
    selector: int,
    args: tuple[Expr, ...],
    signatures: dict[int, str],
    assumed_pointer: int | None = None,
) -> Expr:
    """The printed payload for a selector and its argument words."""
    rules = frozenset({"assumes-folded-free-pointer"} if assumed_pointer is not None else ())
    if selector == PANIC and len(args) == 1 and assumed_pointer is None:
        return Call("Panic", args)
    signature = signatures.get(selector)
    if signature is not None:
        name, params = split_signature(signature)
        if len(params) == len(args) and all(ONE_WORD.fullmatch(p) for p in params):
            args = tuple(
                Call("address", (a,))
                if p == "address" and isinstance(a, Const) and a.value < 1 << 160
                else a
                for p, a in zip(params, args, strict=True)
            )
            return CustomError(
                selector, name, args, assumed_pointer, rules=rules | {"custom-error-name"}
            )
    return CustomError(selector, None, args, assumed_pointer, rules=rules)


def static_error_payload(payload_hex: str, signatures: dict[int, str]) -> Expr | None:
    """A constant payload (selector + words) whose selector names a dictionary error."""
    data = bytes.fromhex(payload_hex.removeprefix("0x"))
    if len(data) < 4 or (len(data) - 4) % 32:
        return None
    selector = int.from_bytes(data[:4], "big")
    if selector not in signatures or selector in {PANIC, ERROR_STRING}:
        return None
    words = tuple(Const(int.from_bytes(data[i : i + 32], "big")) for i in range(4, len(data), 32))
    payload = error_payload(selector, words, signatures)
    return payload if isinstance(payload, CustomError) and payload.name else None


def _word_store(stmt: Stmt) -> tuple[Expr, Expr] | None:
    """MEM[a] = v, including the free pointer slot: code that reverts next may use
    0x40 as scratch for error arguments (`mstore(0x40, x); revert(0x1c, 0x44)`)."""
    stored = _store(stmt)
    if stored is not None:
        return stored
    if (
        isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], Index)
        and isinstance(stmt.targets[0].base, Env)
        and stmt.targets[0].base.name == "MEM"
    ):
        return stmt.targets[0].key, stmt.value
    return None


def _mentions_name(stmt: Stmt, name: str) -> bool:
    return any(
        isinstance(node, Var) and node.name == name
        for expr in stmt.expressions()
        for node in _walk(expr)
    )


def _signed(value: int | None) -> int | None:
    """Canonical forms are taken modulo 2**256; a word ending at the payload is -28."""
    return value - (1 << 256) if value is not None and value >> 255 else value


def _stable(expr: Expr) -> bool:
    """Its value at the revert equals its value where it was stored (only memory changes)."""
    if has_effect(expr):
        return False
    for node in _walk(expr):
        if isinstance(node, (ExternalCallExpr, AbiCodec, Slice)):
            return False
        if (
            isinstance(node, Index)
            and isinstance(node.base, Env)
            and node.base.name
            in {
                "MEM",
                "MEM8",
            }
        ):
            return False
        if isinstance(node, Env) and node.name in {"MEM", "MEM8"}:
            return False
    return True


def _match(
    statements: list[Stmt],
    index: int,
    tracker: Tracker,
    signatures: dict[int, str],
    uses: Counter[str],
) -> tuple[int, list[Stmt]] | None:
    t = tracker.copy()
    c = Cursor(statements, index, t)
    pointer: Var | None = None
    try:
        first = c.peek()
        read = _pointer_read(first) if first is not None else None
        if read is not None:
            pointer = read
            t.observe(c.take())
        # Word stores, possibly interleaved with local assignments (e.g. a word
        # read from memory into a local before it is stored as an argument).
        items: list[Stmt] = []
        stores: list[tuple[Form, Expr]] = []
        store_items: list[int] = []
        while (following := c.peek()) is not None and len(items) < 64:
            word = _word_store(following)
            if word is not None:
                stores.append((t.canon(word[0]), word[1]))
                store_items.append(len(items))
            elif not (
                isinstance(following, Assign)
                and len(following.targets) == 1
                and is_local(following.targets[0])
                and _pointer_read(following) is None
                and not has_effect(following.value)
            ):
                break
            items.append(following)
            t.observe(c.take())
        expect(bool(stores))
        while (following := c.peek()) is not None and _pointer_read(following) is not None:
            t.observe(c.take())
        stmt = c.take()
        expect(
            isinstance(stmt, Revert)
            and isinstance(stmt.payload, Slice)
            and stmt.payload.space == "MEM"
        )
        assert isinstance(stmt, Revert) and isinstance(stmt.payload, Slice)
        begin = t.canon(stmt.payload.start)
        length = constant_of(add(t.canon(stmt.payload.end), begin, -1))
        expect(length is not None and length >= 4 and (length - 4) % 32 == 0)
        assert length is not None
        count = (length - 4) // 32
        offsets = [_signed(constant_of(add(form, begin, -1))) for form, _ in stores]
        assumed = None
        if None in offsets:
            # Optimized legacy code: the selector went to MEM[MEM[64]] but the
            # argument addresses were folded to constants (MEM[64] known, 0x80).
            expect(begin[0] == "fp" and begin in t.bases and offsets[0] == 0)
            absolute = [constant_of(form) for form, _ in stores[1:]]
            expect(None not in absolute)
            assumed = min(a for a in absolute if a is not None) - 4
            expect(assumed >= 0x80)
            offsets = [0] + [a - assumed for a in absolute if a is not None]
        # The selector word: left-aligned at the payload start (stored first, the
        # arguments overwrite its zero bytes) or right-aligned in the word that
        # ends there (`mstore(0, sel)`, `revert(0x1c, ...)`), in any order.
        selector = None
        selector_at = None
        for position, (offset, (_, value)) in enumerate(zip(offsets, stores, strict=True)):
            if not isinstance(value, Const):
                continue
            left = offset == 0 and value.value >> 224 and not value.value & ((1 << 224) - 1)
            right = offset == -28 and 0 < value.value < 1 << 32 and assumed is None
            if left and position == 0:
                selector, selector_at = value.value >> 224, position
            elif right and selector is None:
                selector, selector_at = value.value, position
        expect(selector is not None and selector != ERROR_STRING)
        assert selector is not None and selector_at is not None
        arguments = [
            (offset, value)
            for position, (offset, (_, value)) in enumerate(zip(offsets, stores, strict=True))
            if position != selector_at
        ]
        expect(sorted(o for o, _ in arguments) == [4 + 32 * i for i in range(count)])
        expect(not any(has_effect(value) for _, value in stores))
        # Every memory read must see the stores that preceded it. Stores before
        # the last memory-reading item stay in place; among the arguments only
        # that last item may read memory (it is evaluated at the revert, where
        # the same stores precede it).
        reading_locals = [
            i
            for i, item in enumerate(items)
            if i not in store_items and isinstance(item, Assign) and not _stable(item.value)
        ]
        reading_arguments = [
            store_items[k]
            for k, (_, value) in enumerate(stores)
            if k != selector_at and not _stable(value)
        ]
        last = max(reading_locals + reading_arguments, default=-1)
        expect(all(i == last for i in reading_arguments))
        preserved = [item for i, item in enumerate(items) if i not in store_items or i < last]
        words = dict(arguments)
    except (NoMatch, IndexError):
        return None
    consumed = c.consumed()
    kept: list[Stmt] = []
    hidden = [s for s in consumed if s is not stmt and not any(s is k for k in preserved)]
    if pointer is not None and any(_mentions_name(s, pointer.name) for s in preserved):
        kept.append(consumed[0])
        hidden = [s for s in hidden if s is not consumed[0]]
    elif pointer is not None:
        # The pointer local is read only inside this sequence (or kept as it was).
        inside = sum(
            1
            for s in consumed
            for e in s.expressions()
            for node in _walk(e)
            if isinstance(node, Var) and node.name == pointer.name
        )
        if uses[pointer.name] > inside:
            kept.append(consumed[0])
            hidden = hidden[1:]
    args = tuple(words[4 + 32 * i] for i in range(count))
    payload = error_payload(selector, args, signatures, assumed)
    revert = Revert(
        payload,
        evidence=stmt.evidence,
        hidden=stmt.hidden.union(*(statement_ids(s) for s in hidden)),
        rules=stmt.rules | {"error-payload-from-memory"},
        uncertain=stmt.uncertain,
        origin=stmt.origin,
    )
    return c.index, [*kept, *preserved, revert]


def recognize_error_payloads(state: FunctionState, signatures: dict[int, str]) -> None:
    """Replace memory-built revert payloads with Panic / custom error values."""
    uses: Counter[str] = Counter(
        node.name
        for stmt in iter_statements(state.body)
        for expr in stmt.expressions()
        for node in _walk(expr)
        if isinstance(node, Var)
    )

    def visit(statements: list[Stmt]) -> list[Stmt]:
        tracker = Tracker(frozenset())
        result: list[Stmt] = []
        index = 0
        while index < len(statements):
            match = _match(statements, index, tracker, signatures, uses)
            if match is None:
                tracker.observe(statements[index])
                result.append(statements[index])
                index += 1
                continue
            index, replacement = match
            result.extend(replacement)
        return result

    state.body = map_bodies(state.body, visit)
