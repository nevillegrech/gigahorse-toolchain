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
    plus,
)
from .ir import (
    AbiCodec,
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
        stmt = c.take()
        stored = _store(stmt)
        expect(stored is not None)
        assert stored is not None
        base = t.canon(stored[0])
        selector_word = stored[1]
        expect(
            isinstance(selector_word, Const)
            and selector_word.value >> 224 != 0
            and selector_word.value & ((1 << 224) - 1) == 0
        )
        assert isinstance(selector_word, Const)
        selector = selector_word.value >> 224
        expect(selector != ERROR_STRING)
        t.observe(stmt)
        stores: list[tuple[Form, Expr]] = []
        while (following := c.peek()) is not None and len(stores) < 64:
            word = _store(following)
            if word is None:
                break
            stores.append((t.canon(word[0]), word[1]))
            t.observe(c.take())
        relative = [constant_of(add(form, base, -1)) for form, _ in stores]
        assumed = None
        if all(offset is not None for offset in relative):
            offsets = [offset for offset in relative if offset is not None]
        else:
            # Optimized legacy code: the selector went to MEM[MEM[64]] but the
            # argument addresses were folded to constants (MEM[64] known, 0x80).
            absolute = [constant_of(form) for form, _ in stores]
            expect(base[0] == "fp" and base in t.bases and None not in absolute)
            assumed = min(a for a in absolute if a is not None) - 4
            expect(assumed >= 0x80)
            offsets = [a - assumed for a in absolute if a is not None]
        expect(len(set(offsets)) == len(offsets))
        expect(set(offsets) == {4 + 32 * i for i in range(len(offsets))})
        expect(all(_stable(value) for _, value in stores))
        words = {offset: value for offset, (_, value) in zip(offsets, stores, strict=True)}
        count = len(words)
        while (following := c.peek()) is not None and _pointer_read(following) is not None:
            t.observe(c.take())
        stmt = c.take()
        expect(
            isinstance(stmt, Revert)
            and isinstance(stmt.payload, Slice)
            and stmt.payload.space == "MEM"
        )
        assert isinstance(stmt, Revert) and isinstance(stmt.payload, Slice)
        expect(c.same(stmt.payload.start, base))
        expect(c.same(stmt.payload.end, plus(base, 4 + 32 * count)))
    except (NoMatch, IndexError):
        return None
    consumed = c.consumed()
    kept: list[Stmt] = []
    hidden = [s for s in consumed if s is not stmt]
    if pointer is not None:
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
    return c.index, [*kept, revert]


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
