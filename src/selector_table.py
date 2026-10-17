"""Jump targets of selector-table dispatchers (Vyper 0.3.10+), by running the dispatcher.

Vyper 0.3.10 replaced its linear selector checks with tables in the data
section. The dispatcher copies a table entry into memory (CODECOPY) and jumps
to an address read back from it (MLOAD, JUMP), which a stack-based analysis
cannot resolve:

- sparse ("gas"): entry = table[selector % buckets]; the jump goes to a bucket,
  whose code compares the selector with each of its methods;
- dense ("codesize"): a hashed entry holds (selector, handler, flags); the
  dispatcher checks the selector against the entry and jumps to the handler.

Instead of matching either layout, the dispatcher prefix is executed on
concrete calldata until it jumps to an address read from code. A jump every
probe selector reaches is a bucket jump (its targets are reported); a jump
only some selectors reach checks the selector first, so each selector that
reaches it is dispatched to that target (reported with its payability: whether
it is still reached with a call value). Both are what the code does, not a
guess: an emulated path is an execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MASK = (1 << 256) - 1
STEP_LIMIT = 400
PROBES = 4096
CALLDATA_WORDS = 64


@dataclass
class TableDispatch:
    # jump pc -> targets it can reach
    jumps: dict[int, set[int]] = field(default_factory=dict)
    # (handler, selector, payable) for jumps that check the selector first
    entries: list[tuple[int, int, bool]] = field(default_factory=list)
    # selector -> smallest calldata size the dispatcher accepts (checked-selector jumps)
    min_sizes: dict[int, int] = field(default_factory=dict)
    # Whether a selector the dispatcher does not route ends in revert(0, 0)
    fallback_reverts: bool = False
    # Selectors the dispatcher routes somewhere other than revert(0, 0)
    routed: set[int] = field(default_factory=set)


class _Stop(Exception):
    pass


def _instructions(code: bytes) -> tuple[dict[int, tuple[int, int]], set[int]]:
    """pc -> (opcode, push value); and the JUMPDEST pcs."""
    ops: dict[int, tuple[int, int]] = {}
    jumpdests: set[int] = set()
    pc = 0
    while pc < len(code):
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            size = op - 0x5F
            ops[pc] = (op, int.from_bytes(code[pc + 1 : pc + 1 + size].ljust(size, b"\0")))
            pc += 1 + size
            continue
        if op == 0x5B:
            jumpdests.add(pc)
        ops[pc] = (op, 0)
        pc += 1
    return ops, jumpdests


def _run(
    code,
    ops,
    jumpdests,
    selector: int,
    value: int,
    stop_at_first_branch=False,
    size: int | None = None,
    follow=False,
):
    """Execute from pc 0; return (jump pc, target) of the first jump to an address
    read from code, None otherwise. Values carry a flag: read from copied code.
    With `follow`, table jumps are taken and the result is ("revert", data size)
    when execution ends in a REVERT."""
    calldata = (selector.to_bytes(4, "big") + bytes(32 * CALLDATA_WORDS))[
        : (4 + 32 * CALLDATA_WORDS) if size is None else size
    ]
    stack: list[tuple[int, bool]] = []
    memory = bytearray(256)
    from_code = bytearray(256)  # 1 where a byte was written by CODECOPY
    copied = False
    pc = 0

    def pop():
        if not stack:
            raise _Stop
        return stack.pop()

    for _ in range(STEP_LIMIT):
        if pc not in ops:
            raise _Stop
        op, push = ops[pc]
        nxt = pc + 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
        if op == 0x5F:
            stack.append((0, False))
        elif 0x60 <= op <= 0x7F:
            stack.append((push, False))
        elif 0x80 <= op <= 0x8F:
            depth = op - 0x7F
            if len(stack) < depth:
                raise _Stop
            stack.append(stack[-depth])
        elif 0x90 <= op <= 0x9F:
            depth = op - 0x8F
            if len(stack) <= depth:
                raise _Stop
            stack[-1], stack[-1 - depth] = stack[-1 - depth], stack[-1]
        elif op == 0x50:
            pop()
        elif op in BINARY:
            (a, ta), (b, tb) = pop(), pop()
            stack.append((BINARY[op](a, b) & MASK, ta or tb))
        elif op == 0x15:
            a, ta = pop()
            stack.append((int(a == 0), ta))
        elif op == 0x19:
            a, ta = pop()
            stack.append((~a & MASK, ta))
        elif op == 0x35:
            offset, _ = pop()
            word = calldata[offset : offset + 32] if offset < len(calldata) else b""
            stack.append((int.from_bytes(word.ljust(32, b"\0")), False))
        elif op == 0x36:
            stack.append((len(calldata), False))
        elif op == 0x34:
            stack.append((value, False))
        elif op == 0x39:
            (dest, _), (offset, _), (size, _) = pop(), pop(), pop()
            if dest + size > len(memory) or size > 64:
                raise _Stop
            chunk = code[offset : offset + size].ljust(size, b"\0")
            memory[dest : dest + size] = chunk
            from_code[dest : dest + size] = b"\1" * size
            copied = True
        elif op == 0x51:
            (offset, _) = pop()
            if offset + 32 > len(memory):
                raise _Stop
            tainted = any(from_code[offset : offset + 32])
            stack.append((int.from_bytes(memory[offset : offset + 32]), tainted))
        elif op == 0x52:
            (offset, _), (word, _) = pop(), pop()
            if offset + 32 > len(memory):
                raise _Stop
            memory[offset : offset + 32] = word.to_bytes(32, "big")
            from_code[offset : offset + 32] = bytes(32)
        elif op == 0x56:
            target, tainted = pop()
            if tainted and not follow:
                return pc, target
            if target not in jumpdests:
                raise _Stop
            nxt = target
        elif op == 0x57:
            (target, tainted), (condition, _) = pop(), pop()
            if stop_at_first_branch:
                return ("branch", copied)
            if condition:
                if tainted and not follow:
                    return pc, target
                if target not in jumpdests:
                    raise _Stop
                nxt = target
        elif op == 0xFD and follow:
            (_, _), (length, _) = pop(), pop()
            return ("revert", length)
        elif op == 0x5B:
            pass
        else:
            raise _Stop  # outside the dispatcher prefix (halts, storage, calls, ...)
        pc = nxt
    raise _Stop


BINARY = {
    0x01: lambda a, b: a + b,
    0x02: lambda a, b: a * b,
    0x03: lambda a, b: a - b,
    0x04: lambda a, b: a // b if b else 0,
    0x06: lambda a, b: a % b if b else 0,
    0x10: lambda a, b: int(a < b),
    0x11: lambda a, b: int(a > b),
    0x14: lambda a, b: int(a == b),
    0x16: lambda a, b: a & b,
    0x17: lambda a, b: a | b,
    0x18: lambda a, b: a ^ b,
    0x1B: lambda a, b: b << a if a < 256 else 0,
    0x1C: lambda a, b: b >> a if a < 256 else 0,
}


def _probe(code, ops, jumpdests, selector, value=0, size=None, follow=False):
    try:
        return _run(code, ops, jumpdests, selector, value, size=size, follow=follow)
    except _Stop:
        return None


def selector_table(code: bytes) -> TableDispatch:
    """Table jumps of a selector-table dispatcher; empty for any other code."""
    result = TableDispatch()
    ops, jumpdests = _instructions(code)
    try:
        first = _run(code, ops, jumpdests, 0, 0, stop_at_first_branch=True)
    except _Stop:
        first = None
    # The dispatcher reads its table before the first branch (sparse), or
    # jumps without branching at all; solc and older Vyper never copy code there.
    if not (first == ("branch", True) or (first is not None and first[0] != "branch")):
        return result
    reached: dict[int, set[int]] = {}
    for selector in range(PROBES):
        hit = _probe(code, ops, jumpdests, selector)
        if hit is not None:
            reached.setdefault(hit[0], set()).add(selector)
            result.jumps.setdefault(hit[0], set()).add(hit[1])
    buckets = {pc for pc, selectors in reached.items() if len(selectors) == PROBES}
    for jump, selectors in reached.items():
        if jump not in buckets:
            for selector in selectors:
                target = _probe(code, ops, jumpdests, selector)[1]
                payable = _probe(code, ops, jumpdests, selector, value=1) is not None
                result.entries.append((target, selector, payable))
    # Selectors in the data: dense entries hold them; a candidate is one if the
    # dispatcher actually reaches a table jump with it.
    seen: set[int] = set()
    for start in range(len(code) - 3):
        selector = int.from_bytes(code[start : start + 4])
        if selector in seen or selector < PROBES:
            continue
        seen.add(selector)
        hit = _probe(code, ops, jumpdests, selector)
        if hit is None or hit[0] in buckets:
            continue
        jump, target = hit
        result.jumps.setdefault(jump, set()).add(target)
        payable = _probe(code, ops, jumpdests, selector, value=1) is not None
        result.entries.append((target, selector, payable))
    result.jumps = {pc: {t for t in ts if t in jumpdests} for pc, ts in result.jumps.items()}
    result.jumps = {pc: ts for pc, ts in result.jumps.items() if ts}
    result.entries = sorted({(t, s, p) for t, s, p in result.entries if t in jumpdests})
    for _, selector, _ in result.entries:
        result.min_sizes[selector] = next(
            (
                size
                for size in range(4 + 32 * CALLDATA_WORDS + 1)
                if _probe(code, ops, jumpdests, selector, size=size) is not None
            ),
            4 + 32 * CALLDATA_WORDS,
        )
    # Unrouted selectors (probes that are not entries or bucket methods): the
    # dispatcher must end in revert(0, 0) for every one of them.
    candidates = {s for _, s, _ in result.entries} | _bucket_selectors(ops)
    unrouted = [s for s in range(64) if s not in candidates]
    result.fallback_reverts = bool(result.jumps) and all(
        _probe(code, ops, jumpdests, s, follow=True) == ("revert", 0)
        and _probe(code, ops, jumpdests, s, size=0, follow=True) == ("revert", 0)
        for s in unrouted
    )
    if result.jumps:
        result.routed = {s for _, s, _ in result.entries} | {
            s
            for s in _bucket_selectors(ops)
            if _probe(code, ops, jumpdests, s, follow=True) != ("revert", 0)
        }
    return result


def _bucket_selectors(ops) -> set[int]:
    """PUSH4 values (the selectors a bucket compares with)."""
    return {value for op, value in ops.values() if op == 0x63}
