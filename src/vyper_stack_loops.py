"""Vyper 0.2 stack loops: loops that move a known number of words between
memory and the stack.

Vyper 0.2 moves multi-word values through the stack in loops whose counter
lives in memory (MEM[L]) and runs between constants:

- a return (make_return_stmt) pushes the result's words, last first, before
  jumping to the return address it keeps in memory:
      MEM[L] = size; while (MEM[L] > 0) { push MEM[base + MEM[L] - 32]; MEM[L] -= 32 }
- before an internal call, a function with a large frame saves it (0.2.4):
      MEM[L] = start; do { push MEM[MEM[L]]; MEM[L] += 32 } while (MEM[L] < end)
- and restores it after the call:
      MEM[L] = end - 32; do { MEM[MEM[L]] = pop; MEM[L] -= 32 } while (MEM[L] >= start)

A stack analysis cannot count the iterations, so it loses which word is where.
Each loop found here is rewritten by the decompiler's statement insertor
(logic/local.dl): the same loads (or stores), in the same order, just before
the counter is set; in the loop, the load is popped (or the store rewrites the
word with itself), so the loop no longer changes the stack. Memory is the
same: the loop writes only MEM[L], which is outside the words moved. The
count comes from the constants, found by executing the block that sets MEM[L].
"""

from __future__ import annotations

from dataclasses import dataclass

MASK = (1 << 256) - 1
# Two inserted instructions per word: the statement insertor gives each
# insertion point 80 statement ids (logic/statement_insertor.dl), and the
# words stay well within the analysis' 70 stack slots. Larger loops are left
# as they are (the analysis then resolves no return after them).
MAX_WORDS = 36

JUMPDEST, PUSH0, MLOAD, MSTORE, SUB, ADD, MUL = 0x5B, 0x5F, 0x51, 0x52, 0x03, 0x01, 0x02
LT, GT, ISZERO, JUMPI, JUMP, POP = 0x10, 0x11, 0x15, 0x57, 0x56, 0x50
TERMINATORS = {JUMP, JUMPI, 0x00, 0xF3, 0xFD, 0xFE, 0xFF}
# Opcodes that write memory at addresses the emulation does not follow.
MEMORY_WRITERS = {0x37, 0x39, 0x3C, 0x3E, 0x53, 0x5E, 0xF0, 0xF1, 0xF2, 0xF4, 0xF5, 0xFA}
ANY = None  # a pushed constant, bound by the caller of _match


@dataclass(frozen=True)
class StackLoop:
    # Where the moves go: before the first instruction setting the counter.
    insert_before: int
    # Words pushed (MLOAD of each address, in push order) or popped into memory
    # (MSTORE at each address, in pop order).
    loads: tuple[int, ...] = ()
    stores: tuple[int, ...] = ()
    # The loop's own load is popped before this instruction ...
    pop_before: int | None = None
    # ... or its own store keeps the word, inserted before this MSTORE.
    keep_before: int | None = None


def _instructions(code: bytes) -> list[tuple[int, int, int | None]]:
    out: list[tuple[int, int, int | None]] = []
    pc = 0
    while pc < len(code):
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            size = op - 0x5F
            out.append((pc, op, int.from_bytes(code[pc + 1 : pc + 1 + size].ljust(size, b"\0"))))
            pc += 1 + size
        else:
            out.append((pc, op, 0 if op == PUSH0 else None))
            pc += 1
    return out


def _push(ins: tuple[int, int, int | None]) -> int | None:
    return ins[2] if 0x5F <= ins[1] <= 0x7F else None


def _match(ins, i: int, shape: list) -> list[int] | None:
    """Match opcodes from i; ANY entries match a push and collect its value."""
    if i + len(shape) > len(ins):
        return None
    values = []
    for (_, op, value), want in zip(ins[i : i + len(shape)], shape, strict=True):
        if want is ANY:
            if value is None or not 0x5F <= op <= 0x7F:
                return None
            values.append(value)
        elif op != want:
            return None
    return values


RETURN_BODY = [JUMPDEST, ANY, ANY, MLOAD, SUB, ANY, ADD, MLOAD]
RETURN_BODY += [ANY, ANY, MLOAD, SUB, ANY, MSTORE, ANY, JUMP]
SAVE_LOOP = [JUMPDEST, ANY, MLOAD, MLOAD, ANY, ANY, MLOAD, ADD, ANY, MSTORE]
SAVE_LOOP += [ANY, ANY, MLOAD, LT, ISZERO, ANY, JUMPI, ANY, JUMP]
RESTORE_LOOP = [JUMPDEST, ANY, MLOAD, MSTORE, ANY, ANY, MLOAD, SUB, ANY, MSTORE]
RESTORE_LOOP += [ANY, ANY, MLOAD, LT, ISZERO, ISZERO, ANY, JUMPI, ANY, JUMP]


def _return_loop(ins, at, i):
    body = _match(ins, i, RETURN_BODY)
    if body is None:
        return None
    word, slot, base, word2, slot2, slot3, head = body
    if word != 32 or word2 != 32 or not slot == slot2 == slot3:
        return None
    if not _return_head(ins, at, head, slot, ins[i][0]):
        return None
    store = _counter_store(ins, at, head, slot)
    if store is None:
        return None
    start, size = store
    if size % 32 or not 0 < size <= 32 * MAX_WORDS or base - 32 < slot < base + size:
        return None
    loads = tuple(base + size - 32 * k for k in range(1, size // 32 + 1))
    return StackLoop(start, loads=loads, pop_before=ins[i + 8][0])


def _return_head(ins, at: dict[int, int], head: int, slot: int, body: int) -> bool:
    i = at.get(head)
    if i is None:
        return False
    w = ins[i : i + 12]
    ops = [x[1] for x in w]
    if len(w) < 9 or ops[0] != JUMPDEST or _push(w[1]) != 0 or _push(w[2]) != slot:
        return False
    if ops[3:5] != [MLOAD, GT]:
        return False
    k = 7 if ops[5:7] == [ISZERO, ISZERO] else 5
    return len(w) > k + 1 and _push(w[k]) == body and ops[k + 1] == JUMPI


def _frame_loop(ins, at, i):
    """A frame save or restore loop starting at i (its head is its body)."""
    head = ins[i][0]
    save = _match(ins, i, SAVE_LOOP)
    if save is not None:
        slot, word, slot2, slot3, end, slot4, _, back = save
        if word != 32 or back != head or not slot == slot2 == slot3 == slot4:
            return None
        store = _counter_store(ins, at, head, slot)
        if store is None:
            return None
        start, first = store
        if first % 32 or end % 32 or not 0 < (end - first) // 32 <= MAX_WORDS:
            return None
        if first - 32 < slot < end:
            return None
        loads = tuple(range(first, end, 32))
        return StackLoop(start, loads=loads, pop_before=ins[i + 4][0])
    restore = _match(ins, i, RESTORE_LOOP)
    if restore is not None:
        slot, word, slot2, slot3, low, slot4, _, back = restore
        if word != 32 or back != head or not slot == slot2 == slot3 == slot4:
            return None
        store = _counter_store(ins, at, head, slot)
        if store is None:
            return None
        start, first = store
        if first % 32 or low % 32 or not 0 < (first - low) // 32 + 1 <= MAX_WORDS:
            return None
        if low - 32 < slot < first + 32:
            return None
        stores = tuple(range(first, low - 1, -32))
        return StackLoop(start, stores=stores, keep_before=ins[i + 3][0])
    return None


def _counter_store(ins, at: dict[int, int], head: int, slot: int):
    """(start of the counter's value expression, value stored) in the block
    falling through into the loop head, or None."""
    j = at[head] - 1
    if j < 2 or ins[j][1] != MSTORE or _push(ins[j - 1]) != slot:
        return None
    if _push(ins[j - 2]) is not None:
        start = j - 2
    elif ins[j - 2][1] == MLOAD and j >= 3 and _push(ins[j - 3]) is not None:
        start = j - 3
    else:
        return None
    first = j
    while first > 0 and ins[first - 1][1] not in TERMINATORS and ins[first][1] != JUMPDEST:
        first -= 1
    value = _stored_value(ins[first : j + 1])
    return (ins[start][0], value) if value is not None else None


def _stored_value(block) -> int | None:
    """The value the block's last instruction (an MSTORE) stores, by executing
    the block on an unknown stack and memory: only constants are followed."""
    from src.opcodes import OPCODES

    by_code = {op.code: op for op in OPCODES.values()}
    stack: list[int | None] = []
    memory: dict[int, int | None] = {}

    def pop() -> int | None:
        return stack.pop() if stack else None

    for index, (_, op, value) in enumerate(block):
        if 0x5F <= op <= 0x7F:
            stack.append(value)
        elif 0x80 <= op <= 0x8F:
            n = op - 0x7F
            stack.append(stack[-n] if len(stack) >= n else None)
        elif 0x90 <= op <= 0x9F:
            n = op - 0x8F
            while len(stack) < n + 1:
                stack.insert(0, None)
            stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
        elif op == POP:
            pop()
        elif op == MLOAD:
            address = pop()
            stack.append(memory.get(address) if address is not None else None)
        elif op == MSTORE:
            address, word = pop(), pop()
            if index == len(block) - 1:
                return word
            if address is None:
                memory.clear()
            else:
                for key in [k for k in memory if abs(k - address) < 32]:
                    del memory[key]
                memory[address] = word
        elif op in (ADD, SUB, MUL):
            a, b = pop(), pop()
            if a is None or b is None:
                stack.append(None)
            else:
                stack.append({ADD: a + b, SUB: a - b, MUL: a * b}[op] & MASK)
        else:
            info = by_code.get(op)
            if info is None:
                return None
            for _ in range(info.pop_words()):
                pop()
            stack.extend([None] * info.push_words())
            if op in MEMORY_WRITERS:
                memory.clear()
    return None


def stack_loops(code: bytes) -> list[StackLoop]:
    ins = _instructions(code)
    at = {pc: i for i, (pc, _, _) in enumerate(ins)}
    found = []
    for i, (_, op, _) in enumerate(ins):
        if op != JUMPDEST:
            continue
        loop = _return_loop(ins, at, i) or _frame_loop(ins, at, i)
        if loop is not None:
            found.append(loop)
    return found
