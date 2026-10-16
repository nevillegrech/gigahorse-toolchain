"""Check sparse byte facts against concrete zero-filled memory and branch states."""

import random

from reconstruction.byte_memory import ByteMemory


def test_unknown_writes_invalidate_only_their_known_range():
    memory = ByteMemory(zero_default=True)
    memory.forget(32, 32)
    assert memory.get(31) == memory.get(64) == 0
    assert memory.get(32) is None
    memory.update([(33, 0), (34, 18)])
    assert memory.get(33) == 0 and memory.get(34) == 18
    memory.forget(None, 0)
    assert memory.get(34) == 18
    memory.forget(None, 1)
    assert memory.get(34) is None and memory.get(1000000) is None


def test_join_does_not_turn_disagreeing_explicit_values_into_background_zero():
    left, right = ByteMemory(zero_default=True), ByteMemory(zero_default=True)
    right.update([(10, 18)])
    joined = left.join(right)
    assert joined.get(10) is None and joined.get(11) == 0
    left.forget(8, 8)
    left.update([(10, 18)])
    joined = left.join(right)
    assert joined.get(10) == 18 and joined.get(12) is None and joined.get(16) == 0


def test_join_with_unknown_background_retains_only_established_bytes():
    unknown, zero = ByteMemory(), ByteMemory(zero_default=True)
    unknown.update([(17, 0), (18, 2)])
    joined = unknown.join(zero)
    assert not joined.zero_default
    assert joined.get(17) == 0 and joined.get(18) is None and joined.get(19) is None
    assert unknown.fingerprint() != zero.fingerprint()


def test_interval_limit_discards_zero_background_without_losing_explicit_bytes():
    memory = ByteMemory(zero_default=True)
    memory.update([(1024, 18)])
    for index in range(129):
        memory.forget(index * 2, 1)
    assert not memory.zero_default and not memory.unknown_ranges
    assert memory.get(1024) == 18 and memory.get(1025) is None


def test_random_memory_facts_remain_true_across_writes_and_branch_joins():
    rng = random.Random(328947)
    for _ in range(40):
        memory = ByteMemory(zero_default=True)
        concrete = [bytearray(96)]
        branches = 0
        for _ in range(28):
            action = rng.randrange(4)
            start, size = rng.randrange(88), rng.randrange(1, 9)
            if action == 0:
                data = rng.randbytes(size)
                memory.forget(start, size)
                memory.update(enumerate(data, start))
                for state in concrete:
                    state[start : start + size] = data
            elif action == 1:
                memory.forget(start, size)
                for state in concrete:
                    state[start : start + size] = rng.randbytes(size)
            elif action == 2 and branches < 4:
                other = memory.copy()
                data = rng.randbytes(size)
                other.forget(start, size)
                other.update(enumerate(data, start))
                forked = [bytearray(state) for state in concrete]
                for state in forked:
                    state[start : start + size] = data
                memory = memory.join(other)
                concrete.extend(forked)
                branches += 1
            else:
                memory.forget(None, size)
                for state in concrete:
                    offset = rng.randrange(88)
                    state[offset : offset + size] = rng.randbytes(size)
            for offset in range(96):
                known = memory.get(offset)
                if known is not None:
                    assert all(state[offset] == known for state in concrete), (action, offset)
