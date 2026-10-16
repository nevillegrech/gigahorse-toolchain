"""Sparse byte facts with an optional zero-filled EVM frame background.

Explicit known bytes override unknown intervals. A write of unknown address or
size discards the background and all facts; bounded interval overflow discards
only the background. Private calls carry the complete memory state.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class ByteMemory:
    facts: dict[int, int] = field(default_factory=dict)
    zero_default: bool = False
    unknown_ranges: tuple[tuple[int, int], ...] = ()

    def copy(self) -> ByteMemory:
        return ByteMemory(dict(self.facts), self.zero_default, self.unknown_ranges)

    def fingerprint(self) -> tuple:
        return self.zero_default, self.unknown_ranges, tuple(sorted(self.facts.items()))

    def get(self, offset: int) -> int | None:
        if offset in self.facts:
            return self.facts[offset]
        if self.zero_default and not any(a <= offset < b for a, b in self.unknown_ranges):
            return 0
        return None

    def __contains__(self, offset: int) -> bool:
        return self.get(offset) is not None

    def __getitem__(self, offset: int) -> int:
        value = self.get(offset)
        if value is None:
            raise KeyError(offset)
        return value

    def __len__(self) -> int:
        return len(self.facts)

    def clear(self):
        self.facts.clear()
        self.zero_default = False
        self.unknown_ranges = ()

    def _unknown(self, ranges: Iterable[tuple[int, int]]):
        if not self.zero_default:
            return
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if start >= end:
                continue
            if merged and start <= merged[-1][1]:
                merged[-1] = merged[-1][0], max(end, merged[-1][1])
            else:
                merged.append((start, end))
        if len(merged) > 128:
            self.zero_default, self.unknown_ranges = False, ()
        else:
            self.unknown_ranges = tuple(merged)

    def forget(self, offset: int | None, length: int | None):
        if length == 0:
            return
        if offset is None or length is None:
            self.clear()
            return
        self.facts = {k: v for k, v in self.facts.items() if not offset <= k < offset + length}
        self._unknown((*self.unknown_ranges, (offset, offset + length)))

    def update(self, values: Iterable[tuple[int, int]]):
        for offset, value in values:
            # Canonicalize redundant zero facts when the background knows them.
            implicit_zero = self.zero_default and not any(
                a <= offset < b for a, b in self.unknown_ranges
            )
            if value == 0 and implicit_zero:
                self.facts.pop(offset, None)
            else:
                self.facts[offset] = value

    def join(self, other: ByteMemory) -> ByteMemory:
        result = ByteMemory(zero_default=self.zero_default and other.zero_default)
        values = {}
        differing = []
        for offset in self.facts.keys() | other.facts.keys():
            left, right = self.get(offset), other.get(offset)
            if left is not None and left == right:
                values[offset] = left
            else:
                differing.append((offset, offset + 1))
        result._unknown((*self.unknown_ranges, *other.unknown_ranges, *differing))
        result.update(values.items())
        return result
