"""Dependency-free Ethereum Keccak-256 (original Keccak padding, not SHA3-256).

Used to check selector/topic dictionaries without the optional naming extra.
Inputs here are short signature strings, so a plain-Python permutation suffices.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1
_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_RATE = 136  # bytes, for a 256-bit output


def _rotate(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(state: list[list[int]]) -> None:
    for constant in _ROUND_CONSTANTS:
        columns = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= delta
        moved = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                moved[y][(2 * x + 3 * y) % 5] = _rotate(state[x][y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = moved[x][y] ^ ((~moved[(x + 1) % 5][y]) & moved[(x + 2) % 5][y])
        state[0][0] ^= constant


def keccak256(data: bytes) -> bytes:
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE:
        padded.append(0)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), _RATE):
        block = padded[start : start + _RATE]
        for lane in range(_RATE // 8):
            x, y = lane % 5, lane // 5
            state[x][y] ^= int.from_bytes(block[8 * lane : 8 * lane + 8], "little")
        _permute(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()[:8]


def topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()
