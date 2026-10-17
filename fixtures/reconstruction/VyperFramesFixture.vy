# Vyper 0.2.12 saves a caller's frame (more than 10 local variables) on the
# stack in a loop before an internal call, and restores it in a loop after.

total: public(uint256)


@internal
@view
def _scale(x: uint256) -> uint256:
    return x * 3 + self.total


@internal
@view
def _pair(x: uint256) -> (uint256, uint256):
    return x + 1, self._scale(x)


@internal
def _bump(amount: uint256):
    assert amount < 100, "too much"
    self.total += amount


@internal
@view
def _deep(x: uint256) -> uint256:
    c: uint256 = x + 1
    d: uint256 = c * 2
    e: uint256 = d + 3
    f: uint256 = e * 4
    g: uint256 = f + 5
    h: uint256 = g * 6
    i: uint256 = h + 7
    j: uint256 = i * 8
    k: uint256 = j + 9
    m: uint256 = k * 10
    n: uint256 = self._scale(m)
    return c + d + e + f + g + h + i + j + k + m + n


@external
def many(a: uint256, b: uint256) -> uint256:
    c: uint256 = a + b
    d: uint256 = a * 2
    e: uint256 = b * 3
    f: uint256 = c + d
    g: uint256 = e + f
    h: uint256 = g + 1
    i: uint256 = h + 2
    j: uint256 = i + 3
    k: uint256 = j + 4
    m: uint256 = k + 5
    n: uint256 = self._scale(a)
    p: uint256 = 0
    q: uint256 = 0
    p, q = self._pair(n)
    self._bump(b)
    r: uint256 = self._deep(q)
    return c + d + e + f + g + h + i + j + k + m + n + p + q + r
