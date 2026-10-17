# Internal calls: Vyper 0.2 keeps the return address in memory (callee stores
# it at entry, returns through mload) and pushes multi-word results in a loop.

total: public(uint256)
owner: public(address)


@external
def __init__():
    self.owner = msg.sender


@internal
@view
def _scaled(x: uint256) -> uint256:
    return x * 3 + self.total


@internal
@view
def _pair(x: uint256, y: uint256) -> (uint256, uint256):
    if x > y:
        return x - y, self._scaled(y)
    return y - x, self._scaled(x)


@internal
@view
def _first_above(x: uint256) -> (uint256, bool):
    for i in range(5):
        if i * 10 > x:
            return i, True
    return 0, False


@internal
def _bump(amount: uint256):
    assert amount < 1000, "too much"
    self.total += amount


@external
def first(x: uint256) -> uint256:
    self._bump(x)
    return self._scaled(x) + self._scaled(x + 1)


@external
@view
def second(x: uint256, y: uint256) -> uint256:
    a: uint256 = 0
    b: uint256 = 0
    a, b = self._pair(x, y)
    return a * 1000 + b


@external
def third(x: uint256) -> uint256:
    assert msg.sender == self.owner
    self._bump(1)
    a: uint256 = 0
    b: uint256 = 0
    a, b = self._pair(x, 7)
    return a + b + self._scaled(a)


@external
@view
def summed(n: uint256) -> uint256:
    s: uint256 = 0
    for i in range(4):
        if i >= n:
            break
        s += self._scaled(i)
    return s


@external
@view
def above(x: uint256) -> uint256:
    i: uint256 = 0
    found: bool = False
    i, found = self._first_above(x)
    if found:
        return i
    return 99
