# Vyper 0.3.10 copies the uint256 arguments it passes on to an internal
# function straight from calldata (one CALLDATACOPY), reading only the
# int128 ones to check them. With a default argument, each entry point checks
# the calldata size before the shared body, so the copy is the only evidence
# of the copied words in the 4-argument entry.

balances: public(HashMap[address, uint256])


@internal
def _swap(i: int128, j: int128, dx: uint256, min_dy: uint256, sender: address) -> uint256:
    dy: uint256 = dx * 997 / 1000
    if i > j:
        dy = dy - 1
    assert dy >= min_dy, "slippage"
    self.balances[sender] += dy
    return dy


@external
def exchange(i: int128, j: int128, dx: uint256, min_dy: uint256) -> uint256:
    return self._swap(i, j, dx, min_dy, msg.sender)


@external
def exchange_for(i: int128, j: int128, dx: uint256, min_dy: uint256, to: address = msg.sender) -> uint256:
    return self._swap(i, j, dx, min_dy, to)
