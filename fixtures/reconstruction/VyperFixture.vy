# Public functions behind Vyper's dispatchers: linear selector checks
# (0.2, 0.3.9) and the selector table (0.3.10, gas and codesize modes); a
# reentrancy lock before the value check and a static array parameter.

event Deposit:
    owner: indexed(address)
    amount: uint256

balances: public(HashMap[address, uint256])
total: public(uint256)
owner: public(address)
fee: public(uint256)
paused: public(bool)


@external
def __init__():
    self.owner = msg.sender
    self.fee = 3


@external
@payable
def deposit() -> uint256:
    assert not self.paused, "paused"
    self.balances[msg.sender] += msg.value
    self.total += msg.value
    log Deposit(msg.sender, msg.value)
    return self.balances[msg.sender]


@external
def transfer(to: address, amount: uint256) -> bool:
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
    return True


@external
def set_fee(fee: uint256):
    assert msg.sender == self.owner
    assert fee <= 100
    self.fee = fee


@external
def pause(flag: bool):
    assert msg.sender == self.owner
    self.paused = flag


@view
@external
def quote(amount: uint256, i: int128) -> uint256:
    if i < 0:
        return amount
    return amount * (100 - self.fee) / 100


@view
@external
def scaled(x: int128, y: uint256) -> uint256:
    return convert(x, uint256) * y


@pure
@external
def pick(a: address, b: address, first: bool) -> address:
    if first:
        return a
    return b


@external
@nonreentrant("lock")
def add_liquidity(amounts: uint256[2], min_mint: uint256) -> uint256:
    minted: uint256 = amounts[0] + amounts[1]
    assert minted >= min_mint
    self.balances[msg.sender] += minted
    self.total += minted
    return minted
