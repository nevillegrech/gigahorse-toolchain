// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

/// Parameter layouts and 160-bit types the decompiled view must not misstate.
contract ParameterFixture {
    struct Order {
        address maker;
        address taker;
        uint256 amount;
        uint256 price;
    }

    uint160 public price;
    address public owner;

    constructor() {
        owner = msg.sender;
        price = 3;
    }

    /// A static struct in calldata: four head words, one parameter.
    function settle(address caller, Order calldata order, uint256 fee) external pure returns (uint256) {
        uint256 total = order.amount * order.price + fee;
        if (order.maker == caller) {
            total += 1;
        }
        if (order.taker == caller) {
            total += 2;
        }
        return total;
    }

    /// The same struct decoded into memory.
    function settleMemory(Order memory order, uint256 fee) public pure returns (uint256) {
        return order.amount + order.price * fee + uint256(uint160(order.maker) ^ uint160(order.taker));
    }

    /// A uint160 parameter used as a number.
    function setPrice(uint160 next) external {
        require(msg.sender == owner, "owner");
        price = next * 2 + 1;
    }

    /// The stored uint160 used in arithmetic: price() returns a number, not an address.
    function scaled(uint160 by) external view returns (uint256) {
        return uint256(price) * by;
    }

    /// A computed uint160 return: masked like an address, printed as a number.
    function triple(uint160 x) external pure returns (uint160) {
        unchecked {
            return x * 3;
        }
    }

    /// A uint256 parameter that the code only uses as an address.
    function idToAddress(uint256 id) external pure returns (address) {
        return address(uint160(id));
    }

    /// Reads a calldata word past the one-word head (inside the dynamic argument).
    function tail(bytes calldata data) external pure returns (uint256 word, uint256 size) {
        assembly {
            word := calldataload(0x64)
        }
        size = data.length;
    }
}
