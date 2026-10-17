// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

/// Calldata structs that shared ABI decoder helpers return as pointers.
contract DecoderFixture {
    struct Position {
        address token;
        uint24 fee;
        int24 tickLower;
        uint256 amount;
        address recipient;
    }

    mapping(address => uint256) public credit;

    /// The struct is the whole head: its own bounds check equals the head check.
    function open(Position calldata p) external returns (uint256) {
        require(p.amount > 0, "amount");
        credit[p.recipient] += p.amount * p.fee;
        return uint256(int256(p.tickLower)) ^ uint256(uint160(p.token));
    }

    /// The same struct type, so the decoder helper is shared; a field read on one branch.
    function quote(Position calldata p) external pure returns (uint256) {
        if (p.amount > 100) {
            return uint256(uint160(p.recipient));
        }
        return p.amount + p.fee;
    }

    /// A word before the struct: the struct starts at head word 1.
    function shifted(uint256 bonus, Position calldata p) external pure returns (uint256) {
        return bonus + p.amount + uint256(uint160(p.token));
    }

    /// A uint256 field checked like a uint128 (a SafeCast) and used raw stays uint256.
    function scaled(Position calldata p) external pure returns (uint256) {
        uint128 low = uint128(p.amount);
        require(low == p.amount);
        return p.amount * 2 + p.fee;
    }
}
