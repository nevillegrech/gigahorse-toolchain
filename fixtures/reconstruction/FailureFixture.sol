// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

contract FailureFixture {
    error Denied(uint256 amount, address target);

    function reason(uint256 x) external pure returns (uint256) {
        require(x == 7, "permission denied");
        return x;
    }

    function longReason(bool fail) external pure {
        if (fail) revert(unicode"A long failure reason crosses several memory words and includes UTF-8: λ and 雪.\nThe bytes matter.");
    }

    function panicAdd(uint256 x) external pure returns (uint256) { return x + 1; }
    function panicDivide(uint256 x) external pure returns (uint256) { return 100 / x; }
    function panicAssert(bool value) external pure { assert(value); }
    function fixedCustom() external pure { revert Denied(7, address(0x1234)); }
    function dynamicCustom(uint256 x) external pure { revert Denied(x, address(0x1234)); }

    function raw(bytes calldata data) external pure {
        assembly {
            calldatacopy(0, data.offset, data.length)
            revert(0, data.length)
        }
    }

    function clobbered(uint256 word) external pure {
        assembly {
            mstore(0, shl(224, 0x08c379a0))
            mstore(4, 32)
            mstore(36, 3)
            mstore(68, "old")
            mstore(68, word)
            revert(0, 100)
        }
    }
}
