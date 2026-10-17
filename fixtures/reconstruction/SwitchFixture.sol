// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

/// An internal function that switches on msg.sig, as Balancer's vault does for its
/// signature type hashes: the selectors it compares are not new public functions.
contract SwitchFixture {
    uint256 public calls;

    function first(uint256 x) external returns (bytes32) {
        calls += 1;
        return _role(x);
    }

    function second(uint256 x) external returns (bytes32) {
        calls += 2;
        return _role(x);
    }

    function other() external view returns (bytes32) {
        return _role(calls);
    }

    /// A switch on the selector, compared with EQ (Balancer's 0.7 shape): the
    /// literals are first(uint256) and second(uint256).
    function _role(uint256 x) internal pure returns (bytes32 role) {
        bytes32 a = keccak256("FIRST");
        bytes32 b = keccak256("SECOND");
        assembly {
            switch shr(224, calldataload(0))
            case 0x0b3f62f5 {
                role := a
            }
            case 0x7896dfe3 {
                role := b
            }
            default {
                role := x
            }
        }
    }
}
