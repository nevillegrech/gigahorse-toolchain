// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Loop snapshots exercise values captured before a later SSA/PHI update.
contract ExpressionFixture {
    function captureConditional(uint256 n, uint256 seed) external returns (uint256) {
        require(n > 0 && n <= 8);
        assembly {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                if iszero(i) { mstore(0, xor(add(seed, i), 0xa5)) }
                sstore(0, xor(seed, i))
            }
            return(0, 32)
        }
    }

    function captureFirst(uint256 n, uint256 seed) external returns (uint256) {
        require(n > 0 && n <= 8);
        assembly {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let saved := xor(add(seed, i), 0xa5)
                if iszero(i) { mstore(0, saved) }
                sstore(0, saved)
            }
            return(0, 32)
        }
    }

    function captureMapping(uint256 n, uint256 which, uint256 seed) external returns (uint256) {
        require(which < n && n <= 8);
        assembly {
            let selected := 0
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let key := xor(seed, i)
                if eq(i, which) {
                    mstore(0, key)
                    mstore(32, 11)
                    selected := keccak256(0, 64)
                }
                sstore(0, key)
            }
            sstore(selected, seed)
            mstore(0, sload(selected))
            return(0, 32)
        }
    }
}
