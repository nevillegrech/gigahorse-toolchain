// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

// A dynamic destination may overwrite the header or payload of another object.
contract AliasFixture {
    function directReturn(uint256 slotOffset, uint256 destination, uint256 value) external returns (uint256) {
        assembly {
            mstore(0x40, 0x80)
            let p := mload(add(0x40, slotOffset))
            mstore(p, 0x11223344)
            mstore(destination, value)
            return(p, 32)
        }
    }

    function aliasWord(uint256 slotOffset, uint256 destination, uint256 value) external returns (uint256) {
        assembly {
            mstore(0x40, 0x80)
            let p := mload(add(0x40, slotOffset))
            mstore(p, 0x11223344)
            mstore(destination, value)
            mstore(0, mload(p))
            return(0, 32)
        }
    }

    function aliasSize(uint256 slotOffset, uint256 destination, uint256 value) external returns (bytes32) {
        assembly {
            mstore(0x40, 0x80)
            let p := mload(add(0x40, slotOffset))
            mstore(p, 32)
            mstore(add(p, 32), 0x11223344)
            mstore(destination, value)
            return(add(p, 32), mload(p))
        }
    }

    function copyAlias(uint256 slotOffset, uint256 destination, uint256 value, uint256 size) external returns (uint256) {
        assembly {
            mstore(0x40, 0x80)
            let p := mload(add(0x40, slotOffset))
            mstore(p, 0x11223344)
            mstore(0x200, value)
            mcopy(destination, 0x200, size)
            mstore(0, mload(p))
            return(0, 32)
        }
    }
}
