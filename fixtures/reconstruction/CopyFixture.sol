// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

contract CopyFixture {
    function copied(address target, uint256 x, uint256 y) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        bytes memory out = new bytes(68);
        assembly { mcopy(add(out, 32), add(data, 32), 68) }
        return target.call(out);
    }

    function overwrite(address target, uint256 x, uint256 y, uint256 z) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        bytes memory out = new bytes(68);
        assembly {
            mcopy(add(out, 32), add(data, 32), 68)
            mstore(add(out, 36), z)
        }
        return target.call(out);
    }

    function clipped(address target, uint256 x, uint256 y) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        bytes memory out = new bytes(68);
        assembly { mcopy(add(out, 32), add(data, 32), 35) }
        return target.call(out);
    }

    function overlap(address target, uint256 x, uint256 y) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        assembly { mcopy(add(data, 36), add(data, 32), 32) }
        return target.call(data);
    }

    function uncertain(address target, uint256 length) external returns (bool, bytes memory) {
        require(length <= 68);
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), uint256(7), uint256(9));
        bytes memory out = abi.encodeWithSelector(bytes4(0x55667788), uint256(2), uint256(3));
        assembly { mcopy(add(out, 32), add(data, 32), length) }
        return target.call(out);
    }

    function stale(address target, uint256 x, uint256 y, uint256 z) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        assembly {
            let old := mload(add(data, 32))
            mstore(add(data, 36), z)
            mstore(add(data, 32), or(and(old, 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff), 0x1122334400000000000000000000000000000000000000000000000000000000))
        }
        return target.call(data);
    }

    function reverseOverlap(address target, uint256 x, uint256 y) external returns (bool, bytes memory) {
        bytes memory data = abi.encodeWithSelector(bytes4(0x11223344), x, y);
        assembly { mcopy(add(data, 32), add(data, 36), 32) }
        return target.call(data);
    }
}

contract CopyTarget {
    fallback() external {
        assembly {
            calldatacopy(0, 0, calldatasize())
            return(0, calldatasize())
        }
    }
}
