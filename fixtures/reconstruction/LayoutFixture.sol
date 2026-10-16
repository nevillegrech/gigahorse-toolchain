// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

contract LayoutFixture {
    address private owner;
    bool private paused;
    uint64 private count;
    uint256[] private items;
    mapping(address => mapping(uint256 => uint256)) private credits;

    function configure(address nextOwner, bool nextPaused, uint64 nextCount) external {
        owner = nextOwner;
        paused = nextPaused;
        count = nextCount;
    }

    function inspect() external view returns (address, bool, uint64) {
        return (owner, paused, count);
    }

    function append(uint256 value) external {
        items.push(value);
    }

    function at(uint256 index) external view returns (uint256) {
        return items[index];
    }

    function size() external view returns (uint256) {
        return items.length;
    }

    function assign(address account, uint256 key, uint256 value) external {
        require(msg.sender == owner, "owner");
        credits[account][key] = value;
    }

    function lookup(address account, uint256 key) external view returns (uint256) {
        return credits[account][key];
    }
}
