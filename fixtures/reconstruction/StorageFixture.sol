// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

contract StorageFixture {
    uint256 private value;
    mapping(address => uint256) private balances;

    function read() external view returns (uint256) {
        return value;
    }

    function write(uint256 next) external {
        require(next <= 1000, "limit");
        value = next;
    }

    function credit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function balance(address account) external view returns (uint256) {
        return balances[account];
    }

    function choose(bool flag) external view returns (uint256) {
        return flag ? value : balances[msg.sender];
    }
}
