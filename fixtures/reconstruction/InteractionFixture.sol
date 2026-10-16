// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

interface TokenLike {
    function transfer(address to, uint256 value) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

contract InteractionFixture {
    uint256 public count;

    function pay(address token, address to, uint256 amount) external returns (bool) {
        bool ok = TokenLike(token).transfer(to, amount);
        require(ok, "token");
        count += 1;
        return ok;
    }

    function read(address token, address owner) external view returns (uint256) {
        return TokenLike(token).balanceOf(owner);
    }

    function send(address payable to, uint256 amount) external payable returns (bool) {
        (bool ok,) = to.call{value: amount}("");
        return ok;
    }

    function forward(address target, bytes calldata data) external payable returns (bool, bytes memory) {
        return target.call{value: msg.value}(data);
    }

    function delegate(address target, bytes calldata data) external returns (bool, bytes memory) {
        return target.delegatecall(data);
    }

    function rawTransfer(address target, address to, uint256 amount) external returns (bool, bytes memory) {
        return target.call(abi.encodeWithSelector(TokenLike.transfer.selector, to, amount));
    }
}

// Only used by independent EVM validation; never provided to the decompiler.
contract InteractionTarget {
    function transfer(address to, uint256 amount) external pure returns (bool) {
        require(to != address(0), "recipient");
        return amount != 13;
    }

    function balanceOf(address owner) external pure returns (uint256) {
        return uint256(uint160(owner)) ^ 0xabc;
    }

    receive() external payable {}
}
