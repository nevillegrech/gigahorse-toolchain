pragma solidity 0.8.4;

contract MergedVars {
    address public owner;
    uint8 public number;
    bool public flag;

    function update(address newOwner, uint8 newNumber, bool newFlag) external {
        owner = newOwner;
        number = newNumber;
        flag = newFlag;
    }

    function update(ValueProvider provider) external {
        owner = provider.getAddr();
        number = provider.getSmallInt();
        flag = provider.getBool();
    }
}

interface ValueProvider {

    function getAddr() external view returns (address);
    function getSmallInt() external view returns (uint8);
    function getBool() external view returns (bool);
}

contract SimpleArray {
    address[] public owners;
}

contract SimpleMapping {
    mapping (address => bool) public owners;
}