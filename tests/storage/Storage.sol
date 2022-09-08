pragma solidity 0.8.4;

contract MergedVars {
    address public owner;
    uint8 public number;
    bool public flag;
}

contract SimpleArray {
    address[] public owners;
}

contract SimpleMapping {
    mapping (address => bool) public owners;
}
