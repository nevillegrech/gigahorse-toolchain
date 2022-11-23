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

contract ArrayKeyMappings {

    mapping(bytes => bool) private map1;
    mapping(string => address) private map2;

    function targetFunction(bytes32 hash, bytes calldata key) external {
        require(!map1[key], "Already registered");
        map1[key] = true;
    }

    function targetFunction(bytes32 hash, string memory key) external {
        require(map2[key] == address(0), "Already registered");
        map2[key] = msg.sender;
    }
}
