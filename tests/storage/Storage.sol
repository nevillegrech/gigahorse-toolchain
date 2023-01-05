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

contract MergedArray {
    struct Info {
        address owner;
        uint8 number;
        bool flag;
    }
    Info[] public owners;
}

contract TwoWordValueArray {
    struct Info {
        uint256 val1;
        uint256 val2;
    }
    Info[] public vals;
    address public owner;
}

contract NestedMapping {
    mapping (address => mapping (address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
}

contract Complex {
    struct str {
        address a;
        uint256[] ns;
    }
    struct str2 {
        address a;
        mapping (address => address) mp;
    }
    mapping (address => str) public owners;
    mapping (address => str2) public admins;

    function getOwners(address key) external view returns (address, uint256[] memory) {
        str storage owner = owners[key];
        return (owner.a, owner.ns);
    }

    function adminFor(address key1, address key2) external view returns (address) {
        return admins[key1].mp[key2];
    }

}