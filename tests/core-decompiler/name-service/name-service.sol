pragma solidity >=0.5.0 < 0.6.0;

contract NameService {
    uint256 _reservePrice;
    mapping (bytes32 => address) commitmentToOwner;
    mapping (bytes32 => uint256) commitmentToBlock;
    mapping (bytes32 => bytes32) nameToVal;
    mapping (bytes32 => address) nameToOwner;
    

    // constructor
    constructor(uint256 reservePrice) public {
        _reservePrice = reservePrice;
    }

    function transferTo(bytes32 name, address newOwner) public {
        require(nameToOwner[name] == msg.sender, "Only the owner can change the ownership.");
        nameToOwner[name] = newOwner;
    }

    function setValue(bytes32 name, bytes32 value) public {
        require(nameToOwner[name] == msg.sender, "Only the owner can change the value.");
        nameToVal[name] = value;
    }

    function getValue(bytes32 name) public view returns (bytes32) {
        return nameToVal[name];
    }

    function commitToName(bytes32 commitment) public payable {
        require(msg.value == _reservePrice, "Please give a value higher than the reserve price.");
        require(commitmentToOwner[commitment] == address(0), "Someone has already committed to this name.");
        commitmentToOwner[commitment] = msg.sender;
        commitmentToBlock[commitment] = block.number;
    }

    function registerName(bytes32 nonce, bytes32 name, bytes32 value) public {
        bytes32 commitment = makeCommitment(nonce, name, msg.sender);
        require(commitmentToOwner[commitment] == msg.sender, "The message sender should have made the commitment");
        require(block.number - commitmentToBlock[commitment] >=20, "You can only reveal 20 blocks after commiting.");
        require(nameToOwner[name]== address(0), "Name already taken.");
        nameToOwner[name] = msg.sender;
        nameToVal[name] = value;
    }

    function getOwner(bytes32 name) public view returns(address) {
        return nameToOwner[name];
    }

    // Commitment utility
    function makeCommitment(bytes32 nonce, bytes32 name, address sender) public pure returns(bytes32) {
        return keccak256(abi.encodePacked(nonce, name, sender));
    }
}
