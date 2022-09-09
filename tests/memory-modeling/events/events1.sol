pragma solidity >=0.4.21 <0.7.0;

contract SimpleAuction {
    event HighestBidIncreased(address bidder, uint amount); // Event
    event EventWithString(address, uint, string);
    event EventWithStringTwo(string, address, uint, string);

    function bid() public payable {
        // ...
        emit HighestBidIncreased(msg.sender, msg.value); // Triggering event
    }

    function getString(string memory testStr) public payable returns (bytes32){

    	emit EventWithString(msg.sender, msg.value, testStr);

        return keccak256(abi.encodePacked(testStr));
    }

    function getStringTwo(string memory testStr) public payable returns (bytes32){

    	emit EventWithStringTwo(testStr, msg.sender, msg.value, testStr);

        return keccak256(abi.encodePacked(testStr));
    }
}
