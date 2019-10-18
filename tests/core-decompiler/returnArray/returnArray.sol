pragma solidity >0.4.18;

contract Deployed {
    
    function setA(uint) public {}
    
    function a() public pure returns (uint) {}
    
    function c() public pure returns (bool) {}

    function b() public pure returns (uint[] memory) {}

    function hash2(string memory testStr, bytes memory testbytes) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr, testbytes));
    }

    function hash3(string memory testStr, uint256 num, bytes memory testbytes) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr, num, testbytes));
    }
}

contract Existing  {
    
    Deployed dc;
    
    constructor(address _t) public {
        dc = Deployed(_t);
    }
 
    function getA() public view returns (uint result) {
        if(dc.c())
            return 0;
        return dc.a();
    }

    function getB() public view returns (uint[] memory result) {
        return dc.b();
    }
    
    function setA(uint _val) public returns (uint result) {
        dc.setA(_val);
        return _val;
    }
    
    function doHash(string memory a, bytes memory b, uint c) public returns (bytes32, bytes32){
        return (dc.hash2(a,b), dc.hash3(a,c,b));
    }
}
