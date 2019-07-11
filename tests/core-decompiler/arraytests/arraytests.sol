pragma solidity ^ 0.5;


contract ArrayTests{
    
    
    function getBytes(bytes memory testbytes) public pure returns (bytes32){
        return keccak256(testbytes);
    }
    
    function getString(string memory testStr) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr));
    }

    function hash2(string memory testStr, bytes memory testbytes) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr, testbytes));
    }

    function f(uint len) public pure {
        uint[] memory a = new uint[](7);
        bytes memory b = new bytes(len);
        uint[] memory aa = new uint[](len);
        assert(a.length == 7);
        assert(b.length == len);
        assert(aa.length == len);
        a[6] = 8;
        aa[8] = 99;
    }

    function g(uint len) public pure {
        uint[][] memory a = new uint[][](7);
        assert(a.length == 7);
        uint[] memory b = new uint[](7);
        a[6][6] = 8;
        a[1] = b;
        a[1][2] = len;
    }
}
