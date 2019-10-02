pragma solidity ^ 0.5;


contract ArrayTests{
    
    string public name;
    uint256[] public myArr;
    address payable public owner;
    
    function getBytes(bytes memory testbytes) public pure returns (bytes32){
        return keccak256(testbytes);
    }

    function getArray(uint[] memory testarr) public pure returns (bytes32){
        testarr[5] = 3;
        return keccak256(abi.encodePacked(testarr));
    }

    function getArrayExt(uint[] calldata testarr) external pure returns (bytes32){
        //testarr[5] = 3;
        return keccak256(abi.encodePacked(testarr[5]));
    }
    
    function getString(string memory testStr) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr));
    }

    function hash2(string memory testStr, bytes memory testbytes) public pure returns (bytes32){
        return keccak256(abi.encodePacked(testStr, testbytes));
    }

    function setName(string memory _name) public {
        name = _name;
    }

    function getArr() public view returns (uint256[] memory){
        return myArr;
    }

    function makeCall() public {
        ArrayTests myContract = ArrayTests(owner);
        uint256[] memory arr = myContract.getArr();
        myArr = arr;
    }

    function f(uint len) public pure {
        uint[] memory a = new uint[](7);
        bytes memory b = new bytes(len);
        uint32[] memory aa = new uint32[](len);
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
