pragma solidity >0.4.18;

contract Deployed {
    
    function setA(uint) public {}
    
    function a() public pure returns (uint) {}
    
    function c() public pure returns (bool) {}

    function b() public pure returns (uint[] memory) {}
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
    
}
