pragma solidity 0.8.4;

contract OwnerGuarded {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }

    function guarded() external {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}

contract AdminGuarded {
    mapping (address => bool) public isAdmin;
    
    constructor() {
        isAdmin[msg.sender] = true;
    }

    function addAdmin(address newAdmin) external {
        require(isAdmin[msg.sender]);
        isAdmin[newAdmin] = true;
    }

    function guarded() external {
        require(isAdmin[msg.sender]);
        payable(msg.sender).transfer(address(this).balance);
    }
}

contract ExternalAuthGuarded {
    OwnerGuarded public auth1;
    AdminGuarded public auth2;
    
    constructor(OwnerGuarded _auth1, AdminGuarded _auth2) {
        auth1 = _auth1;
        auth2 = _auth2;
    }


    function guarded1() external {
        require(msg.sender == auth1.owner());
        payable(msg.sender).transfer(address(this).balance);
    }

    function guarded2() external {
        require(auth2.isAdmin(msg.sender));
        payable(msg.sender).transfer(address(this).balance);
    }
}
