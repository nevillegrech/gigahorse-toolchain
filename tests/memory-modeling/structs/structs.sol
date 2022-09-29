pragma solidity 0.8.4;

contract SimpleStruct {
    struct TransferArgs {
        address _from;
        address _to;
        uint256 _amt;
    }

    event Transfer(address,address,uint256);
    
    function transfer(address _to, uint256 _amt) external returns (bool) {
        TransferArgs memory args = TransferArgs(msg.sender, _to, _amt);
        _transfer(args);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amt) external returns (bool) {
        TransferArgs memory args = TransferArgs(_from, _to, _amt);
        _transfer(args);
        return true;
    }


    function altTransfer(address _to, uint256 _amt, bool _flag) external returns (bool) {
        TransferArgs memory args = TransferArgs(msg.sender, _to, _amt);

        if(_flag)
            args._amt = 2*args._amt;
        else
            args._amt = 3*args._amt;

        _transfer(args);
        return true;
    }

    function _transfer(TransferArgs memory args) internal {
        emit Transfer(args._from, args._to, args._amt);
    }
}

contract StoredStruct {
    struct TransferArgs {
        address _from;
        address _to;
        uint256 _amt;
    }

    mapping (address => TransferArgs) public storedTransfer;

    event Transfer(address,address,uint256);

    function storeTransfer(address _to, uint256 _amt) external returns (bool) {
        TransferArgs memory args = TransferArgs(msg.sender, _to, _amt);
        storedTransfer[msg.sender] = args;
        return true;
    }

    function transfer() external returns (bool) {
        TransferArgs memory args = storedTransfer[msg.sender];
        _transfer(args);
        return true;
    }

    function transferFrom(address from) external returns (bool) {
        TransferArgs memory args = storedTransfer[from];
        _transfer(args);
        return true;
    }

    function _transfer(TransferArgs memory args) internal {
        emit Transfer(args._from, args._to, args._amt);
    }
}

contract ComplexStruct {
    struct MessageArgs {
        address _from;
        address _to;
        bytes _data;
    }

    event Message(address,address,bytes);
    
    function transfer(address _to, bytes memory _data) external returns (bool) {
        MessageArgs memory args = MessageArgs(msg.sender, _to, _data);
        _msg(args);
        return true;
    }

    function transferFrom(address _from, address _to, bytes memory _data) external returns (bool) {
        MessageArgs memory args = MessageArgs(_from, _to, _data);
        _msg(args);
        return true;
    }

    function _msg(MessageArgs memory args) internal {
        emit Message(args._from, args._to, args._data);
    }
}

contract EmptyArrayConflict {

    event Message(address,address,bytes);

    function sendEmpty(address to) external {
        // SL: The empty array is currently mistakenly inferred as a single word struct.
        // Causes issues to the type inference of the 2nd argument of _msg(). Need to address.
        _msg(to, "");
    }

    function send(address to, bytes memory str) external {
        _msg(to, str);
    }

    function _msg(address to, bytes memory str) internal {
        emit Message(msg.sender, to, str);
    }
}