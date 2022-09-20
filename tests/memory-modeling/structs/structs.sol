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
