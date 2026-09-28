pragma solidity 0.5.16;

// Each slot packs an address with a uint64. With --optimize, solc 0.5.16
// stores tx.origin, address(this), block.coinbase and msg.sender with no mask.
contract PackedAddresses {
    address public origin;
    uint64 public originTime;
    address public self;
    uint64 public selfTime;
    address public coinbase;
    uint64 public coinbaseTime;
    address public sender;
    uint64 public senderTime;

    function setOrigin() external { origin = tx.origin; }
    function setSelf() external { self = address(this); }
    function setCoinbase() external { coinbase = block.coinbase; }
    function setSender() external { sender = msg.sender; }

    function setTimes() external {
        uint64 time = uint64(block.timestamp);
        originTime = time;
        selfTime = time;
        coinbaseTime = time;
        senderTime = time;
    }
}
