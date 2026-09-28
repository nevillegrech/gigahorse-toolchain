pragma solidity 0.5.16;

// digest is a full-word storage variable that holds a hash. Master types it
// both as bytes32 and as uint256.
// Compiled with: solc 0.5.16 --optimize --bin-runtime FullWordHash.sol
contract FullWordHash {
    bytes32 public digest;
    uint256 public count;

    function store(bytes calldata data) external {
        digest = keccak256(data);
        count = count + 1;
    }
}
