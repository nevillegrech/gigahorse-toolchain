pragma solidity 0.8.4;

contract Tester{
  address public owner;
  event UpdateOwner(address, address);

  function updateOwner(address newOwner) external {
    emit UpdateOwner(owner, owner = newOwner);
  }
}
