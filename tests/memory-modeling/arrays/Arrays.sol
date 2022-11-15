pragma solidity >= 0.8.0;

contract CallDataArrays {

  function get(address[] memory addr) external pure returns (address[] memory) {
      return addr;
  }

  function get(uint256[] memory nums) external pure returns (uint256[] memory) {
      return nums;
  }

  function get(bool[] memory bools) external pure returns (bool[] memory) {
      return bools;
  }

}
