pragma solidity >= 0.8.0;

contract CallDataToMemoryArrays {

  function get(address[] memory addr) external pure returns (address[] memory) {
      return addr;
  }

  function get(uint256[] memory nums) external pure returns (uint256[] memory) {
      return nums;
  }

  function get(string memory str) external pure returns (string memory) {
      return str;
  }

}

contract CallDataArrayGet {

  function _get(address[] calldata addr, uint256 index) private pure returns (address) {
      return addr[index];
  }

  function get(address[] calldata addr, uint256 index) external pure returns (address) {
      return _get(addr, index);
  }

  function get(address[] calldata addr, uint256 index1, uint256 index2) external pure returns (address, address) {
      return (_get(addr, index1), _get(addr, index2));
  }
}