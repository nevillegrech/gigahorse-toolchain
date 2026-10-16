// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

contract ControlFlowFixture {
    uint256 private running;

    function choose(bool flag, uint256 left, uint256 right) external pure returns (uint256) {
        uint256 result;
        if (flag) result = left + 7;
        else result = right * 3;
        return result ^ 0x55;
    }

    function sum(uint256 n) external pure returns (uint256 result) {
        require(n <= 64, "bound");
        for (uint256 i; i < n; ++i) {
            if (i == 7) continue;
            if (i == 31) break;
            result += i;
        }
    }

    function nested(uint256 n, uint256 m) external pure returns (uint256 result) {
        require(n <= 8 && m <= 8, "bound");
        for (uint256 i; i < n; ++i) {
            for (uint256 j; j < m; ++j) {
                if (((i + j) & 1) == 0) result += i * j;
                else result ^= j;
            }
        }
    }

    function persist(uint256 n) external returns (uint256) {
        require(n <= 32, "bound");
        for (uint256 i; i < n; ++i) running += i;
        return running;
    }

    function swap(uint256 n) external pure returns (uint256) {
        require(n <= 64, "bound");
        uint256 a = 1;
        uint256 b = 2;
        for (uint256 i; i < n; ++i) (a, b) = (b, a);
        return a * 100 + b;
    }
}
