// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.30;

/// A large internal function reading calldata through its argument (an
/// inlining candidate for the memory model), called from seven places:
/// inlined, it would be printed seven times.
contract InliningFixture {
    uint256[8] public weights;

    constructor() {
        for (uint256 i = 0; i < 8; i++) {
            weights[i] = i * 7 + 3;
        }
    }

    function _mix(uint256[] calldata xs, uint256 seed) internal view returns (uint256 acc) {
        acc = seed;
        for (uint256 i = 0; i < xs.length; i++) {
            uint256 x = (xs[i] ^ seed) + i;
            x = (x * 31 + weights[i % 8]) % 1_000_003;
            if (x & 1 == 1) {
                x = x * 3 + 1;
            } else {
                x = x / 2;
            }
            uint256 y = (x << 3) | (seed & 7);
            if (y > 4096) {
                y -= x / 3 + weights[(i + 1) % 8];
            }
            x = (x + y * 5) % 999_983;
            acc += x + i * weights[(i + 2) % 8];
        }
        if (acc > 10 ** 12) {
            acc = acc % 10 ** 12 + xs.length;
        }
    }

    function a(uint256[] calldata xs) external view returns (uint256) {
        return _mix(xs, 1);
    }

    function b(uint256[] calldata xs) external view returns (uint256) {
        return _mix(xs, 2) + 1;
    }

    function c(uint256[] calldata xs, uint256 s) external view returns (uint256) {
        return _mix(xs, s);
    }

    function d(uint256[] calldata xs, uint256[] calldata ys) external view returns (uint256) {
        return _mix(xs, 3) ^ _mix(ys, 4);
    }

    function e(uint256[] calldata xs) external view returns (uint256) {
        uint256 r = _mix(xs, 5);
        return _mix(xs, r);
    }

    function f(uint256[] calldata xs) external view returns (uint256) {
        return xs.length == 0 ? 0 : _mix(xs, xs[0]);
    }
}
