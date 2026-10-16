import hashlib

import pytest

from reconstruction.keccak import keccak256, selector, topic


def test_known_vectors():
    assert (
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert selector("transfer(address,uint256)") == "0xa9059cbb"
    assert topic("Transfer(address,address,uint256)") == (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_not_sha3_256_padding():
    # Ethereum Keccak differs from FIPS SHA3-256 only by the padding byte.
    assert keccak256(b"abc") != hashlib.sha3_256(b"abc").digest()


@pytest.mark.parametrize("length", [1, 135, 136, 137, 271, 272, 1000])
def test_block_boundaries_match_reference(length):
    eth_hash = pytest.importorskip("eth_hash.auto")
    data = bytes((i * 7 + length) & 0xFF for i in range(length))
    assert keccak256(data) == eth_hash.keccak(data)
