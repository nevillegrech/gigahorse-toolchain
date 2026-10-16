"""Memory allocations printed as objects execute exactly like the code they replace."""

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")

from reconstruction.highlevel.interpreter import DecompiledMachine, ViewMismatch
from reconstruction.highlevel.ir import Allocation, Assign
from reconstruction.highlevel.passes import iter_statements
from reconstruction.highlevel.view import build_decompiled
from reconstruction_tests.decompiled_support import DEPLOYED, deployed_fixture
from reconstruction_tests.synthetic import one_block_program
from reconstruction_tests.test_calldata_execution import creation_code
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_weth_execution import deploy_runtime

NOT31 = (1 << 256) - 32
CONSTANTS = {
    "zero": "0x0",
    "thirtyone": "0x1f",
    "thirtytwo": "0x20",
    "forty": "0x40",
    "sixtyfour": "0x40",
    "eighty": "0x80",
    "not31": hex(NOT31),
}
INIT = [("PUSH", 0x80), ("PUSH", 0x40), ("MSTORE", "init", [], ["forty", "eighty"])]
RETURN_WORD = [
    ("PUSH", 0),
    ("MSTORE", "out", [], ["zero", "s"]),
    ("PUSH", 0x20),
    ("PUSH", 0),
    ("RETURN", "ret", [], ["zero", "thirtytwo"]),
]


OPAQUE = [
    # MEM[msg.data[64]] = 0: an address the analysis cannot resolve, so the
    # words below are read back from memory (not forwarded from their stores).
    ("PUSH", 0),
    ("PUSH", 0x40),
    ("CALLDATALOAD", "where", ["w"], ["forty"]),
    ("MSTORE", "opaque", [], ["w", "zero"]),
]


def _struct_program(both_words: bool):
    """p = 2-word struct at the free pointer; word0 = msg.data[0] (and word1 =
    msg.data[32]); an opaque store; return word0 + word1 + MEM[64]."""
    second = [
        ("PUSH", 0x20),
        ("CALLDATALOAD", "load1", ["x1"], ["thirtytwo"]),
        "DUP2",
        ("PUSH", 0x20),
        ("ADD", "a1", ["a1"], ["thirtytwo", "p"]),
        ("MSTORE", "w1", [], ["a1", "x1"]),
    ]
    ops = [
        *INIT,
        ("PUSH", 0x40),
        ("MLOAD", "pointer", ["p"], ["forty"]),
        "DUP1",
        ("PUSH", 0x40),
        ("ADD", "end", ["e"], ["sixtyfour", "p"]),
        ("PUSH", 0x40),
        ("MSTORE", "update", [], ["forty", "e"]),
        ("PUSH", 0),
        ("CALLDATALOAD", "load0", ["x0"], ["zero"]),
        "DUP2",
        ("MSTORE", "w0", [], ["p", "x0"]),
        *(second if both_words else []),
        *OPAQUE,
        "DUP1",
        ("MLOAD", "r0", ["r0"], ["p"]),
        "DUP2",
        ("PUSH", 0x20),
        ("ADD", "a2", ["a2"], ["thirtytwo", "p"]),
        ("MLOAD", "r1", ["r1"], ["a2"]),
        ("ADD", "pair", ["q"], ["r1", "r0"]),
        ("PUSH", 0x40),
        ("MLOAD", "after", ["f"], ["forty"]),
        ("ADD", "sum", ["s"], ["f", "q"]),
        *RETURN_WORD,
    ]
    return one_block_program(ops, CONSTANTS)


def _bytes_program():
    """p = allocate(round(L) + 32) with L = msg.data[0]; MEM[p] = L; an opaque
    store; return MEM[p] + MEM[64] - p."""
    ops = [
        *INIT,
        ("PUSH", 0x40),
        ("MLOAD", "pointer", ["p"], ["forty"]),
        ("PUSH", 0),
        ("CALLDATALOAD", "load", ["L"], ["zero"]),
        "DUP1",
        ("PUSH", 31),
        ("ADD", "a", ["a"], ["thirtyone", "L"]),
        ("PUSH", NOT31),
        ("AND", "r", ["r"], ["not31", "a"]),
        ("PUSH", 0x20),
        ("ADD", "b", ["b"], ["thirtytwo", "r"]),
        "DUP3",
        ("ADD", "end", ["e"], ["p", "b"]),
        ("PUSH", 0x40),
        ("MSTORE", "update", [], ["forty", "e"]),
        "DUP2",
        ("MSTORE", "length", [], ["p", "L"]),
        *OPAQUE,
        "DUP1",
        ("MLOAD", "read", ["l"], ["p"]),
        "DUP2",
        ("PUSH", 0x40),
        ("MLOAD", "after", ["f"], ["forty"]),
        ("SUB", "size", ["d"], ["f", "p"]),
        ("ADD", "sum", ["s"], ["d", "l"]),
        *RETURN_WORD,
    ]
    return one_block_program(ops, CONSTANTS)


def _array_program():
    """Two `new uint256[](n)` (n = msg.data[0]); the second one's base depends on n,
    so its words are addressed from its pointer. q[1] = msg.data[32]; an opaque
    store; return q.length + q[1] + MEM[64]."""

    def allocation(pointer: str, suffix: str, depth: str) -> list:
        return [
            ("PUSH", 0x40),
            ("MLOAD", f"pointer{suffix}", [pointer], ["forty"]),
            depth,  # n
            ("PUSH", 0x20),
            ("MUL", f"b{suffix}", [f"b{suffix}"], ["thirtytwo", "n"]),
            ("PUSH", 0x20),
            ("ADD", f"c{suffix}", [f"c{suffix}"], ["thirtytwo", f"b{suffix}"]),
            "DUP2",
            ("ADD", f"e{suffix}", [f"e{suffix}"], [pointer, f"c{suffix}"]),
            ("PUSH", 0x40),
            ("MSTORE", f"update{suffix}", [], ["forty", f"e{suffix}"]),
            depth,  # n again
            "DUP2",  # the pointer
            ("MSTORE", f"length{suffix}", [], [pointer, "n"]),
        ]

    ops = [
        *INIT,
        ("PUSH", 0),
        ("CALLDATALOAD", "load", ["n"], ["zero"]),  # [n]
        *allocation("p1", "1", "DUP2"),  # [n, p1]
        *allocation("p", "2", "DUP3"),  # [n, p1, p]
        ("PUSH", 0x20),
        ("CALLDATALOAD", "loadx", ["x"], ["thirtytwo"]),
        "DUP2",
        ("PUSH", 0x40),
        ("ADD", "a", ["a"], ["sixtyfour", "p"]),
        ("MSTORE", "element", [], ["a", "x"]),
        *OPAQUE,
        "DUP1",
        ("PUSH", 0x40),
        ("ADD", "a2", ["a2"], ["sixtyfour", "p"]),
        ("MLOAD", "r", ["r"], ["a2"]),
        "DUP2",
        ("MLOAD", "l", ["l"], ["p"]),
        ("ADD", "q", ["q"], ["l", "r"]),
        ("PUSH", 0x40),
        ("MLOAD", "after", ["f"], ["forty"]),
        ("ADD", "sum", ["s"], ["f", "q"]),
        *RETURN_WORD,
    ]
    return one_block_program(ops, CONSTANTS)


def _allocations(decompiled):
    return [
        stmt.value
        for view in decompiled.views
        for stmt in iter_statements(view.body)
        if isinstance(stmt, Assign) and isinstance(stmt.value, Allocation)
    ]


def _matches_evm(decompiled, runtime, cases):
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    for data in cases:
        expected, reverted = reference.call(data)
        result = DecompiledMachine(decompiled).execute(data)
        assert (result.output, result.reverted) == (expected, reverted), data.hex()


WORDS = [(0, 0), (1, 2), (2**255, 2**255), (2**256 - 1, 7)]
OPAQUE_AT = [0x300, 0x80, 0xA0, 0]  # after the objects, onto word0 / word1, scratch


@pytest.mark.parametrize("both_words", [True, False])
def test_struct_allocation_fields_and_literal_match_evm(both_words):
    program, runtime = _struct_program(both_words)
    decompiled = build_decompiled(program)
    text = decompiled.text
    [allocation] = _allocations(decompiled)
    assert allocation.kind == "struct" and allocation.words == 2
    if both_words:
        assert "v0 = struct(msg.data[0], msg.data[32]);" in text
    else:
        assert "v0 = new struct(2);" in text and "v0.word0 = msg.data[0];" in text
    assert "v0.word0" in text and "v0.word1" in text
    cases = [
        a.to_bytes(32) + b.to_bytes(32) + where.to_bytes(32)
        for a, b in WORDS
        for where in OPAQUE_AT
    ]
    _matches_evm(decompiled, runtime, cases)


def test_bytes_allocation_matches_evm():
    program, runtime = _bytes_program()
    decompiled = build_decompiled(program)
    assert "v0 = new bytes(msg.data[0]);" in decompiled.text
    [allocation] = _allocations(decompiled)
    assert allocation.kind == "bytes"
    cases = [
        n.to_bytes(32) + bytes(32) + where.to_bytes(32)
        for n in (0, 1, 31, 32, 33, 64, 1000)
        for where in OPAQUE_AT
    ]
    _matches_evm(decompiled, runtime, cases)


def test_array_allocations_and_elements_match_evm():
    program, runtime = _array_program()
    decompiled = build_decompiled(program)
    text = decompiled.text
    # The first array is never read: the memory passes keep only its pointer bump.
    [array] = _allocations(decompiled)
    assert array.kind == "array"
    assert "v1 = new uint256[](msg.data[0]);" in text
    assert "v1[1] = msg.data[32];" in text and "v1[1]" in text.split("v1[1] = ")[1]
    assert "v1.length" in text
    cases = [
        n.to_bytes(32) + x.to_bytes(32) + where.to_bytes(32)
        for n in (0, 1, 2, 5)
        for x in (0, 7, 2**256 - 1)
        for where in OPAQUE_AT
    ]
    _matches_evm(decompiled, runtime, cases)


def test_folded_allocation_is_a_checked_string_constant(tmp_path):
    _, decompiled, runtime = deployed_fixture(DEPLOYED, "uniswap-v2-pair", tmp_path / "r")
    assert 'v0 = "Uniswap V2";' in decompiled.text and "v0.length" in decompiled.text
    name = next(v for v in decompiled.views if v.name == "name")
    allocation = next(
        s
        for s in iter_statements(name.body)
        if isinstance(s, Assign) and isinstance(s.value, Allocation)
    )
    assert allocation.value.assumed_base == 0x80 and allocation.value.text == b"Uniswap V2"
    assert "assumes-folded-free-pointer" in allocation.value.rules
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    deploy_runtime(reference, runtime, {})
    data = bytes.fromhex("06fdde03")
    expected, reverted = reference.call(data)
    assert not reverted
    assert DecompiledMachine(decompiled).execute(data).output == expected
    # A wrong assumption is never executed silently.
    allocation.value = Allocation(
        "struct",
        allocation.value.end,
        words=2,
        values=allocation.value.values,
        assumed_base=0xA0,
        text=allocation.value.text,
    )
    with pytest.raises(ViewMismatch, match="free pointer 0x80, expected 0xa0"):
        DecompiledMachine(decompiled).execute(data)
