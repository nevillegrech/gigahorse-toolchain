"""Custom errors and Panic codes built in memory print as one revert and execute exactly."""

import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.highlevel.interpreter import DecompiledMachine, ViewMismatch
from reconstruction.highlevel.ir import CustomError
from reconstruction.highlevel.lift import ProgramContext
from reconstruction.highlevel.naming import load_names
from reconstruction.highlevel.passes import iter_expr, iter_statements
from reconstruction.highlevel.view import build_decompiled, collect_keys
from reconstruction_tests.synthetic import one_block_program
from reconstruction_tests.test_calldata_execution import creation_code
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"
DENIED = 0xEF39661E  # Denied(uint256,address)


def payloads(decompiled):
    return [
        node
        for view in decompiled.views
        for stmt in iter_statements(view.body)
        for expr in stmt.expressions()
        for node in iter_expr(expr)
        if isinstance(node, CustomError)
    ]


@pytest.mark.parametrize("variant", ["optimized", "via-ir"])
def test_dictionary_custom_error_is_named_and_matches_evm(variant, tmp_path, record_property):
    stem = f"failure-{variant}"
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    program = fixture_program(stem, tmp_path)
    dictionary = tmp_path / "errors.facts"
    dictionary.write_text(f"0x{DENIED:08x}\tDenied(uint256,address)\n")
    keys = collect_keys(ProgramContext.build(program, tmp_path))
    decompiled = build_decompiled(program, tmp_path, load_names(*keys, errors_path=dictionary))
    text = decompiled.text
    assert "error Denied(uint256,address); // [dict] 0xef39661e: selector hash matches" in text
    assert "revert Denied(7, address(0x1234));" in text  # the constant payload
    assert "revert Denied(varg0, address(0x1234));" in text  # built in memory
    reference = EVMReference(manifest)
    ids = manifest["method_identifiers"]
    cases = [bytes.fromhex(ids["fixedCustom()"])] + [
        bytes.fromhex(ids["dynamicCustom(uint256)"]) + encode(["uint256"], [x])
        for x in (0, 7, 2**255 + 1, 2**256 - 1)
    ]
    for data in cases:
        expected, reverted = reference.call(data)
        assert reverted and expected[:4] == DENIED.to_bytes(4, "big")
        result = DecompiledMachine(decompiled).execute(data)
        assert (result.output, result.reverted) == (expected, reverted), data.hex()
    record_property(f"custom_error_evm_cases_{variant}", len(cases))


def test_folded_free_pointer_assumption_is_checked_when_executed(tmp_path):
    program = fixture_program("failure-optimized", tmp_path)
    decompiled = build_decompiled(program, tmp_path)
    assumed = [p for p in payloads(decompiled) if p.assumed_pointer is not None]
    assert [p.assumed_pointer for p in assumed] == [0x80]
    assert "assumes-folded-free-pointer" in assumed[0].rules
    # Rewrite that payload with a wrong assumption: executing it must not pass silently.
    for view in decompiled.views:
        for stmt in iter_statements(view.body):
            if getattr(stmt, "payload", None) is assumed[0]:
                stmt.payload = CustomError(
                    DENIED, None, assumed[0].args, 0xA0, rules=assumed[0].rules
                )
    ids = json.loads((FIXTURES / "failure-optimized.json").read_text())["method_identifiers"]
    data = bytes.fromhex(ids["dynamicCustom(uint256)"]) + encode(["uint256"], [5])
    with pytest.raises(ViewMismatch, match="free pointer 0x80, expected 0xa0"):
        DecompiledMachine(decompiled).execute(data)


def _program(ops: list, constants: dict[str, str]):
    return one_block_program(ops, constants)


SELECTOR_WORD = DENIED << 224
CONSTANTS = {
    "zero": "0x0",
    "four": "0x4",
    "forty": "0x40",
    "eighty": "0x80",
    "word": hex(SELECTOR_WORD),
}


def _custom_error_program(case: str):
    """MEM[64] = 0x80; p = MEM[64]; MEM[p] = sel; MEM[p + 4] = msg.data[0]; revert(p, size)."""
    selector = [("PUSH", SELECTOR_WORD), "DUP2", ("MSTORE", "sel", [], ["p", "word"])]
    argument = [
        ("PUSH", 0),
        ("CALLDATALOAD", "load", ["x"], ["zero"]),
        "DUP2",
        ("PUSH", 4),
        ("ADD", "plus", ["a"], ["four", "p"]),
        ("MSTORE", "arg", [], ["a", "x"]),
    ]
    # The argument written first is clobbered by the selector word's zero bytes;
    # a 68-byte range includes a word nobody wrote. Neither may fold.
    stores = argument + selector if case == "argument-first" else selector + argument
    size = 0x44 if case == "unwritten-word" else 0x24
    ops = [
        ("PUSH", 0x80),
        ("PUSH", 0x40),
        ("MSTORE", "init", [], ["forty", "eighty"]),
        ("PUSH", 0x40),
        ("MLOAD", "pointer", ["p"], ["forty"]),
        *stores,
        ("PUSH", size),
        "DUP2",
        ("REVERT", "revert", [], ["p", "size"]),
    ]
    return _program(ops, CONSTANTS | {"size": hex(size)})


@pytest.mark.parametrize(
    "case,folded",
    [("selector-first", True), ("argument-first", False), ("unwritten-word", False)],
)
def test_memory_built_error_folds_only_when_bytes_are_exact(case, folded, record_property):
    program, runtime = _custom_error_program(case)
    decompiled = build_decompiled(program)
    assert bool(payloads(decompiled)) == folded, decompiled.text
    if folded:
        assert "revert(abi.encodeWithSelector(0xef39661e, msg.data[0]));" in decompiled.text
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    for word in (0, 1, 0xFFFF << 200, 2**256 - 1):
        data = word.to_bytes(32, "big")
        expected, reverted = reference.call(data)
        assert reverted and expected[:4] == DENIED.to_bytes(4, "big")
        result = DecompiledMachine(decompiled).execute(data)
        assert (result.output, result.reverted) == (expected, reverted), (case, data.hex())
    record_property(f"error_fold_{case}", folded)


def test_inline_panic_in_scratch_memory_becomes_panic():
    ops = [
        ("PUSH", 0x4E487B71 << 224),
        ("PUSH", 0),
        ("MSTORE", "sel", [], ["zero", "word"]),
        ("PUSH", 0x32),
        ("PUSH", 4),
        ("MSTORE", "code", [], ["four", "fifty"]),
        ("PUSH", 0x24),
        ("PUSH", 0),
        ("REVERT", "revert", [], ["zero", "size"]),
    ]
    constants = CONSTANTS | {"fifty": "0x32", "size": "0x24", "word": hex(0x4E487B71 << 224)}
    program, runtime = _program(ops, constants)
    decompiled = build_decompiled(program)
    assert "revert(Panic(50));" in decompiled.text
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    expected, reverted = reference.call(b"")
    assert reverted and expected == bytes.fromhex("4e487b71") + (50).to_bytes(32, "big")
    result = DecompiledMachine(decompiled).execute(b"")
    assert (result.output, result.reverted) == (expected, reverted)


def _right_aligned_program(case: str):
    """`mstore(0, sel)` then the arguments at 0x20, 0x40, ...; `revert(0x1c, 4 + 32k)`."""
    selector = [("PUSH", DENIED), ("PUSH", 0), ("MSTORE", "sel", [], ["zero", "selector"])]
    first = [
        ("PUSH", 0),
        ("CALLDATALOAD", "load", ["x"], ["zero"]),
        ("PUSH", 0x20),
        ("MSTORE", "arg0", [], ["thirtytwo", "x"]),
    ]
    if case == "one-argument":
        body, size = [*selector, *first], 0x24
    elif case == "free-pointer-slot":
        # The second argument word is MEM[0x40]: scratch once the code reverts.
        second = [
            ("PUSH", 0x20),
            ("CALLDATALOAD", "load1", ["y"], ["thirtytwo"]),
            ("PUSH", 0x40),
            ("MSTORE", "arg1", [], ["forty", "y"]),
        ]
        body, size = [*selector, *first, *second], 0x44
    else:  # the argument is a word read from memory at a calldata address
        read = [
            ("PUSH", 0),
            ("CALLDATALOAD", "load", ["a"], ["zero"]),
            ("MLOAD", "read", ["x"], ["a"]),
            ("PUSH", 0x20),
            ("MSTORE", "arg0", [], ["thirtytwo", "x"]),
        ]
        body, size = [*selector, *read], 0x24
    ops = [
        *body,
        ("PUSH", size),
        ("PUSH", 0x1C),
        ("REVERT", "revert", [], ["start", "size"]),
    ]
    constants = {
        "zero": "0x0",
        "thirtytwo": "0x20",
        "forty": "0x40",
        "start": "0x1c",
        "size": hex(size),
        "selector": hex(DENIED),
    }
    return _program(ops, constants)


@pytest.mark.parametrize("case", ["one-argument", "free-pointer-slot", "argument-reads-memory"])
def test_right_aligned_error_payloads_match_evm(case, record_property):
    program, runtime = _right_aligned_program(case)
    decompiled = build_decompiled(program)
    [payload] = payloads(decompiled)
    assert payload.selector == DENIED and payload.name is None
    text = decompiled.text
    if case == "one-argument":
        assert "revert(abi.encodeWithSelector(0xef39661e, msg.data[0]));" in text
    elif case == "free-pointer-slot":
        assert "revert(abi.encodeWithSelector(0xef39661e, msg.data[0], msg.data[32]));" in text
    else:
        # The selector store stays: the memory read may see it (address 0).
        assert "MEM[0] = 0xef39661e;" in text
        assert "revert(abi.encodeWithSelector(0xef39661e, MEM[msg.data[0]]));" in text
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    words = [0, 4, 0x20, 0x200, 2**256 - 1] if case != "argument-reads-memory" else [0, 4, 0x200]
    for word in words:
        data = word.to_bytes(32, "big") + (word ^ 0xABCD).to_bytes(32, "big")
        expected, reverted = reference.call(data)
        assert reverted and expected[:4] == DENIED.to_bytes(4, "big")
        result = DecompiledMachine(decompiled).execute(data)
        assert (result.output, result.reverted) == (expected, reverted), (case, data.hex())
    record_property(f"right_aligned_{case}", len(words))
