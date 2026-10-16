"""Custom errors and Panic codes built in memory print as one revert and execute exactly."""

import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.constants import resolve_constants
from reconstruction.highlevel.interpreter import DecompiledMachine, ViewMismatch
from reconstruction.highlevel.ir import CustomError
from reconstruction.highlevel.lift import ProgramContext
from reconstruction.highlevel.naming import load_names
from reconstruction.highlevel.passes import iter_expr, iter_statements
from reconstruction.highlevel.view import build_decompiled, collect_keys
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.semantics import SemanticInfo
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


OPCODES = {"MSTORE": 0x52, "MLOAD": 0x51, "CALLDATALOAD": 0x35, "ADD": 0x01, "REVERT": 0xFD}
OPCODES |= {"DUP2": 0x81}


def assemble(ops: list) -> tuple[bytes, list[Instruction]]:
    """Bytecode and one-block IR from one op list.

    An op is ("PUSH", value), a mnemonic, or (mnemonic, ir_name, definitions,
    operands) for an instruction that is also an IR statement at its pc.
    """
    code = bytearray()
    instructions = []
    for op in ops:
        if isinstance(op, tuple) and op[0] == "PUSH":
            value = op[1]
            width = max(1, (value.bit_length() + 7) // 8)
            code += bytes([0x5F + width]) + value.to_bytes(width, "big")
            continue
        mnemonic = op if isinstance(op, str) else op[0]
        if not isinstance(op, str):
            _, name, defs, uses = op
            instructions.append(
                Instruction(name, mnemonic, list(defs), list(uses), [hex(len(code))])
            )
        code.append(OPCODES[mnemonic])
    return bytes(code), instructions


def _program(ops: list, constants: dict[str, str]):
    runtime, instructions = assemble(ops)
    program = Program(
        dict(constants),
        {},
        [Function("root", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex(),
    )
    program.constants = resolve_constants(program, constants, [], [])
    program.semantics = SemanticInfo(3, [], [], [], {}, program.constants, [], [], [], [])
    return program, runtime


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
