"""Payload shapes need exact byte evidence; selectors do not prove a cause."""

import json

import pytest

from reconstruction.constant_memory import ConstantMemory, MemorySnapshot, State
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.reverts import (
    ERROR,
    PANIC,
    analyze_reverts,
    decode_payload,
    describe,
    guard_payloads,
)
from reconstruction.semantics import Guard, SemanticInfo
from reconstruction_tests.test_controlflow import fixture_program


def error_bytes(reason):
    return (
        bytes.fromhex(ERROR[2:])
        + (32).to_bytes(32)
        + len(reason).to_bytes(32)
        + reason.ljust((len(reason) + 31) // 32 * 32, b"\0")
    )


@pytest.mark.parametrize("reason", [b"", b"denied", b"x" * 95, "雪λ\n".encode(), b"\xff\xfe"])
def test_error_payload_preserves_raw_reason_bytes_and_utf8_uncertainty(reason):
    result = decode_payload(error_bytes(reason))
    assert result["encoding"] == "Error(string)"
    assert result["reason_hex"] == "0x" + reason.hex()
    assert result["reason"] == (None if reason == b"\xff\xfe" else reason.decode())
    text = describe({**result, "status": "static"})
    assert "\n" not in text
    assert "source-level cause" in result["limitations"][0]


@pytest.mark.parametrize("code", [0, 1, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 0x41, 0x51, 0x99])
def test_panic_code_is_decoded_without_claiming_it_was_generated_by_the_compiler(code):
    result = decode_payload(bytes.fromhex(PANIC[2:]) + code.to_bytes(32))
    assert result["encoding"] == "Panic(uint256)" and result["panic_code"] == hex(code)
    assert ("unrecognized" in result["panic_meaning"]) == (code == 0x99)


@pytest.mark.parametrize("fault", ["offset", "size", "padding", "truncated", "trailing"])
def test_noncanonical_error_payload_is_not_printed_as_a_decoded_reason(fault):
    data = bytearray(error_bytes(b"bad"))
    if fault == "offset":
        data[35] = 64
    elif fault == "size":
        data[67] = 255
    elif fault == "padding":
        data[-1] = 1
    elif fault == "truncated":
        data.pop()
    else:
        data.extend(b"\0" * 32)
    result = decode_payload(bytes(data))
    assert result["encoding"] != "Error(string)" and result["reason"] is None


def test_partial_selector_and_unknown_words_do_not_become_a_full_payload_claim():
    stmt = Instruction("bad", "REVERT", [], ["offset", "size"], ["0x10"])
    program = Program(
        {},
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", [stmt], [], [])],
        [],
        [],
    )
    program.revert_memory = {
        "bad": {
            "byte_length": 68,
            "known_ranges": [
                {"offset": 0, "data": "deadbeef"},
                {"offset": 36, "data": (7).to_bytes(32).hex()},
            ],
        }
    }
    info = analyze_reverts(program)[0]
    assert info["status"] == "partial" and info["selector"] == "0xdeadbeef"
    assert info["payload_hex"] is None and info["reason"] is None
    assert "remaining payload unresolved" in describe(info)


def test_snapshot_join_and_capture_bounds_forget_unestablished_bytes():
    a, b = MemorySnapshot(8, {0: 7, 1: 8}), MemorySnapshot(9, {0: 7, 1: 9})
    result = a.join(b)
    assert result.size is None and result.known == {0: 7}
    program = Program({}, {}, [], [], [], [])
    analysis = ConstantMemory(program, {}, (), ())
    analysis.capture_revert("huge", [0, (1 << 256) - 1], State({}, {0: 7}))
    assert not analysis.reverts["huge"].known
    analysis.capture_revert("empty", [None, 0], State({}, {}))
    assert analysis.reverts["empty"].to_dict() == {"byte_length": 0, "known_ranges": []}


def test_custom_selector_raw_words_are_not_given_an_invented_name_or_types():
    result = decode_payload(bytes.fromhex("deadbeef") + (7).to_bytes(32))
    assert result["encoding"] == "selector_and_raw_words"
    assert result["raw_words"] == ["0x7"] and result["selector"] == "0xdeadbeef"
    assert "name/types unresolved" in describe({**result, "status": "static"})
    assert json.loads(json.dumps(result)) == result


def test_inlined_calls_do_not_leave_data_operands_on_restored_jumps(tmp_path):
    program = fixture_program("failure-optimized", tmp_path)
    jumps = [s for b in program.blocks for s in b.instructions if s.opcode == "JUMP"]
    assert jumps and any("0x147" in s.original_statements for s in jumps)
    assert all(len(s.operands) == 1 for s in jumps)


@pytest.mark.parametrize("paths", ["same", "different", "missing", "cycle", "private-call"])
def test_guard_reason_requires_all_modeled_failure_paths_to_agree(paths):
    constants = {"zero": "0x0", "size": "0x64"}
    entry = Block(
        "0x0", [Instruction("guard", "JUMPI", [], ["bad", "flag"], [])], ["fail", "ok"], ["ok"]
    )
    fail = Block(
        "fail",
        [Instruction("branch", "JUMPI", [], ["left", "other"], [])],
        ["left", "right"],
        ["right"],
    )
    blocks = [entry, fail, Block("ok", [Instruction("stop", "STOP", [], [], [])], [], [])]
    for ident in ("left", "right"):
        blocks.append(
            Block(ident, [Instruction(ident, "REVERT", [], ["zero", "size"], [])], [], [])
        )
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], [b.id for b in blocks])],
        blocks,
        [],
        [],
    )
    program.semantics = SemanticInfo(
        3,
        [],
        [],
        [],
        {},
        constants,
        [Guard("0x0", "guard", "flag", "ok", "fail", False)],
        [],
        [],
        [],
    )
    for ident in ("left", "right"):
        data = error_bytes(b"B" if paths == "different" and ident == "right" else b"A")
        program.revert_memory[ident] = {
            "byte_length": len(data),
            "known_ranges": [{"offset": 0, "data": data.hex()}],
        }
    if paths == "missing":
        program.revert_memory.pop("right")
    if paths == "cycle":
        fail.successors = ["fail", "left"]
    if paths == "private-call":
        fail.instructions.insert(0, Instruction("call", "CALLPRIVATE", [], ["callee"], []))
    result = guard_payloads(program, analyze_reverts(program))
    assert ("guard" in result) == (paths == "same")
