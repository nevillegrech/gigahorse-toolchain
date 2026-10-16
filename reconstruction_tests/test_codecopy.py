"""Exact executed-code copying, zero padding, clobbers and proof freshness."""

import hashlib
from dataclasses import replace

import pytest

from reconstruction.constant_memory import proof_is_current
from reconstruction.constants import resolve_constants
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.reverts import analyze_reverts
from reconstruction.semantics import SemanticInfo
from reconstruction.validation import UnsupportedExecution

MASK = (1 << 256) - 1


def push(value):
    return b"\x7f" + value.to_bytes(32)


def copied_program(
    payload=b"bound code bytes",
    *,
    source=None,
    size=32,
    destination=0,
    output_size=None,
    halt="REVERT",
    bind=True,
):
    """Tuples select a calldata word; all other operands are literal EVM words."""
    names = (("size", size), ("source", source), ("destination", destination))
    end = sum(33 + isinstance(value, tuple) for _, value in names) + 1 + 66 + 1
    if source is None:
        source = end
    output_size = output_size if output_size is not None else size if isinstance(size, int) else 32
    output_offset = destination if isinstance(destination, int) else 0
    constants = {"out_size": hex(output_size), "out_offset": hex(output_offset)}
    raw, instructions = b"", []
    for name, value in (("size", size), ("source", source), ("destination", destination)):
        if isinstance(value, tuple):
            constants[name + "_head"] = hex(value[0])
            instructions.append(
                Instruction(
                    "load_" + name, "CALLDATALOAD", [name], [name + "_head"], [hex(len(raw) + 33)]
                )
            )
            raw += push(value[0]) + b"\x35"
        else:
            constants[name] = hex(value)
            raw += push(value)
    instructions.append(
        Instruction("copy", "CODECOPY", [], ["destination", "source", "size"], [hex(len(raw))])
    )
    raw += b"\x39" + push(output_size) + push(output_offset)
    instructions.append(Instruction("end", halt, [], ["out_offset", "out_size"], [hex(len(raw))]))
    raw += b"\xfd" if halt == "REVERT" else b"\xf3"
    assert len(raw) == end
    runtime = raw + payload
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex() if bind else None,
    )
    program.constants = resolve_constants(program, constants)
    program.semantics = SemanticInfo(3, [], [], [], {}, program.constants, [], [], [], [])
    return program, runtime


@pytest.mark.parametrize(
    "source,size,destination",
    [
        (None, 32, 0),
        (None, 5, 64),
        (None, 128, 0),
        (166, 32, 0),
        (1000000, 32, 0),
        (MASK, 32, 0),
        (MASK, 0, MASK),
    ],
)
def test_copy_and_padding_match_independent_evm(source, size, destination, record_property):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    program, runtime = copied_program(source=source, size=size, destination=destination)
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    expected, reverted = reference.call(b"")
    assert reverted
    for mode in (False, True):
        machine = ProjectedMachine(program, structured=mode)
        result = machine.execute(b"")
        assert (result.output, result.reverted) == (expected, reverted)
    summary = analyze_reverts(program)[0]
    assert summary["payload_hex"] == "0x" + expected.hex()
    assert proof_is_current(program)
    assert (
        program.constant_verification["bytecode_input"]["sha256"]
        == hashlib.sha256(runtime).hexdigest()
    )
    observation = program.constant_verification["code_copy_observations"][0]
    assert observation["copied_bytes_sha256"] == hashlib.sha256(expected).hexdigest()
    if source == MASK and size:
        assert observation["zero_padded_bytes"] == size and expected == bytes(size)
    record_property("codecopy_evm_cases", 1)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_literal_error_copied_from_code_folds_with_exact_source_evidence():
    reason = "copied reason ☃"
    data = reason.encode()
    payload = (
        bytes.fromhex("08c379a0")
        + (32).to_bytes(32)
        + len(data).to_bytes(32)
        + data.ljust((len(data) + 31) // 32 * 32, b"\0")
    )
    program, _ = copied_program(payload, size=len(payload))
    assert analyze_reverts(program)[0]["reason"] == reason
    text, mapping = render_recovered(program, structure_flow=True)
    assert 'evm.revert_error("copied reason \\u2603");' in text
    assert len(mapping["revert_folds"]) == 1
    assert {"copy", "end"} <= set(mapping["revert_folds"][0]["ir_statements"])
    assert "0x63" in mapping["revert_folds"][0]["bytecode_offsets"]
    assert ProjectedMachine(program, structured=True).execute(b"").output == payload


@pytest.mark.parametrize("dynamic", ("source", "destination", "size"))
def test_unknown_copy_operands_cannot_leave_zero_background_or_old_bytes(dynamic, record_property):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    args = {dynamic: (0,)}
    program, runtime = copied_program(**args)
    summary = analyze_reverts(program)[0]
    assert summary["status"] != "static"
    assert (
        program.constant_verification["code_copy_observations"][0]["status"] == "unresolved_range"
    )
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    for value in (0, 5, len(runtime) - len(b"bound code bytes")):
        data = value.to_bytes(32)
        expected, reverted = reference.call(data)
        for mode in (False, True):
            result = ProjectedMachine(program, structured=mode).execute(data)
            assert (result.output, result.reverted) == (expected, reverted)
    record_property("codecopy_evm_cases", 3)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_unavailable_input_does_not_supply_code_bytes_or_initial_zeros():
    program, _ = copied_program(bind=False)
    assert program.constant_verification["initial_memory"] == "unknown"
    assert analyze_reverts(program)[0]["status"] == "unresolved"
    with pytest.raises(UnsupportedExecution, match="exact executed code"):
        ProjectedMachine(program, structured=True).execute(b"")
    zero, _ = copied_program(bind=False, size=0, source=MASK, destination=MASK)
    assert ProjectedMachine(zero, structured=True).execute(b"").output == b""


@pytest.mark.parametrize("mutation", ("code", "evidence", "context"))
def test_changed_code_or_copy_provenance_withholds_decoded_payload(mutation):
    program, _ = copied_program()
    assert proof_is_current(program)
    if mutation == "code":
        program.runtime_bytecode = program.runtime_bytecode[:-2] + "ff"
    elif mutation == "evidence":
        program.constant_verification["code_copy_observations"][0]["source_offset"] = "0x0"
    else:
        program.constant_verification["bytecode_input"]["sha256"] = "0" * 64
    assert not proof_is_current(program)
    assert analyze_reverts(program)[0]["status"] == "unresolved"
    assert not render_recovered(program, structure_flow=True)[1]["revert_folds"]


def test_oversized_copy_withholds_knowledge_without_allocating_huge_ranges():
    program, _ = copied_program(size=MASK, output_size=32)
    assert analyze_reverts(program)[0]["status"] == "unresolved"
    assert (
        program.constant_verification["code_copy_observations"][0]["status"]
        == "copy_bound_exceeded"
    )


def test_codesize_is_established_only_from_the_exact_code_input(record_property):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    runtime = bytes.fromhex("3860005260206000f3") + b"unexecuted bytes"
    constants = {"zero": "0x0", "size": "0x20", "length": "0x1"}
    statements = [
        Instruction("length", "CODESIZE", ["length"], [], ["0x0"]),
        Instruction("store", "MSTORE", [], ["zero", "length"], ["0x3"]),
        Instruction("return", "RETURN", [], ["zero", "size"], ["0x8"]),
    ]
    p = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", statements, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex(),
    )
    p.constants = resolve_constants(p, constants)
    assert p.constants["length"] == hex(len(runtime))
    assert p.constant_hints["length"] == "0x1"
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    expected, reverted = reference.call(b"")
    for mode in (False, True):
        result = ProjectedMachine(p, structured=mode).execute(b"")
        assert (result.output, result.reverted) == (expected, reverted)
    missing = replace(p, runtime_bytecode=None)
    with pytest.raises(UnsupportedExecution, match="CODESIZE requires"):
        ProjectedMachine(missing, structured=False).execute(b"")
    record_property("codecopy_evm_cases", 1)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_private_memory_summaries_distinguish_zero_and_unknown_backgrounds():
    from reconstruction.byte_memory import ByteMemory
    from reconstruction.constant_memory import ConstantMemory

    function = Function("child", ["child"], [], None, [], ["child"])
    program = Program(
        {"zero": "0x0"},
        {},
        [function],
        [
            Block(
                "child",
                [
                    Instruction("read", "MLOAD", ["loaded"], ["zero"], []),
                    Instruction("return", "RETURNPRIVATE", [], ["zero", "loaded"], []),
                ],
                [],
                [],
            )
        ],
        [],
        [],
    )
    analysis = ConstantMemory(program, program.constants, (), ())
    zero = ByteMemory(zero_default=True)
    unknown = ByteMemory()
    clobbered = ByteMemory(zero_default=True)
    clobbered.forget(0, 32)
    assert zero.facts == unknown.facts == clobbered.facts == {}
    assert analysis.function(function, (), zero).values == (0,)
    assert analysis.function(function, (), unknown).values == (None,)
    assert analysis.function(function, (), clobbered).values == (None,)
    assert len(analysis.cache) == 3


@pytest.mark.parametrize("contents", ("xyz", "0x0", ""))
def test_malformed_executed_code_input_is_rejected(tmp_path, contents):
    from reconstruction.model import load_program
    from reconstruction_tests.test_controlflow import fixture_program

    fixture_program("control-flow-via-ir", tmp_path)
    (tmp_path / "bytecode.hex").write_text(contents)
    with pytest.raises(ValueError, match="bytecode"):
        load_program(tmp_path)


def test_legacy_relations_without_executed_code_remain_conservative(tmp_path):
    from reconstruction.model import load_program
    from reconstruction_tests.test_controlflow import fixture_program

    fixture_program("control-flow-via-ir", tmp_path)
    (tmp_path / "bytecode.hex").unlink()
    program = load_program(tmp_path)
    assert program.runtime_bytecode is None
    assert program.to_dict()["bytecode_context"]["available"] is False
    assert program.constant_verification["initial_memory"] == "unknown"
