"""Terminal abstractions preserve payloads and must not hide relevant operations."""

import json

import pytest

from reconstruction.constant_memory import proof_is_current
from reconstruction.constants import resolve_constants
from reconstruction.controlflow import structure_function
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine, decode_revert_helper
from reconstruction.recovered import render_recovered
from reconstruction.returns import ReturnLayout
from reconstruction.revert_folding import find_revert_folds
from reconstruction.reverts import analyze_reverts
from reconstruction.semantics import SemanticInfo
from reconstruction.validation import UnsupportedExecution
from reconstruction_tests.test_reverts import error_bytes


def program_for_payload(data=None, extra=()):
    if data is None:
        data = error_bytes(b"permission denied")
    constants = {"zero": "0x0", "size": hex(len(data)), "gas": "0x10000", "target": "0x1234"}
    statements = []
    for offset in range(0, len(data), 32):
        address, value = f"offset{offset}", f"word{offset}"
        constants.update(
            {
                address: hex(offset),
                value: hex(int.from_bytes(data[offset : offset + 32].ljust(32, b"\0"))),
            }
        )
        statements.append(
            Instruction(f"store{offset}", "MSTORE", [], [address, value], [hex(offset + 1)])
        )
    statements += [*extra, Instruction("revert", "REVERT", [], ["zero", "size"], ["0xff"])]
    semantics = SemanticInfo(3, [], [], [], {}, constants, [], [], [], [])
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", statements, [], [])],
        [],
        [],
        semantics,
    )
    refresh(program)
    return program


def refresh(program):
    program.semantics.constants = resolve_constants(program, program.constants)


def folds(program):
    summaries = {r["statement"]: r for r in analyze_reverts(program)}
    function = program.functions[0]
    return find_revert_folds(program, function, structure_function(program, function), summaries)


def test_compact_helper_maps_every_removed_statement_to_its_original_offsets():
    program = program_for_payload()
    detailed, _ = render_recovered(program)
    text, mapping = render_recovered(program, structure_flow=True)
    assert 'evm.revert_error("permission denied");' in text and "evm.mstore(" not in text
    assert "evm.mstore(" in detailed and "evm.revert_error(" not in detailed
    line = next(row for row in mapping["lines"] if row["inference"] == "folded-revert")
    assert set(line["ir_statements"]) == {s.id for s in program.blocks[0].instructions}
    assert set(line["bytecode_offsets"]) == {
        pc for s in program.blocks[0].instructions for pc in s.original_statements
    }
    assert line["proof_references"] == ["constant_verification"]
    machine = ProjectedMachine(program, structured=True)
    result = machine.execute(b"")
    assert result.reverted and result.output == error_bytes(b"permission denied")
    assert machine.folded_revert_checks == 1


@pytest.mark.parametrize("op", ["SLOAD", "SSTORE", "TSTORE", "LOG0", "CALL", "STATICCALL"])
def test_state_reads_writes_logs_and_calls_stay_visible(op):
    if op in {"SLOAD"}:
        definitions, operands = ["loaded"], ["zero"]
    elif op in {"SSTORE", "TSTORE", "LOG0"}:
        definitions, operands = [], ["zero", "zero"]
    elif op == "CALL":
        definitions, operands = ["ok"], ["gas", "target", "zero", "zero", "zero", "zero", "zero"]
    else:
        definitions, operands = ["ok"], ["gas", "target", "zero", "zero", "zero", "zero"]
    program = program_for_payload(
        extra=[Instruction("effect", op, definitions, operands, ["0xfe"])]
    )
    assert analyze_reverts(program)[0]["status"] == "static"
    assert not folds(program)
    text, mapping = render_recovered(program, structure_flow=True)
    assert f"evm.{op.lower()}(" in text and not mapping["revert_folds"]


@pytest.mark.parametrize("change", ["instruction", "literal", "edge", "snapshot"])
def test_stale_or_corrupt_proof_inputs_withhold_folding_and_decoded_payload_claims(change):
    program = program_for_payload()
    assert proof_is_current(program) and folds(program)
    if change == "instruction":
        program.blocks[0].instructions[0].operands[1] = "zero"
    elif change == "literal":
        program.semantics.constants["word0"] = "0x0"
    elif change == "edge":
        program.blocks[0].successors.append("0x0")
    else:
        program.revert_memory["revert"]["known_ranges"][0]["data"] = "00"
    assert not proof_is_current(program) and not folds(program)
    assert analyze_reverts(program)[0]["status"] == "unresolved"


def test_a_definition_exposed_in_another_block_is_not_hidden():
    program = program_for_payload(
        extra=[Instruction("capture", "MLOAD", ["captured"], ["zero"], [])]
    )
    program.blocks.append(
        Block(
            "other",
            [
                Instruction("save", "SSTORE", [], ["zero", "captured"], []),
                Instruction("stop", "STOP", [], [], []),
            ],
            [],
            [],
        )
    )
    program.functions[0].blocks.append("other")
    refresh(program)
    assert proof_is_current(program) and not folds(program)


def test_a_definition_exposed_by_a_semantic_return_shape_is_not_hidden():
    program = program_for_payload(
        extra=[Instruction("capture", "MLOAD", ["captured"], ["zero"], [])]
    )
    program.return_layouts.append(
        ReturnLayout(
            "other",
            "other_return",
            "candidate_dynamic_encoding",
            {"kind": "array", "element": {"kind": "word"}, "length_variable": "captured"},
            [],
            [],
            [],
        )
    )
    assert proof_is_current(program) and not folds(program)


@pytest.mark.parametrize(
    "text",
    ["evm.revert_error('雪λ\\n');", "evm.revert_panic(0x11);", "evm.revert_data('0xdeadbeef');"],
)
def test_literal_helper_bytes_are_reencoded_independently(text):
    data = decode_revert_helper(text)
    assert data == (
        error_bytes("雪λ\n".encode())
        if "error" in text
        else bytes.fromhex("4e487b71") + (17).to_bytes(32)
        if "panic" in text
        else bytes.fromhex("deadbeef")
    )


@pytest.mark.parametrize(
    "text",
    [
        "__import__('os').getcwd();",
        "evm.revert_error(name);",
        "evm.revert_error('x', 'y');",
        "evm.revert_panic(-1);",
        "evm.revert_data('0xgg');",
    ],
)
def test_helper_parser_rejects_dynamic_or_unsupported_calls(text):
    with pytest.raises(UnsupportedExecution):
        decode_revert_helper(text)


def test_unconditional_encoder_chain_becomes_one_helper_with_complete_evidence():
    program = program_for_payload()
    original = program.blocks[0].instructions
    program.constants["jump_target"] = "0x100"
    program.block_targets["jump_target"] = "tail"
    program.blocks[0].instructions = [
        *original[:2],
        Instruction("jump", "JUMP", [], ["jump_target"], ["0x80"]),
    ]
    program.blocks[0].successors = ["tail"]
    program.blocks.append(Block("tail", original[2:], [], []))
    program.functions[0].blocks.append("tail")
    refresh(program)
    assert proof_is_current(program)
    text, mapping = render_recovered(program, structure_flow=True)
    assert text.count('evm.revert_error("permission denied");') == 1
    assert not any(word in text for word in ("evm.mstore(", "goto "))
    assert len(mapping["revert_folds"]) == 1
    fold = mapping["revert_folds"][0]
    assert tuple(fold["blocks"]) == ("0x0", "tail")
    assert set(fold["ir_statements"]) == {s.id for b in program.blocks for s in b.instructions}
    machine = ProjectedMachine(program, structured=True)
    assert machine.execute(b"").output == error_bytes(b"permission denied")
    assert machine.folded_revert_checks == 1


def test_state_write_before_revert_is_retained_and_matches_evm():
    pytest.importorskip("eth_tester", reason="install the validation extra")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    data = (0xAA).to_bytes(32)
    program = program_for_payload(
        data, [Instruction("effect", "SSTORE", [], ["zero", "size"], ["0x9"])]
    )
    program.blocks[0].instructions[0].original_statements = ["0x4"]
    program.blocks[0].instructions[-1].original_statements = ["0xe"]
    refresh(program)
    assert proof_is_current(program) and not folds(program)
    runtime = bytes.fromhex("60aa600052602060005560206000fd")
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    expected, reverted = reference.call(b"")
    assert reverted and expected == data
    text, mapping = render_recovered(program, structure_flow=True)
    assert "evm.sstore(0x0, 0x20)" in text and not mapping["revert_folds"]
    for mode in (False, True):
        machine = ProjectedMachine(program, structured=mode)
        result = machine.execute(b"")
        assert result.output == expected and result.reverted and not result.storage
        assert machine.folded_revert_checks == 0


def test_wrong_printed_helper_is_detected_against_the_original_memory(monkeypatch):
    monkeypatch.setattr(
        "reconstruction.revert_folding.render_helper", lambda _: 'evm.revert_error("wrong");'
    )
    program = program_for_payload()
    machine = ProjectedMachine(program, structured=True)
    with pytest.raises(UnsupportedExecution, match="Printed folded revert disagrees"):
        machine.execute(b"")
    assert (
        json.loads(json.dumps(program.to_dict()))["revert_summaries"][0]["reason"]
        == "permission denied"
    )
