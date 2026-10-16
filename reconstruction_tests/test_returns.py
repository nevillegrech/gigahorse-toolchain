"""Return encodings must be witnessed, bounded, and distinct from pointers."""

from dataclasses import replace

import pytest

from reconstruction.calldata import Offset
from reconstruction.memory import ReturnWrite
from reconstruction.model import Instruction, load_program
from reconstruction.recovered import render_recovered
from reconstruction.returns import ReturnAnalysis, analyze_returns, decode_encoding, describe
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_evaluation import evaluation_program


def aggregate(program):
    function = next(f for f in program.functions if f.selectors == ["0x82ad56cb"])
    layout = next(r for r in program.return_layouts if r.function == function.id)
    return function, layout


def test_deployed_return_layouts_use_encoder_witnesses_and_keep_raw_bytes(tmp_path):
    program, _ = evaluation_program(tmp_path)
    candidates = [r for r in program.return_layouts if r.status == "candidate_dynamic_encoding"]
    assert len(candidates) == 6
    assert len([r for r in program.return_layouts if r.status == "raw_words"]) == 10
    _, layout = aggregate(program)
    assert describe(layout.shape) == "((word{0,1}, byte_sequence)[])"
    text, mapping = render_recovered(program, structure_flow=True)
    candidate = next(
        line
        for line in mapping["lines"]
        if line["inference"] == "return-layout-candidate"
        and layout.statement in line["ir_statements"]
    )
    lines = text.splitlines()
    assert "Candidate return encoding" in lines[candidate["line"] - 1]
    assert "evm.return(" in lines[candidate["line"]]
    assert "return (u256(v_0x40acb + 0x20))" not in text
    assert len(layout.evidence) > 10
    assert {"0xb7eS0xbbeS0x40ac8", "0xb86S0xbbeS0x40ac8", "0xae7S0xb58S0xbbeS0x40ac8"} <= set(
        layout.evidence
    )


def test_memory_pointer_hint_is_not_printed_as_a_scalar_without_extension(tmp_path):
    program, _ = evaluation_program(tmp_path)
    program.semantics.memory_model = None
    program.return_layouts = analyze_returns(program)
    _, layout = aggregate(program)
    assert layout.status == "unresolved" and not layout.words
    text, mapping = render_recovered(program, structure_flow=True)
    assert "upstream value hints may be memory pointers" in text
    assert not any(line["inference"] == "raw-return-words" for line in mapping["lines"])


@pytest.mark.parametrize(
    "fault", ["counter-stride", "missing-phi", "unknown-store", "ambiguous-width", "unaligned-head"]
)
def test_incomplete_array_encoder_does_not_become_a_type_claim(tmp_path, fault):
    program, _ = evaluation_program(tmp_path)
    function, layout = aggregate(program)
    analysis = ReturnAnalysis(program)
    if fault == "counter-stride":
        definition = None
        # Find the actual increment feeding the outer encoder's count PHI.
        for phi, _, value in program.phi_inputs:
            if "0xb4f_0x0" in phi and "0x40ac8" in phi:
                stmt = analysis.definitions.get(value)
                if (
                    stmt
                    and stmt.opcode == "ADD"
                    and any(analysis.value(v) == Offset(1) for v in stmt.operands)
                ):
                    definition = stmt
                    break
        assert definition is not None
        program.semantics.constants["bad_step"] = "0x2"
        definition.operands = [
            "bad_step" if analysis.value(v) == Offset(1) else v for v in definition.operands
        ]
    elif fault == "missing-phi":
        program.phi_inputs = [
            r for r in program.phi_inputs if not ("0xb4f_0x8" in r[0] and "0x40ac8" in r[0])
        ]
    elif fault == "unknown-store":
        block = analysis.blocks["0xb4fB0xbbeB0x40ac8"]
        block.instructions.insert(
            -1, Instruction("clobber", "MSTORE", [], ["unknown_address", "unknown_word"], [])
        )
    elif fault == "ambiguous-width":
        memory = program.semantics.memory_model
        allocation = next(a for a in memory.arrays if a.identity == "0xbcbV0x40ac8")
        memory.arrays.append(replace(allocation, element_bytes="0x1"))
    else:
        header = next(
            w
            for w in program.semantics.memory_model.return_writes
            if w.statement == layout.statement and w.offset == 0
        )
        value = analysis.statements[header.writer].operands[1]
        program.semantics.constants[value] = "0x21"
    updated = next(r for r in analyze_returns(program) if r.function == function.id)
    assert updated.status == "unresolved" and updated.shape is None
    assert updated.limitations


def test_partial_write_blocks_raw_word_reconstruction(tmp_path):
    program = fixture_program("storage-via-ir", tmp_path)
    layout = next(
        r for r in program.return_layouts if r.status == "raw_words" and len(r.words) == 1
    )
    statement = next(s for b in program.blocks for s in b.instructions if s.id == layout.statement)
    block = next(b for b in program.blocks if statement in b.instructions)
    block.instructions.insert(
        -1, Instruction("byte-clobber", "MSTORE8", [], [statement.operands[0], "byte"], [])
    )
    program.semantics.memory_model.return_writes.append(
        ReturnWrite(statement.id, "byte-clobber", 0, 0, 1)
    )
    updated = next(r for r in analyze_returns(program) if r.statement == statement.id)
    assert updated.status == "unresolved" and not updated.words


@pytest.mark.parametrize("fault", ["schema", "missing-table", "zero-width", "foreign-return"])
def test_invalid_memory_extension_fails_explicitly(tmp_path, fault):
    evaluation_program(tmp_path)
    if fault == "schema":
        (tmp_path / "SemanticMemorySchema.csv").write_text("99\n")
    elif fault == "missing-table":
        (tmp_path / "SemanticMemoryArray.csv").unlink()
    elif fault == "zero-width":
        (tmp_path / "SemanticMemoryArray.csv").write_text("array\t0x0\tlength\n")
    else:
        (tmp_path / "SemanticMemoryReturnArray.csv").write_text("missing-return\t0\tarray\n")
    with pytest.raises((ValueError, FileNotFoundError)):
        load_program(tmp_path)


def encoded_result():
    def word(value):
        return value.to_bytes(32)

    parts = [word(1) + word(64) + word(5) + b"hello".ljust(32, b"\0"), word(0) + word(64) + word(0)]
    return word(32) + word(2) + word(64) + word(64 + len(parts[0])) + b"".join(parts)


def result_shape():
    return {
        "kind": "tuple",
        "items": [
            {
                "kind": "array",
                "element": {
                    "kind": "tuple",
                    "items": [{"kind": "canonical_bool_word"}, {"kind": "byte_sequence"}],
                },
            }
        ],
    }


def test_wire_decoder_handles_nested_dynamic_and_static_tuples():
    assert decode_encoding(encoded_result(), result_shape()) == [[[1, b"hello"], [0, b""]]]
    shape = {
        "kind": "tuple",
        "items": [
            {
                "kind": "array",
                "element": {"kind": "tuple", "items": [{"kind": "word"}, {"kind": "word"}]},
            }
        ],
    }
    data = b"".join(value.to_bytes(32) for value in (32, 2, 1, 2, 3, 4))
    assert decode_encoding(data, shape) == [[[1, 2], [3, 4]]]


@pytest.mark.parametrize(
    "fault", ["backward", "unaligned", "boolean", "padding", "truncated", "budget", "cycle"]
)
def test_wire_decoder_rejects_invalid_or_unbounded_shapes(fault):
    data = bytearray(encoded_result())
    shape = result_shape()
    if fault == "backward":
        data[:32] = (0).to_bytes(32)
    elif fault == "unaligned":
        data[:32] = (33).to_bytes(32)
    elif fault == "boolean":
        data[128:160] = (2).to_bytes(32)
    elif fault == "padding":
        data[255] = 1
    elif fault == "truncated":
        data = data[:-1]
    elif fault == "cycle":
        shape = {"kind": "array"}
        shape["element"] = shape
    with pytest.raises(ValueError):
        decode_encoding(bytes(data), shape, max_items=1 if fault == "budget" else 4096)


def test_tuple_field_constraints_keep_bool_and_address_ambiguity(tmp_path):
    program, _ = evaluation_program(tmp_path)
    function, _ = aggregate(program)
    fields = {f.field_index: f for f in program.calldata_fields if f.function == function.id}
    assert fields[0].checked_type_candidates == ["address", "uint160"]
    assert "call_target" in fields[0].roles
    assert fields[1].checked_type_candidates == [] and "condition_input" in fields[1].roles
    assert fields[2].encoding == "byte_sequence" and fields[2].checked_type_candidates == []
    assert all("bool" not in f.checked_type_candidates for f in fields.values())
    assert all(
        a.type_candidates == ["word"]
        for a in program.semantics.arguments
        if a.function == function.id
    )
