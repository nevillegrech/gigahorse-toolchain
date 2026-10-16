import hashlib
import json
from pathlib import Path

import pytest

from reconstruct import write_bundle
from reconstruction.model import Block, Function, Instruction, Program, load_program
from reconstruction.recovered import Expressions, render_recovered
from reconstruction.semantics import Term, child, find_guards, parse_term
from src.tac_schema import TACRelations

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"
STEMS = ("storage-optimized", "storage-via-ir", "layout-optimized", "layout-via-ir")


def fixture_program(stem, directory):
    core = json.loads((FIXTURES / f"{stem}.relations.json").read_text())
    semantic = json.loads((FIXTURES / f"{stem}.semantic.json").read_text())
    TACRelations(core | semantic).write_dir(directory)
    return load_program(directory)


def test_nested_souffle_terms_are_parsed_as_data():
    term = parse_term('$MappingAccessIndex($MappingAccessIndex($ConstantIndex(0x2), "0x7_a"), 0x8)')
    assert term.constructor == "MappingAccessIndex"
    assert child(child(term)).arguments == ("0x2",)
    assert child(term).arguments[1] == "0x7_a"
    assert parse_term("$Storage") == parse_term("$Storage()") == Term("Storage")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "0x1",
        "$Constant()",
        "$Constant(0x1, 0x2)",
        "$Mapping($Constant(0x1)",
        "$Storage,$Storage",
        "$Constant(__import__('os'))",
        "$Storage trailing",
        "$Mapping(" * 70 + "$Constant(0x0)" + ")" * 70,
    ],
)
def test_malformed_semantic_terms_fail_explicitly(text):
    with pytest.raises(ValueError):
        parse_term(text)


@pytest.mark.parametrize("stem", STEMS)
def test_compiler_fixture_hashes_and_selectors_match(stem, tmp_path):
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    assert (
        hashlib.sha256((FIXTURES / manifest["source"]).read_bytes()).hexdigest()
        == manifest["source_sha256"]
    )
    assert (
        hashlib.sha256(bytes.fromhex((FIXTURES / f"{stem}.hex").read_text())).hexdigest()
        == manifest["bytecode_sha256"]
    )
    program = fixture_program(stem, tmp_path)
    recovered = {selector for function in program.functions for selector in function.selectors}
    assert {"0x" + value for value in manifest["method_identifiers"].values()} <= recovered


@pytest.mark.parametrize("stem", STEMS)
def test_readable_view_has_valid_evidence_and_keeps_stateful_operations(stem, tmp_path):
    program = fixture_program(stem, tmp_path)
    text, source_map = render_recovered(program)
    statements = {s.id: s for b in program.blocks for s in b.instructions}
    mapped = {sid for line in source_map["lines"] for sid in line["ir_statements"]}
    stateful = {
        sid
        for sid, s in statements.items()
        if s.opcode
        in {
            "SLOAD",
            "SSTORE",
            "TLOAD",
            "TSTORE",
            "RETURN",
            "REVERT",
            "CALL",
            "DELEGATECALL",
            "STATICCALL",
            "CREATE",
            "SELFDESTRUCT",
        }
    }
    assert stateful <= mapped
    assert mapped <= statements.keys()
    for line in source_map["lines"]:
        assert 1 <= line["line"] <= len(text.splitlines())
        expected_offsets = {
            offset
            for sid in line["ir_statements"]
            for offset in statements[sid].original_statements
        }
        assert set(line["bytecode_offsets"]) == expected_offsets
    assert "require(" in text
    assert "NOT compilable Solidity" in text
    assert program.semantics.storage_accesses
    assert "inferences" in " ".join(program.warnings)


@pytest.mark.parametrize("stem", ("storage-optimized", "storage-via-ir"))
def test_mapping_paths_and_source_type_ambiguity_remain_visible(stem, tmp_path):
    program = fixture_program(stem, tmp_path)
    text, _ = render_recovered(program)
    assert "mapping_1[msg.sender]" in text
    assert "mapping_1[msg.sender] = " in text
    by_selector = {
        selector: function.id for function in program.functions for selector in function.selectors
    }
    boolean_function = by_selector["0xf6e00e0f"]
    boolean = [arg for arg in program.semantics.arguments if arg.function == boolean_function]
    assert boolean[0].type_candidates == ["bool"]
    assert boolean[0].validation_statements
    address_function = by_selector["0xe3d670d7"]
    address = [arg for arg in program.semantics.arguments if arg.function == address_function]
    assert address[0].type_candidates == ["address", "uint160"]


@pytest.mark.parametrize("stem", ("layout-optimized", "layout-via-ir"))
def test_packed_ranges_agree_with_compiler_storage_layout(stem, tmp_path):
    program = fixture_program(stem, tmp_path)
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    inferred = program.semantics.storage_fields
    for field in manifest["storage_layout"]["storage"]:
        slot = hex(int(field["slot"]))
        width = int(manifest["storage_layout"]["types"][field["type"]]["numberOfBytes"])
        low, high = int(field["offset"]), int(field["offset"]) + width - 1
        assert any(
            candidate.slot == slot and candidate.byte_low == low and candidate.byte_high == high
            for candidate in inferred
        ), f"Missing {field['label']}: slot {slot}, bytes {low}..{high}"
    text, _ = render_recovered(program)
    assert "mapping_2[" in text
    assert "array_1" in text
    assert any(
        access.index.constructor == "MappingAccessIndex"
        and child(access.index).constructor == "MappingAccessIndex"
        for access in program.semantics.storage_accesses
    )


@pytest.mark.parametrize("opcode", ("SLOAD", "MLOAD", "TLOAD", "CALL", "STATICCALL", "PHI"))
def test_state_reads_and_calls_are_not_reexecuted_by_expression_inlining(opcode):
    load = Instruction("0x1", opcode, ["loaded"], ["slot"], ["0x1"])
    function = Function("fn", ["block"], [], None, [], ["block"])
    program = Program({"slot": "0x0"}, {}, [function], [Block("block", [load], [], [])], [], [])
    expressions = Expressions(program, function)
    value = expressions.value("loaded")
    assert value.text == expressions.name("loaded")
    assert not value.evidence


def test_guard_recognition_requires_two_resolved_distinct_outcomes():
    jump = Instruction("0x1", "JUMPI", [], ["target", "condition"], ["0x1"])
    block = Block("entry", [jump], ["success", "failure"], ["success"])
    program = Program({}, {"target": "failure"}, [], [block], [], [])
    guards = find_guards(program, {"failure"})
    assert len(guards) == 1 and not guards[0].success_when_nonzero
    program.block_targets.clear()
    assert find_guards(program, {"failure"}) == []
    program.block_targets["target"] = "failure"
    block.successors.append("third")
    assert find_guards(program, {"failure"}) == []


def test_partial_semantic_export_is_not_reported_as_success(tmp_path):
    directory = tmp_path / "relations"
    fixture_program("storage-via-ir", directory)
    (directory / "SemanticStoragePath.csv").unlink()
    with pytest.raises(FileNotFoundError):
        load_program(directory)


def test_unrecognized_semantic_schema_fails_explicitly(tmp_path):
    directory = tmp_path / "relations"
    fixture_program("storage-via-ir", directory)
    (directory / "SemanticSchema.csv").write_text("99\n")
    with pytest.raises(ValueError, match="Unsupported semantic schema"):
        load_program(directory)


def test_bundle_provenance_must_match_actual_bytecode(tmp_path):
    directory = tmp_path / "relations"
    fixture_program("storage-via-ir", directory)
    (directory / "bytecode.hex").write_text((FIXTURES / "storage-via-ir.hex").read_text())
    output = tmp_path / "bundle"
    with pytest.raises(ValueError, match="claimed provenance"):
        write_bundle(directory, output, {"input_sha256": "wrong"})
    assert not output.exists()
    write_bundle(directory, output, {"input_kind": "existing-relations"})
    report = json.loads((output / "analysis.json").read_text())
    assert (
        report["provenance"]["input_sha256"]
        == json.loads((FIXTURES / "storage-via-ir.json").read_text())["bytecode_sha256"]
    )
