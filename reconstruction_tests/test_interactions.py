import json
from pathlib import Path

import pytest

from reconstruction.interactions import SIGNATURE_HINTS, load_external_calls, selector_value
from reconstruction.model import Block, Function, Instruction, Program, load_program
from reconstruction.recovered import render_recovered
from reconstruction_tests.test_controlflow import fixture_program

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


def sample_call(opcode="CALL"):
    operands = ["gas", "target", "value", "start", "size", "out", "outsize"]
    if opcode in {"STATICCALL", "DELEGATECALL"}:
        operands.remove("value")
    selector = Instruction("selector-def", "CONST", ["selector"], [], [])
    other = Instruction("other-def", "CONST", ["other"], [], [])
    call = Instruction("call", opcode, ["ok"], operands, [])
    writer = Instruction("writer", "MSTORE", [], ["start", "selector"], [])
    function = Function("fn", ["entry"], [], None, [*operands, "word"], ["entry"])
    return Program(
        {}, {}, [function], [Block("entry", [selector, other, writer, call], [], [])], [], []
    )


@pytest.mark.parametrize("opcode", ["CALL", "CALLCODE", "STATICCALL", "DELEGATECALL"])
def test_call_kinds_keep_their_distinct_operands_and_success_flag(opcode):
    call = load_external_calls(sample_call(opcode), {}, {}, {})[0]
    assert call.opcode == opcode and call.target == "target" and call.gas == "gas"
    assert call.value == ("value" if opcode in {"CALL", "CALLCODE"} else None)
    assert (call.input_offset, call.input_size, call.output_offset, call.output_size) == (
        "start",
        "size",
        "out",
        "outsize",
    )
    assert call.success_variables == ["ok"]
    assert not call.selector_resolved and not call.signature_hints


def test_selector_ambiguity_and_missing_words_are_retained():
    program = sample_call()
    tables = {"ExternalSelector": [("call", "selector"), ("call", "other")]}
    constants = {"selector": "0xa9059cbb", "other": "0x70a08231", "size": "0x44"}
    call = load_external_calls(program, tables, {"call": {1: ["word"]}}, constants)[0]
    assert not call.selector_resolved and not call.signature_hints
    assert call.selector_candidates == ["0x70a08231", "0xa9059cbb"]
    assert [a.variables for a in call.arguments] == [["word"], []]
    assert any("partial" in warning for warning in call.warnings)
    constants.pop("other")
    call = load_external_calls(program, tables, {}, constants)[0]
    assert call.selector_candidates == ["0xa9059cbb"] and not call.selector_resolved
    assert not call.signature_hints


@pytest.mark.parametrize(
    "table,row",
    [
        ("ExternalSelector", ("missing", "selector")),
        ("ExternalSelector", ("call", "missing")),
        ("ExternalReturn", ("call", "missing", "0")),
        ("ExternalReturn", ("call", "word", "-2")),
        ("ExternalMemory", ("call", "missing", "0", "0", "32")),
        ("ExternalMemory", ("call", "writer", "0", "32", "32")),
    ],
)
def test_invalid_external_evidence_fails_explicitly(table, row):
    with pytest.raises(ValueError):
        load_external_calls(sample_call(), {table: [row]}, {}, {})


def test_memory_evidence_uses_an_exclusive_end_and_allows_copy_ranges():
    call = load_external_calls(
        sample_call(), {"ExternalMemory": [("call", "writer", "-4", "0", "68")]}, {}, {}
    )[0]
    assert call.evidence == ["call", "writer"]
    assert selector_value("0xa9059cbb" + "00" * 28) == "0xa9059cbb"
    assert selector_value("0x123456789") is None


@pytest.mark.parametrize("variant", ("optimized", "via-ir"))
def test_real_interaction_views_keep_calls_and_their_evidence(variant, tmp_path):
    program = fixture_program("interaction-" + variant, tmp_path)
    text, mapping = render_recovered(program, structure_flow=True)
    calls = program.semantics.external_calls
    assert len(calls) == 6
    assert {c.opcode for c in calls} == {"CALL", "STATICCALL", "DELEGATECALL"}
    assert sum(c.selector_resolved for c in calls) == 3
    if variant == "optimized":
        copied = next(c for c in calls if c.abi_sources == ["memory-fragments"])
        assert len(copied.arguments) == 2 and all(len(a.variables) == 1 for a in copied.arguments)
        assert any(
            statements.opcode == "MCOPY"
            for b in program.blocks
            for statements in b.instructions
            if statements.id in copied.evidence
        )
    assert "transfer(address,uint256)" in text and "balanceOf(address)" in text
    assert "collisions possible" in text and "ABI is unresolved" in text
    assert "input: memory(" in text and "output: memory(" in text
    mapped = {
        s
        for line in mapping["lines"]
        if line["inference"] == "external-call"
        for s in line["ir_statements"]
    }
    assert {c.statement for c in calls} <= mapped
    statements = {s.id: s for b in program.blocks for s in b.instructions}
    assert mapped <= statements.keys()
    assert all({c.statement} <= set(c.evidence) <= statements.keys() for c in calls)
    assert all(c.return_variables for c in calls)
    manifest = json.loads((FIXTURES / f"interaction-{variant}.json").read_text())
    assert {"0x" + s for s in manifest["method_identifiers"].values()} <= {
        s for f in program.functions for s in f.selectors
    }


def test_current_schema_requires_complete_interaction_export(tmp_path):
    fixture_program("interaction-via-ir", tmp_path)
    (tmp_path / "SemanticExternalReturn.csv").unlink()
    with pytest.raises(FileNotFoundError):
        load_program(tmp_path)


def test_copy_schema_requires_fragment_evidence_table(tmp_path):
    fixture_program("copy-via-ir", tmp_path)
    (tmp_path / "SemanticCallDataEvidence.csv").unlink()
    with pytest.raises(FileNotFoundError):
        load_program(tmp_path)


@pytest.mark.parametrize("version", (1, 2))
def test_older_semantic_schemas_remain_readable(version, tmp_path):
    from reconstruction.interactions import COPY_TABLES, EXTERNAL_TABLES

    fixture_program("interaction-via-ir", tmp_path)
    (tmp_path / "SemanticSchema.csv").write_text(str(version) + "\n")
    for name in COPY_TABLES | (EXTERNAL_TABLES if version == 1 else {}):
        (tmp_path / f"Semantic{name}.csv").unlink()
    program = load_program(tmp_path)
    assert program.semantics.schema_version == version
    assert len(program.semantics.external_calls) == 6
    if version == 1:
        assert not any(c.selector_resolved for c in program.semantics.external_calls)


def test_local_signature_hints_have_the_claimed_keccak_selectors():
    keccak = pytest.importorskip("eth_hash.auto").keccak
    for selector, signatures in SIGNATURE_HINTS.items():
        assert all("0x" + keccak(s.encode())[:4].hex() == selector for s in signatures)


def test_copied_fragments_keep_byte_alignment_missing_words_and_evidence():
    tables = {
        "CallDataFragment": [
            ("call", "0", "4", "selector", "prefix32"),
            ("call", "4", "32", "word", "exact"),
        ],
        "CallDataEvidence": [("call", "writer")],
    }
    call = load_external_calls(
        sample_call(), tables, {}, {"selector": "0xa9059cbb" + "00" * 28, "size": "0x44"}
    )[0]
    assert call.selector_resolved and call.selector_candidates == ["0xa9059cbb"]
    assert call.abi_sources == ["memory-fragments"]
    assert [a.variables for a in call.arguments] == [["word"], []]
    assert {"call", "writer", "selector-def"} <= set(call.evidence)
    # A raw MSTORE's first four bytes are distinct from a right-aligned selector.
    call = load_external_calls(
        sample_call(), tables, {}, {"selector": "0xa9059cbb", "size": "0x44"}
    )[0]
    assert call.selector_candidates == ["0x00000000"]
    tables["CallDataFragment"].append(("call", "0", "4", "other", "exact"))
    call = load_external_calls(
        sample_call(), tables, {}, {"selector": "0xa9059cbb" + "00" * 28, "size": "0x44"}
    )[0]
    assert not call.selector_resolved and not call.signature_hints


@pytest.mark.parametrize(
    "offset,width,variable,encoding",
    [
        ("-1", "4", "selector", "exact"),
        ("0", "3", "selector", "exact"),
        ("0", "32", "selector", "prefix32"),
        ("65536", "4", "selector", "exact"),
        ("0", "4", "missing", "exact"),
    ],
)
def test_invalid_copied_fragment_facts_fail_explicitly(offset, width, variable, encoding):
    with pytest.raises(ValueError, match="calldata fragment"):
        load_external_calls(
            sample_call(),
            {"CallDataFragment": [("call", offset, width, variable, encoding)]},
            {},
            {},
        )


@pytest.mark.parametrize("variant", ("optimized", "via-ir"))
def test_copy_fixtures_preserve_overwrite_and_overlap_uncertainty(variant, tmp_path):
    stem = "copy-" + variant
    program = fixture_program(stem, tmp_path)
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    statements = {s.id: s for b in program.blocks for s in b.instructions}

    def call_for(signature):
        selector = "0x" + manifest["method_identifiers"][signature]
        function = next(f for f in program.functions if selector in f.selectors)
        ids = {s.id for b in program.blocks if b.id in function.blocks for s in b.instructions}
        calls = [c for c in program.semantics.external_calls if c.statement in ids]
        assert len(calls) == 1
        return calls[0]

    copied = call_for("copied(address,uint256,uint256)")
    assert copied.selector_resolved and copied.selector_candidates == ["0x11223344"]
    assert [len(a.variables) for a in copied.arguments] == [1, 1]
    copies = {s for s in copied.evidence if statements[s].opcode == "MCOPY"}
    assert len(copies) >= (2 if variant == "optimized" else 1)
    overwritten = call_for("overwrite(address,uint256,uint256,uint256)")
    assert overwritten.selector_resolved
    assert any(a.index == 0 and len(a.variables) == 1 for a in overwritten.arguments)
    clipped = call_for("clipped(address,uint256,uint256)")
    assert clipped.selector_resolved
    assert not any(a.index == 0 and a.variables for a in clipped.arguments)
    overlapping = call_for("overlap(address,uint256,uint256)")
    assert overlapping.selector_resolved
    assert not any(a.index == 0 and a.variables for a in overlapping.arguments)
    assert any(a.index == 1 and len(a.variables) == 1 for a in overlapping.arguments)
    for signature in (
        "uncertain(address,uint256)",
        "reverseOverlap(address,uint256,uint256)",
        "stale(address,uint256,uint256,uint256)",
    ):
        assert not call_for(signature).selector_resolved
    text, mapping = render_recovered(program, structure_flow=True)
    assert "partial" in text and "unknown" in text
    assert {c.statement for c in program.semantics.external_calls} <= {
        s for line in mapping["lines"] for s in line["ir_statements"]
    }
