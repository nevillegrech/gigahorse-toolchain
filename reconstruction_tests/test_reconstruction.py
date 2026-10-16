import json
import os
from pathlib import Path

import pytest

from reconstruct import main, normalize_bytecode, write_bundle
from reconstruction.model import Instruction, Program, load_program
from reconstruction.render import identifier, render_instruction, render_program
from src import tac_schema as schema

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


@pytest.fixture
def facts(tmp_path):
    """A minimal complete schema, including an intentional reverse-address order."""
    rows = {relation.name: [] for relation in schema.ALL_RELATIONS}
    rows.update(
        {
            "TAC_Op": [("0x20", "SLOAD"), ("0x10", "SSTORE")],
            "TAC_Block": [("0x20", "0x0"), ("0x10", "0x0")],
            "TAC_Statement_Next": [("0x20", "0x10")],
            "TAC_Def": [("0x20", "loaded", "0")],
            "TAC_Use": [("0x20", "slot", "0"), ("0x10", "slot", "0"), ("0x10", "loaded", "1")],
            "TAC_Variable_Value": [("slot", "0x0")],
            "TAC_Statement_OriginalStatement": [("0x20", "0x8")],
            "InFunction": [("0x0", "0x0")],
            "IRFunctionEntry": [("0x0",)],
        }
    )
    directory = tmp_path / "relations"
    schema.TACRelations(rows).write_dir(directory)
    return directory


def test_relation_order_and_bytecode_evidence_are_preserved(facts):
    program = load_program(facts)
    assert [stmt.id for stmt in program.blocks[0].instructions] == ["0x20", "0x10"]
    assert program.blocks[0].instructions[0].original_statements == ["0x8"]
    assert program.to_dict()["storage_accesses"][0]["constant_slot"] == "0x0"
    text = render_program(program)
    assert text.index("storage[0x0];") < text.index("storage[0x0] = v_loaded;")
    assert "NOT compilable Solidity" in text


def test_ambiguous_constants_are_not_arbitrarily_chosen(facts):
    with (facts / "TAC_Variable_Value.csv").open("a") as stream:
        stream.write("slot\t0x1\n")
    program = load_program(facts)
    assert "slot" not in program.constants
    assert "storage[v_slot]" in render_program(program)
    assert any("Ambiguous constant" in warning for warning in program.warnings)


@pytest.mark.parametrize(
    "relation,row",
    [
        ("TAC_Use", "0x20\tslot\t-1\n"),
        ("TAC_Use", "0x20\tslot\t3\n"),
        ("TAC_Use", "0x20\tother\t0\n"),
        ("TAC_Op", "0x20\tSUB\n"),
        ("TAC_Block", "0x20\t0x99\n"),
        ("LocalBlockEdge", "0x0\tmissing\n"),
        ("TAC_Def", "malformed\n"),
    ],
)
def test_inconsistent_facts_fail_before_publishing(facts, tmp_path, relation, row):
    with (facts / f"{relation}.csv").open("a") as stream:
        stream.write(row)
    output = tmp_path / "bundle"
    with pytest.raises(ValueError):
        write_bundle(facts, output, {})
    assert not output.exists()


def test_missing_relations_fail_explicitly(facts):
    (facts / "TAC_Use.csv").unlink()
    with pytest.raises(FileNotFoundError, match="TAC_Use"):
        load_program(facts)


def test_uncertain_order_and_unmapped_code_are_visible(facts):
    (facts / "TAC_Statement_Next.csv").write_text("")
    (facts / "UnmappedStatements.csv").write_text("0x99\n")
    program = load_program(facts)
    assert any("Partial statement order" in warning for warning in program.warnings)
    assert program.unmapped_statements == ["0x99"]
    assert 'Unmapped statements: ["0x99"]' in render_program(program)


@pytest.mark.parametrize(
    "opcode,expected",
    [
        ("SUB", "u256(0x2 - 0x3)"),
        ("SHL", "u256(0x3 << 0x2)"),
        ("SHR", "(0x3 >> 0x2)"),
        ("SDIV", "evm.sdiv(0x2, 0x3)"),
        ("DIV", "evm.div(0x2, 0x3)"),
        ("FUTURE_OPCODE", "evm.future_opcode(0x2, 0x3)"),
    ],
)
def test_evm_operand_order_and_special_semantics(opcode, expected):
    program = Program({"a": "0x2", "b": "0x3"}, {}, [], [], [], [])
    stmt = Instruction("0x0", opcode, ["result"], ["a", "b"], [])
    assert render_instruction(stmt, program) == f"v_result = {expected};"


def test_phi_is_not_rewritten_as_a_sequential_assignment():
    program = Program({}, {}, [], [], [], [])
    stmt = Instruction("0x0", "PHI", ["r"], ["a", "b"], [])
    assert "phi_unordered(v_a, v_b)" in render_instruction(stmt, program)


def test_phi_minus_one_index_preserves_all_inputs(facts):
    (facts / "TAC_Op.csv").write_text("0x20\tPHI\n0x10\tSSTORE\n")
    (facts / "TAC_Use.csv").write_text("0x20\tb\t-1\n0x20\ta\t-1\n")
    program = load_program(facts)
    assert program.blocks[0].instructions[0].operands == ["a", "b"]
    assert "phi_unordered(v_a, v_b)" in render_program(program)


def test_cloned_identifiers_do_not_collide():
    assert identifier("0x1_0x2", "v_") != identifier("0x1_5f_0x2", "v_")
    assert identifier("0x1/0x2", "v_").isidentifier()


@pytest.mark.parametrize("text", ["", "0x", "abc", "0xgg", "60__", "60;00"])
def test_invalid_hex_is_rejected(text):
    with pytest.raises(ValueError):
        normalize_bytecode(text)


def test_hex_normalization():
    assert normalize_bytecode(" 0X60 AA\n00 ") == "60aa00"


def test_render_command_needs_no_native_runtime(facts, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    output = tmp_path / "bundle"
    assert main(["render", str(facts), "--output", str(output)]) == 0
    assert (output / "relations/TAC_Op.csv").is_file()
    report = json.loads((output / "analysis.json").read_text())
    assert report["schema_version"] == 2
    assert report["compilable_solidity"] is False
    before = (output / "analysis.json").read_bytes()
    assert main(["render", str(facts), "--output", str(output)]) == 1
    assert (output / "analysis.json").read_bytes() == before


@pytest.mark.parametrize("stem", ["storage-optimized", "storage-via-ir"])
def test_real_gigahorse_snapshot_retains_all_operations(tmp_path, stem):
    snapshot = json.loads((FIXTURES / f"{stem}.relations.json").read_text())
    directory = tmp_path / "relations"
    schema.TACRelations(snapshot).write_dir(directory)
    program = load_program(directory)
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    expected = {"0x" + selector for selector in manifest["method_identifiers"].values()}
    recovered = {selector for function in program.functions for selector in function.selectors}
    assert expected <= recovered
    instructions = [stmt for block in program.blocks for stmt in block.instructions]
    assert {stmt.id for stmt in instructions} == {stmt for stmt, _ in snapshot["TAC_Op"]}
    assert len(instructions) == len(snapshot["TAC_Op"])
    assert {"SLOAD", "SSTORE", "SHA3"} <= {stmt.opcode for stmt in instructions}
    assert any(access["constant_slot"] == "0x0" for access in program.to_dict()["storage_accesses"])
    assert render_program(program) == render_program(load_program(directory))


@pytest.mark.skipif(os.environ.get("GIGAHORSE_INTEGRATION") != "1", reason="opt-in native test")
@pytest.mark.parametrize(
    "stem",
    [
        "storage-optimized",
        "storage-via-ir",
        "layout-optimized",
        "layout-via-ir",
        "control-flow-optimized",
        "control-flow-via-ir",
        "interaction-optimized",
        "interaction-via-ir",
        "copy-optimized",
        "copy-via-ir",
        "expression-optimized",
        "expression-via-ir",
        "alias-optimized",
        "alias-via-ir",
        "failure-optimized",
        "failure-via-ir",
    ],
)
def test_live_bytecode_pipeline(tmp_path, stem):
    output = tmp_path / stem
    assert (
        main(["decompile", str(FIXTURES / f"{stem}.hex"), "--interpreted", "--output", str(output)])
        == 0
    )
    report = json.loads((output / "analysis.json").read_text())
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    assert report["provenance"]["input_sha256"] == manifest["bytecode_sha256"]
    if manifest["storage_layout"]["storage"]:
        assert report["storage_accesses"]
        assert report["semantics"]["storage_fields"]
    assert report["semantics"]["guards"]
    assert (output / "recovered.sol.txt").is_file()
    source_map = json.loads((output / "recovered.map.json").read_text())
    assert source_map["lines"]
    structured_map = json.loads((output / "structured.map.json").read_text())
    assert all(item["status"] == "structured" for item in structured_map["control_flow"])
    if stem.startswith("interaction-"):
        check_native_call_outputs(load_program(output / "relations"), manifest)


def check_native_call_outputs(program, manifest):
    """Fresh facts must keep call-written words dynamic, including bool checks."""
    from reconstruction.projection import ProjectedMachine
    from reconstruction.validation import ExternalOutcome

    selector = bytes.fromhex(manifest["method_identifiers"]["pay(address,address,uint256)"])
    data = selector + b"".join(value.to_bytes(32) for value in (11, 12, 17))
    for returned in (0, 1, 2):
        machine = ProjectedMachine(
            program,
            structured=True,
            external_handler=lambda _, returned=returned: ExternalOutcome(
                returned.to_bytes(32), True
            ),
        )
        result = machine.execute(data, code_sizes={11: 1}, observed_gas_values=[1000000] * 16)
        assert len(result.external_calls) == 1
        if returned == 1:
            assert not result.reverted and result.output == (1).to_bytes(32)
            assert result.storage == {0: 1}
        else:
            assert result.reverted and not result.storage
