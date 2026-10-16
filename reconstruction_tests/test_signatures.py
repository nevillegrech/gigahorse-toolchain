import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

pytest.importorskip("eth_hash", reason="install the naming extra for signature hints")
from eth_hash.auto import keccak

from reconstruct import main
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.recovered import function_name, render_recovered
from reconstruction.signatures import apply_signature_file
from reconstruction_tests.test_controlflow import fixture_program

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


def test_names_are_hints_and_do_not_replace_inferred_arguments(tmp_path):
    program = fixture_program("storage-via-ir", tmp_path / "relations")
    manifest = json.loads((FIXTURES / "storage-via-ir.json").read_text())
    path = tmp_path / "names.tsv"
    path.write_text(
        "".join(
            "0x" + selector + "\t" + signature + "\n"
            for signature, selector in manifest["method_identifiers"].items()
        )
    )
    before = deepcopy(program.semantics.arguments), deepcopy(program.blocks)
    apply_signature_file(program, path)
    assert (program.semantics.arguments, program.blocks) == before
    assert program.signature_info.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    text, source_map = render_recovered(program, structure_flow=True)
    assert "function hint_" in text and "tailcall hint_" in text
    assert "external hints, collisions possible" in text
    assert source_map["signature_info"]["selector_hash"] == "keccak-256-first-four-bytes"
    assert (
        main(
            [
                "render",
                str(tmp_path / "relations"),
                "--signatures",
                str(path),
                "--output",
                str(tmp_path / "bundle"),
            ]
        )
        == 0
    )
    assert json.loads((tmp_path / "bundle/analysis.json").read_text())["signature_info"][
        "candidates"
    ]


def test_hash_mismatches_and_special_dispatch_selectors_are_not_names(tmp_path):
    program = Program(
        {},
        {},
        [
            Function("f", ["e"], ["0xa9059cbb"], None, [], ["e"]),
            Function("fallback", ["z"], ["0x00000000"], None, [], ["z"]),
        ],
        [Block("e", [], [], []), Block("z", [], [], [])],
        [],
        [],
    )
    path = tmp_path / "names.tsv"
    path.write_text(
        "0xa9059cbb\tapprove(address,uint256)\n0x00000000\tfallback()\n0xA9059CBB\ttransfer(address,uint256)\n"
    )
    apply_signature_file(program, path)
    assert program.signature_info.candidates == {"0xa9059cbb": ["transfer(address,uint256)"]}
    assert program.signature_info.rejected_matching_rows == 1
    assert function_name(program.functions[0], program.signature_info) == "hint_transfer_a9059cbb"
    assert function_name(program.functions[1], program.signature_info) == "selector_00000000"


def test_real_selector_collision_retains_candidates_and_generic_name(tmp_path):
    signatures = ["burn(uint256)", "collate_propagate_storage(bytes16)"]
    selectors = {"0x" + keccak(s.encode())[:4].hex() for s in signatures}
    assert selectors == {"0x42966c68"}
    program = Program(
        {},
        {},
        [Function("f", ["e"], ["0x42966c68"], None, [], ["e"])],
        [Block("e", [], [], [])],
        [],
        [],
    )
    path = tmp_path / "names.tsv"
    path.write_text("".join("0x42966c68\t" + s + "\n" for s in signatures))
    apply_signature_file(program, path)
    assert program.signature_info.candidates["0x42966c68"] == sorted(signatures)
    assert function_name(program.functions[0], program.signature_info) == "selector_42966c68"


def test_external_names_do_not_change_call_kind_or_word_recovery(tmp_path):
    program = fixture_program("interaction-via-ir", tmp_path / "relations")
    calls = program.semantics.external_calls
    before = [(c.opcode, c.target, deepcopy(c.arguments)) for c in calls]
    path = tmp_path / "names.tsv"
    path.write_text("0xa9059cbb\ttransfer(address,uint256)\n0x70a08231\tbalanceOf(address)\n")
    apply_signature_file(program, path)
    assert [(c.opcode, c.target, c.arguments) for c in calls] == before
    assert any(c.signature_hints == ["transfer(address,uint256)"] for c in calls)


def test_metadata_cannot_inject_source_through_a_signature(tmp_path):
    program = Program(
        {},
        {},
        [Function("f", ["e"], ["0xa9059cbb"], None, [], ["e"])],
        [Block("e", [Instruction("stop", "STOP", [], [], [])], [], [])],
        [],
        [],
    )
    path = tmp_path / "names.tsv"
    path.write_text("0xa9059cbb\ttransfer(address,uint256);evil()\n")
    apply_signature_file(program, path)
    assert (
        not program.signature_info.candidates and program.signature_info.rejected_matching_rows == 1
    )
