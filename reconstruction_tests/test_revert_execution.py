"""Decoded/partial failure payloads compared with original compiler bytecode."""

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import decode, encode
from eth_hash.auto import keccak

from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.reverts import analyze_reverts
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


@pytest.mark.parametrize("variant", ["optimized", "via-ir"])
def test_failure_payloads_and_annotations_match_evm(variant, tmp_path, record_property):
    stem = "failure-" + variant
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    assert (
        hashlib.sha256((FIXTURES / manifest["source"]).read_bytes()).hexdigest()
        == manifest["source_sha256"]
    )
    runtime = bytes.fromhex((FIXTURES / f"{stem}.hex").read_text())
    assert hashlib.sha256(runtime).hexdigest() == manifest["bytecode_sha256"]
    program = fixture_program(stem, tmp_path)
    info_by_id = {r["statement"]: r for r in analyze_reverts(program)}
    reference = EVMReference(manifest)
    counts, printed = Counter(), Counter()
    custom_selector = "0x" + keccak(b"Denied(uint256,address)")[:4].hex()

    def check(signature, types=(), values=(), value=0, raw=None):
        data = (
            raw
            if raw is not None
            else bytes.fromhex(manifest["method_identifiers"][signature]) + encode(types, values)
        )
        expected, reverted = reference.call(data, value)
        observed = None
        for structured in (False, True):
            machine = ProjectedMachine(program, structured=structured)
            result = machine.execute(
                data,
                value=value,
                caller=int(reference.sender, 16),
                address=int(reference.address, 16),
            )
            assert (result.output, result.reverted) == (expected, reverted), (signature, data.hex())
            assert not result.storage
            printed.update(machine.projection_counts())
            if machine.last_revert_statement:
                observed = info_by_id[machine.last_revert_statement]
                if observed["status"] == "static":
                    assert bytes.fromhex(observed["payload_hex"][2:]) == expected
                    if observed["encoding"] == "Error(string)":
                        assert observed["reason"] == decode(["string"], expected[4:])[0]
                    if observed["encoding"] == "Panic(uint256)":
                        assert (
                            int(observed["panic_code"], 16) == decode(["uint256"], expected[4:])[0]
                        )
                if observed["selector"]:
                    assert observed["selector"] == "0x" + expected[:4].hex()
        if observed:
            counts[observed["encoding"] or "unresolved"] += 1
        if signature in {"dynamicCustom(uint256)", "clobbered(uint256)"}:
            assert observed["status"] == "partial" and observed["reason"] is None
            assert observed["selector"] == (
                custom_selector if signature.startswith("dynamic") else "0x08c379a0"
            )
        if signature == "fixedCustom()":
            assert observed["raw_words"] == ["0x7", "0x1234"]
        if signature == "raw(bytes)" and raw is None:
            assert observed["status"] == "unresolved" and observed["selector"] is None
        counts["cases"] += 1

    mask = (1 << 256) - 1
    for x in (0, 7, 9, mask):
        check("reason(uint256)", ["uint256"], [x])
    for x in (False, True):
        check("longReason(bool)", ["bool"], [x])
    for x in (0, 7, mask):
        check("panicAdd(uint256)", ["uint256"], [x])
    for x in (0, 1, 3, mask):
        check("panicDivide(uint256)", ["uint256"], [x])
    for x in (False, True):
        check("panicAssert(bool)", ["bool"], [x])
    check("fixedCustom()")
    for x in (0, 7, mask):
        check("dynamicCustom(uint256)", ["uint256"], [x])
    for x in (0, int.from_bytes(b"abc".ljust(32, b"\0")), mask):
        check("clobbered(uint256)", ["uint256"], [x])
    error = bytes.fromhex("08c379a0") + encode(["string"], ["forged caller data"])
    panic = bytes.fromhex("4e487b71") + encode(["uint256"], [17])
    custom = bytes.fromhex(custom_selector[2:]) + encode(
        ["uint256", "address"], [7, "0x" + "12" * 20]
    )
    for payload in (b"", b"\xff", b"dead", error, panic, custom, bytes(range(64))):
        check("raw(bytes)", ["bytes"], [payload])
    check("reason(uint256)", ["uint256"], [7], value=1)
    check("panicAdd(uint256)", ["uint256"], [0], value=1)
    check("truncated", raw=bytes.fromhex(manifest["method_identifiers"]["reason(uint256)"]))
    check(
        "invalid-bool",
        raw=bytes.fromhex(manifest["method_identifiers"]["longReason(bool)"])
        + encode(["uint256"], [2]),
    )
    check(
        "invalid-offset",
        raw=bytes.fromhex(manifest["method_identifiers"]["raw(bytes)"])
        + encode(["uint256"], [1 << 200]),
    )
    check("unknown", raw=bytes.fromhex("deadbeef"))
    assert counts["cases"] == 35 and counts["Error(string)"] >= 4 and counts["Panic(uint256)"] >= 3
    text, mapping = render_recovered(program, structure_flow=True)
    assert 'Failure payload: Error("permission denied")' in text
    assert "evm.revert_panic(0x11);" in text
    assert 'Error("old")' not in text and "Denied(" not in text
    annotations = [
        line
        for line in mapping["lines"]
        if line["inference"] in {"revert-payload", "folded-revert"}
    ]
    assert annotations and all(
        line["proof_references"] == ["constant_verification"] for line in annotations
    )
    detailed, _ = render_recovered(program)
    assert "Revert payload: Panic(0x11)" in detailed and "evm.revert_panic(" not in detailed
    assert mapping["revert_folds"] and printed["printed_folded_revert_checks"] >= 8
    record_property("evm_contract_cases", counts["cases"])
    record_property("decoded_error_cases", counts["Error(string)"])
    record_property("decoded_panic_cases", counts["Panic(uint256)"])
    for name, count in printed.items():
        record_property(name, count)
    record_property("fixture", stem)
    record_property("bytecode_sha256", manifest["bytecode_sha256"])
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / f"{stem}.relations.json").read_bytes()
            + (FIXTURES / f"{stem}.semantic.json").read_bytes()
        ).hexdigest(),
    )
