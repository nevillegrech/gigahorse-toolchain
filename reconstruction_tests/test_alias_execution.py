"""Aliased scalar/header/copy writes must not turn native hints into wrong literals."""

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


@pytest.mark.parametrize("variant", ["optimized", "via-ir"])
def test_aliased_memory_and_return_sizes_match_evm(variant, tmp_path, record_property):
    stem = "alias-" + variant
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
    reference = EVMReference(manifest)
    selectors = {s for f in program.functions for s in f.selectors}
    assert {"0x" + s for s in manifest["method_identifiers"].values()} <= selectors
    cases = checks = 0

    def check(signature, arguments, value=0):
        nonlocal cases, checks
        data = bytes.fromhex(manifest["method_identifiers"][signature]) + encode(
            ["uint256"] * len(arguments), arguments
        )
        expected, reverted = reference.call(data, value)
        for mode in (False, True):
            machine = ProjectedMachine(program, structured=mode)
            actual = machine.execute(
                data,
                value=value,
                caller=int(reference.sender, 16),
                address=int(reference.address, 16),
            )
            assert (actual.output, actual.reverted) == (expected, reverted), (
                signature,
                arguments,
                value,
            )
            assert not actual.storage
            checks += machine.expression_checks
        cases += 1

    for destination in (0, 0x40, 0x7F, 0x80, 0x81, 0x9F, 0xA0, 0x200):
        for word in (0, 7, (1 << 256) - 1):
            check("aliasWord(uint256,uint256,uint256)", [0, destination, word])
            check("directReturn(uint256,uint256,uint256)", [0, destination, word])
    for destination, word in [(0x80, n) for n in (0, 1, 31, 32, 33, 64)] + [
        (0x7F, 1),
        (0x81, 0),
        (0xA0, 7),
        (0xA0, (1 << 256) - 1),
        (0x40, 0),
        (0x200, 17),
    ]:
        check("aliasSize(uint256,uint256,uint256)", [0, destination, word])
    for destination in (0x7F, 0x80, 0x81, 0xA0, 0x200):
        for length in (0, 1, 4, 31, 32, 33, 64):
            check("copyAlias(uint256,uint256,uint256,uint256)", [0, destination, 7, length])
    for signature, args in (
        ("aliasWord(uint256,uint256,uint256)", [0, 128, 7]),
        ("aliasSize(uint256,uint256,uint256)", [0, 128, 1]),
        ("copyAlias(uint256,uint256,uint256,uint256)", [0, 128, 7, 32]),
    ):
        check(signature, args, value=1)
    # Hints remain inspectable without authorizing literal substitution.
    assert program.constant_hints and program.to_dict()["constant_hints"] == program.constant_hints
    text, _ = render_recovered(program, structure_flow=True)
    assert "native constant hints" in text
    record_property("evm_contract_cases", cases)
    record_property("printed_expression_checks", checks)
    record_property("fixture", stem)
    record_property("bytecode_sha256", manifest["bytecode_sha256"])
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / f"{stem}.relations.json").read_bytes()
            + (FIXTURES / f"{stem}.semantic.json").read_bytes()
        ).hexdigest(),
    )
