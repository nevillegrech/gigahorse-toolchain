"""Check copied and overwritten calldata against independent EVM observations."""

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.projection import ProjectedMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


@pytest.mark.parametrize("variant", ("optimized", "via-ir"))
def test_copied_calldata_matches_evm(variant, tmp_path, monkeypatch, record_property):
    stem = "copy-" + variant
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    program = fixture_program(stem, tmp_path)
    reference = EVMReference(manifest)
    creation = manifest["auxiliary_contracts"]["CopyTarget"]["creation_bytecode"]
    deployment = reference.tester.send_transaction(
        {"from": reference.sender, "gas": 9000000, "data": "0x" + creation}
    )
    target = reference.tester.get_transaction_receipt(deployment)["contract_address"]
    calls_by_id = {c.statement: c for c in program.semantics.external_calls}
    cases = []
    mask = (1 << 256) - 1
    values = [(0, 0), (1, 2), (mask, 0x123456789ABCDEF), (0x1234 << 192, mask)]
    for method in ("copied", "clipped", "overlap", "reverseOverlap"):
        for x, y in values:
            cases.append((method + "(address,uint256,uint256)", [target, x, y]))
    for method in ("overwrite", "stale"):
        for x, y in values:
            cases.append((method + "(address,uint256,uint256,uint256)", [target, x, y, mask ^ x]))
    for length in (0, 1, 2, 3, 4, 5, 31, 32, 35, 36, 37, 67, 68, 69):
        cases.append(("uncertain(address,uint256)", [target, length]))
    call_count = word_count = 0
    printed = Counter()
    for signature, values in cases:
        data = bytes.fromhex(manifest["method_identifiers"][signature]) + encode(
            ["address"] + ["uint256"] * (len(values) - 1), values
        )
        expected, reverted, observed, gas = trace_call(reference, data, 0, monkeypatch)
        traces = []
        for mode in (False, True):
            pending = iter(observed)

            def replay(invocation, pending=pending, mode=mode, signature=signature):
                nonlocal word_count
                actual = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == actual[name], (stem, signature, name)
                call = calls_by_id[invocation.statement]
                if call.selector_resolved:
                    assert invocation.calldata[:4].hex() == call.selector_candidates[0][2:], (
                        stem,
                        signature,
                    )
                for index, candidates in invocation.inferred_words.items():
                    start = 4 + index * 32
                    encoded = invocation.calldata[start : start + 32]
                    assert len(candidates) == 1 and len(encoded) == 32
                    assert int.from_bytes(encoded) == candidates[0], (stem, signature, index)
                    if not mode:
                        word_count += 1
                return ExternalOutcome(actual["returndata"], actual["success"])

            machine = ProjectedMachine(program, structured=mode, external_handler=replay)
            result = machine.execute(
                data,
                caller=int(reference.sender, 16),
                address=int(reference.address, 16),
                observed_gas_values=gas,
            )
            printed.update(machine.projection_counts())
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (expected, reverted), (
                stem,
                signature,
                values,
            )
            traces.append(result.blocks)
        assert traces[0] == traces[1]
        call_count += len(observed)
    assert len(cases) == 38 and call_count == 37
    record_property("evm_contract_cases", len(cases))
    for name, count in printed.items():
        record_property(name, count)
    record_property("evm_external_calls", call_count)
    record_property("evm_abi_words", word_count)
    record_property("validation_mode", "external-results-replayed")
    record_property("fixture", stem)
    record_property("bytecode_sha256", manifest["bytecode_sha256"])
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / f"{stem}.relations.json").read_bytes()
            + (FIXTURES / f"{stem}.semantic.json").read_bytes()
        ).hexdigest(),
    )
