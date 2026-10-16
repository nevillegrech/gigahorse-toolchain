"""Stateful ENS registry checks on the second corpus, using synthetic records.

External results/GAS are replayed from Py-EVM. This covers the registry's own
accounting and authorization paths, not a second legacy registry or world state.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_hash.auto import keccak

from reconstruction.projection import ProjectedMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_calldata_execution import creation_code
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call
from reconstruction_tests.test_weth_execution import deploy_runtime

CORPUS = Path(__file__).resolve().parents[1] / "fixtures/evaluation-next"


def test_registry_owner_operator_records_packed_fields_and_fallback_match_evm(
    tmp_path, monkeypatch, record_property
):
    program, runtime = evaluation_program(tmp_path, "ens-registry", corpus=CORPUS)
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    owner, recipient, operator = reference.tester.get_accounts()[:3]
    # A constant-return legacy stub permits checking all three fallback getters.
    legacy_runtime = b"\x7f" + int(recipient, 16).to_bytes(32) + bytes.fromhex("60005260206000f3")
    tx = reference.tester.send_transaction(
        {"from": owner, "gas": 9000000, "data": "0x" + creation_code(legacy_runtime)}
    )
    legacy = reference.tester.get_transaction_receipt(tx)["contract_address"]
    root, node, missing = (n.to_bytes(32) for n in (0, 7, 8))
    initial = {2: int(legacy, 16)}
    for key in (root, node):
        slot = int.from_bytes(keccak(key + bytes(32)))
        initial[slot] = int(owner, 16)
        initial[(slot + 1) % (1 << 256)] = (0xAABBCCDD << 224) | (23 << 160) | int(recipient, 16)
    deploy_runtime(reference, runtime, initial)
    states = [dict(initial), dict(initial)]
    printed = Counter()
    cases = calls = logs = failures = 0

    def check(selector="", types=(), arguments=(), *, sender=owner, value=0, raw=None):
        nonlocal cases, calls, logs, failures
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        reference.sender = sender
        output, reverted, observed, gas = trace_call(reference, data, value, monkeypatch)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        touched, traces = set(initial), []
        for index, mode in enumerate((False, True)):
            pending = iter(observed)

            def replay(invocation, pending=pending):
                actual = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == actual[name], (data.hex(), name)
                return ExternalOutcome(actual["returndata"], actual["success"])

            machine = ProjectedMachine(program, structured=mode, external_handler=replay)
            result = machine.execute(
                data,
                storage=states[index],
                caller=int(sender, 16),
                address=int(reference.address, 16),
                value=value,
                observed_gas_values=gas,
                code_sizes={int(legacy, 16): len(legacy_runtime)},
            )
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (output, reverted), (data.hex(), sender)
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            touched.update(result.storage)
            states[index] = result.storage
            traces.append(result.blocks)
            printed.update(machine.projection_counts())
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not reverted)
        for slot in touched:
            assert states[0].get(slot, 0) == states[1].get(slot, 0) == reference.storage(slot)
        cases += 1
        calls += len(observed)
        logs += len(expected_logs)
        failures += reverted

    for key in (root, node, missing):
        for selector in ("02571be3", "0178b8bf", "16a25cbd", "f79fe538"):
            check(selector, ["bytes32"], [key])
    for sender in (recipient, owner):
        check("1896f70a", ["bytes32", "address"], [node, operator], sender=sender)
        for ttl in (0, (1 << 64) - 1):
            check("14ab9038", ["bytes32", "uint64"], [node, ttl], sender=sender)
    for approved in (True, False, True):
        check("a22cb465", ["address", "bool"], [operator, approved])
        check("e985e9c5", ["address", "address"], [owner, operator])
        check("14ab9038", ["bytes32", "uint64"], [node, 42], sender=operator)
    label = (99).to_bytes(32)
    child = keccak(root + label)
    check("06ab5923", ["bytes32", "bytes32", "address"], [root, label, recipient], sender=operator)
    check("02571be3", ["bytes32"], [child])
    check(
        "5ef2c7f0",
        ["bytes32", "bytes32", "address", "address", "uint64"],
        [root, label, recipient, operator, 255],
    )
    check("16a25cbd", ["bytes32"], [child])
    check(
        "cf408823",
        ["bytes32", "address", "address", "uint64"],
        [node, recipient, owner, 17],
        sender=operator,
    )
    check("14ab9038", ["bytes32", "uint64"], [node, 18])  # Former owner loses authorization.
    check("14ab9038", ["bytes32", "uint64"], [node, 18], sender=recipient)
    check("5b0fc9c3", ["bytes32", "address"], [node, "0x" + "00" * 20], sender=recipient)
    check("02571be3", ["bytes32"], [node])  # The registry's self-address sentinel returns zero.
    check("f79fe538", ["bytes32"], [node])
    check("0178b8bf", ["bytes32"], [node])
    check("16a25cbd", ["bytes32"], [node])
    check("14ab9038", ["bytes32", "uint256"], [root, (1 << 200) | 123])
    check("a22cb465", ["address", "uint256"], [operator, 2])
    check("02571be3", raw=bytes.fromhex("02571be3"))
    check("02571be3", ["bytes32"], [root], value=1)
    check("deadbeef")
    check()
    assert calls >= 3 and logs > 10 and failures >= 8
    record_property("deployed_registry_cases", cases)
    record_property("deployed_registry_external_calls", calls)
    record_property("deployed_registry_logs", logs)
    record_property("deployed_registry_reverted_cases", failures)
    for name, count in printed.items():
        record_property(name, count)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property("validation_mode", "synthetic-records-with-legacy-results-replayed")
