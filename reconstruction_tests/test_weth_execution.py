"""Archived WETH runtime with synthetic storage and independent Py-EVM execution.

External results and GAS observations are replayed; caller storage, emitted
expressions, logs, returns, rollback and call operands are checked. This does not
validate arbitrary world-state behavior, gas equivalence or production state.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_hash.auto import keccak

from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call

CORPUS = Path(__file__).resolve().parents[1] / "fixtures/evaluation-next"
MASK = (1 << 256) - 1


def deploy_runtime(reference, runtime, initial):
    prefix = b"".join(
        b"\x7f" + word.to_bytes(32) + b"\x7f" + slot.to_bytes(32) + b"\x55"
        for slot, word in initial.items()
    )
    size, offset = len(runtime).to_bytes(2), (len(prefix) + 15).to_bytes(2)
    init = prefix + b"\x61" + size + b"\x61" + offset + bytes.fromhex("60003961") + size
    init += bytes.fromhex("6000f3") + runtime
    tx = reference.tester.send_transaction(
        {"from": reference.sender, "gas": 9000000, "data": "0x" + init.hex()}
    )
    reference.address = reference.tester.get_transaction_receipt(tx)["contract_address"]
    assert reference.backend.get_code(bytes.fromhex(reference.address[2:])) == runtime


@pytest.mark.parametrize("value", (0, 1, 2, 18, 127, 255))
def test_one_byte_storage_hint_is_not_a_boolean_range(value, tmp_path, record_property):
    program, runtime = evaluation_program(tmp_path, "weth9", corpus=CORPUS)
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    # Upper bytes must not change the byte getter; values >1 must survive it.
    initial = {2: (0xA5 << 248) | value}
    deploy_runtime(reference, runtime, initial)
    data = bytes.fromhex("313ce567")
    expected, reverted = reference.call(data)
    assert not reverted and int.from_bytes(expected) == value
    for mode in (False, True):
        machine = ProjectedMachine(program, structured=mode)
        result = machine.execute(data, storage=initial)
        assert (result.output, result.reverted) == (expected, reverted)
        assert result.storage == initial
    field = next(f for f in program.semantics.storage_fields if f.name == "slot_2_bytes_0_0")
    assert field.native_type_hints == ["bool"]
    assert field.type_candidates == ["bool", "uint8"]
    text, mapping = render_recovered(program, structure_flow=True)
    assert "word slot_2_bytes_0_0;" in text
    assert "bool slot_2_bytes_0_0;" not in text
    assert "do not establish 0/1 storage values" in text
    assert any(line["inference"] == "storage-type-uncertainty" for line in mapping["lines"])
    record_property("deployed_weth_byte_cases", 1)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_weth_state_transfers_allowances_and_withdrawals_match_evm(
    tmp_path, monkeypatch, record_property
):
    program, runtime = evaluation_program(tmp_path, "weth9", corpus=CORPUS)
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    user, recipient, spender = reference.tester.get_accounts()[:3]
    zero = "0x" + "00" * 20
    user_slot = int.from_bytes(keccak(int(user, 16).to_bytes(32) + (3).to_bytes(32)))
    # A synthetic liability also exercises failed ETH transfer and rollback.
    initial = {2: 18, user_slot: 1000}
    deploy_runtime(reference, runtime, initial)
    states = [dict(initial), dict(initial)]
    printed = Counter()
    cases = calls = logs = reverted_cases = 0

    def check(selector="", types=(), arguments=(), *, sender=user, value=0, raw=None):
        nonlocal cases, calls, logs, reverted_cases
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        reference.sender = sender
        output, reverted, observed, gas = trace_call(reference, data, value, monkeypatch)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        traces, touched = [], set(initial)
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
            )
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (output, reverted), (data.hex(), sender)
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            assert len(result.external_calls) == len(observed)
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
        reverted_cases += reverted

    check("2e1a7d4d", ["uint256"], [1])  # ETH transfer fails with empty contract balance.
    check(value=7)
    check(raw=b"\x00", value=3)
    check("deadbeef", value=11)
    for value in (0, 5, 17):
        check("d0e30db0", value=value)
    for account in (user, recipient, zero):
        check("70a08231", ["address"], [account])
    for amount in (0, 5, MASK):
        check("095ea7b3", ["address", "uint256"], [spender, amount])
        check("dd62ed3e", ["address", "address"], [user, spender])
        for transferred in (0, 3, 8, 2000):
            check(
                "23b872dd",
                ["address", "address", "uint256"],
                [user, recipient, transferred],
                sender=spender,
            )
    for account in (user, recipient, zero):
        for amount in (0, 1, 100000):
            check("a9059cbb", ["address", "uint256"], [account, amount])
    for amount in (0, 2, 1000, MASK):
        check("2e1a7d4d", ["uint256"], [amount])
    check("2e1a7d4d", ["uint256"], [0], value=1)
    check("a9059cbb", raw=bytes.fromhex("a9059cbb"))
    check("a9059cbb", ["uint256", "uint256"], [(1 << 200) | int(recipient, 16), 1])
    check("313ce567")
    assert calls >= 3 and logs > 10 and reverted_cases > 10
    record_property("deployed_weth_cases", cases)
    record_property("deployed_weth_external_calls", calls)
    record_property("deployed_weth_logs", logs)
    record_property("deployed_weth_reverted_cases", reverted_cases)
    for name, count in printed.items():
        record_property(name, count)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property("validation_mode", "synthetic-storage-with-external-results-replayed")
