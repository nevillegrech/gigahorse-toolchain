"""Stateful caller/upgrade/forwarding checks on the locked deployed proxy runtime.

Targets are local microprograms. External results and GAS are replayed from the
EVM; target/world-state equivalence and arbitrary implementation code are outside
this check. The proxy's own slots, logs, reverts and call operands are compared.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.projection import ProjectedMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_calldata_execution import creation_code
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call

ADMIN_SLOT = int("10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b", 16)
IMPLEMENTATION_SLOT = int("7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3", 16)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/evaluation"


def test_deployed_proxy_roles_state_and_control_flow_match_evm(
    tmp_path, monkeypatch, record_property
):
    program, runtime = evaluation_program(tmp_path, "usdc-proxy")
    printed = Counter()
    reference = EVMReference(
        {"creation_bytecode": creation_code(bytes.fromhex("366000600037366000f3"))}
    )
    echo = reference.address
    user, admin, new_admin = reference.tester.get_accounts()[:3]

    def deploy(code):
        transaction = reference.tester.send_transaction(
            {
                "from": user,
                "gas": 9000000,
                "data": "0x" + creation_code(bytes.fromhex(code)),
            }
        )
        return reference.tester.get_transaction_receipt(transaction)["contract_address"]

    constant = deploy("602a60005260206000f3")
    failure = deploy("63deadbeef6000526004601cfd")
    initial_storage = {ADMIN_SLOT: int(admin, 16), IMPLEMENTATION_SLOT: int(echo, 16)}
    prefix = b"".join(
        b"\x7f" + value.to_bytes(32) + b"\x7f" + slot.to_bytes(32) + b"\x55"
        for slot, value in initial_storage.items()
    )
    size = len(runtime).to_bytes(2)
    offset = (len(prefix) + 15).to_bytes(2)
    init = (
        prefix
        + b"\x61"
        + size
        + b"\x61"
        + offset
        + bytes.fromhex("60003961")
        + size
        + bytes.fromhex("6000f3")
        + runtime
    )
    transaction = reference.tester.send_transaction(
        {"from": user, "gas": 9000000, "data": "0x" + init.hex()}
    )
    reference.address = reference.tester.get_transaction_receipt(transaction)["contract_address"]
    assert reference.backend.get_code(bytes.fromhex(reference.address[2:])) == runtime
    stores = [dict(initial_storage), dict(initial_storage)]
    sites = {site.statement: site for site in program.behavior.delegate_sites}
    cases, call_count, gate_count, logs_count = 0, 0, 0, 0

    def calldata(selector, types=(), values=()):
        return bytes.fromhex(selector) + encode(types, values)

    def check(data, sender=user, value=0):
        nonlocal cases, call_count, gate_count, logs_count
        reference.sender = sender
        expected, reverted, observed, gas = trace_call(reference, data, value, monkeypatch)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        sizes = {
            int(address, 16): len(reference.backend.get_code(bytes.fromhex(address[2:])))
            for address in (
                echo,
                constant,
                failure,
                user,
                admin,
                new_admin,
                reference.address,
                "0x" + "00" * 20,
            )
        }
        traces = []
        for index, mode in enumerate((False, True)):
            pending = iter(observed)

            def replay(invocation, pending=pending, index=index):
                nonlocal gate_count
                actual = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == actual[name], (data.hex(), name)
                if invocation.statement in sites:
                    summary = sites[invocation.statement]
                    assert summary.whole_calldata and invocation.calldata == data
                    assert invocation.target == stores[index][int(summary.target_slot, 16)] & (
                        (1 << 160) - 1
                    )
                    for gate in summary.caller_gates:
                        left = int(sender, 16) & int(gate["caller_mask"], 16)
                        right = stores[index][int(gate["slot"], 16)] & int(gate["storage_mask"], 16)
                        assert (left == right) == (gate["comparison"] == "equal")
                        if index == 0:
                            gate_count += 1
                return ExternalOutcome(actual["returndata"], actual["success"])

            machine = ProjectedMachine(program, structured=mode, external_handler=replay)
            result = machine.execute(
                data,
                storage=stores[index],
                caller=int(sender, 16),
                address=int(reference.address, 16),
                value=value,
                observed_gas_values=gas,
                code_sizes=sizes,
            )
            printed.update(machine.projection_counts())
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (expected, reverted), (
                data.hex(),
                sender,
                value,
            )
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            stores[index] = result.storage
            traces.append(result.blocks)
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not reverted)
        for slot in initial_storage:
            assert stores[0].get(slot, 0) == stores[1].get(slot, 0) == reference.storage(slot)
        cases += 1
        call_count += len(observed)
        logs_count += len(expected_logs)

    # Nonmatching callers forward each administrative selector as ordinary data.
    samples = [
        b"",
        b"\x01\x02\x03",
        bytes.fromhex("deadbeef") + b"x" * 47,
        calldata("3659cfe6", ["address"], [constant]),
        calldata("4f1ef286", ["address", "bytes"], [constant, b"init"]),
        calldata("5c60da1b"),
        calldata("8f283970", ["address"], [new_admin]),
        calldata("f851a440"),
    ]
    for data in samples:
        check(data)
    for data in (b"", bytes.fromhex("deadbeef"), calldata("5c60da1b"), calldata("f851a440")):
        check(data, admin)
    check(calldata("3659cfe6", ["address"], [constant]), user, 1)
    check(calldata("5c60da1b"), admin, 1)
    for target in (user, "0x" + "00" * 20):
        check(calldata("3659cfe6", ["address"], [target]), admin)
    check(calldata("3659cfe6", ["address"], [constant]), admin)
    check(bytes.fromhex("deadbeef"))
    check(calldata("3659cfe6", ["address"], [failure]), admin)
    check(b"arbitrary revert data")
    check(calldata("3659cfe6", ["address"], [echo]), admin)
    check(calldata("8f283970", ["address"], ["0x" + "00" * 20]), admin)
    check(calldata("8f283970", ["address"], [new_admin]), admin)
    check(calldata("f851a440"), admin)
    check(calldata("f851a440"), new_admin)
    check(calldata("3659cfe6", ["address"], [constant]), admin)
    check(calldata("5c60da1b"), new_admin)
    check(calldata("4f1ef286", ["address", "bytes"], [constant, b"init"]), new_admin, 2)
    check(calldata("4f1ef286", ["address", "bytes"], [failure, b"fail"]), new_admin)
    check(bytes.fromhex("3659cfe6"))
    check(bytes.fromhex("3659cfe6"), new_admin)
    assert cases == 31 and call_count > 10 and gate_count > 10 and logs_count > 3
    record_property("deployed_proxy_cases", cases)
    for name, count in printed.items():
        record_property(name, count)
    record_property("deployed_proxy_calls", call_count)
    record_property("deployed_proxy_caller_gates", gate_count)
    record_property("deployed_proxy_logs", logs_count)
    record_property("fixture", "deployed-usdc-proxy")
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / "usdc-proxy.relations.json").read_bytes()
            + (FIXTURES / "usdc-proxy.semantic.json").read_bytes()
        ).hexdigest(),
    )
    record_property("validation_mode", "stateful-proxy-with-external-results-replayed")
