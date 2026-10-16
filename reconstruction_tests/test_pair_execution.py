"""ERC20 paths in the archived pair: nested private calls, state and log checks.

Storage is initialized locally. This covers token accounting paths, not pool
reserves, mint/burn/swap, permit signatures or production pair state.
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
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/evaluation"
MASK = (1 << 256) - 1


def mapping_slot(key, base):
    return int.from_bytes(keccak(int(key, 16).to_bytes(32) + base.to_bytes(32)))


def test_pair_token_paths_with_nested_private_calls_match_evm(tmp_path, record_property):
    program, runtime = evaluation_program(tmp_path, "uniswap-v2-pair")
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    user, recipient, spender, overflow = reference.tester.get_accounts()[:4]
    zero = "0x" + "00" * 20
    initial = {0: 1000, mapping_slot(user, 1): 1000, mapping_slot(overflow, 1): MASK - 2}
    prefix = b"".join(
        b"\x7f" + word.to_bytes(32) + b"\x7f" + slot.to_bytes(32) + b"\x55"
        for slot, word in initial.items()
    )
    size, offset = len(runtime).to_bytes(2), (len(prefix) + 15).to_bytes(2)
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
    deployment = reference.tester.send_transaction(
        {"from": user, "gas": 9000000, "data": "0x" + init.hex()}
    )
    reference.address = reference.tester.get_transaction_receipt(deployment)["contract_address"]
    assert reference.backend.get_code(bytes.fromhex(reference.address[2:])) == runtime
    states = [dict(initial), dict(initial)]
    cases = logs = private_calls = 0
    printed = Counter()
    exercised = set()

    def check(selector, types=(), arguments=(), sender=user, value=0, raw=None):
        nonlocal cases, logs, private_calls
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        reference.sender = sender
        expected, reverted = reference.call(data, value)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        traces, touched = [], set(initial)
        for index, structured in enumerate((False, True)):
            machine = ProjectedMachine(program, structured=structured)
            result = machine.execute(
                data,
                storage=states[index],
                caller=int(sender, 16),
                address=int(reference.address, 16),
                value=value,
            )
            assert (result.output, result.reverted) == (expected, reverted), (data.hex(), sender)
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            traces.append(result.blocks)
            touched.update(result.storage)
            states[index] = result.storage
            printed.update(machine.projection_counts())
            exercised.update(machine.private_interfaces_exercised)
            if index == 0:
                private_calls += machine.private_call_checks
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not reverted)
        for slot in touched:
            assert states[0].get(slot, 0) == states[1].get(slot, 0) == reference.storage(slot)
        cases += 1
        logs += len(expected_logs)

    # Getters, successful/failed nested arithmetic, self/zero transfers, finite
    # and unlimited allowances, overflow rollback, malformed ABI and nonpayable.
    check("18160ddd")
    for account in (user, recipient, overflow, zero):
        check("70a08231", ["address"], [account])
    for amount in (0, 1, 17, 2000):
        check("a9059cbb", ["address", "uint256"], [recipient, amount])
    check("a9059cbb", ["address", "uint256"], [user, 33])
    check("a9059cbb", ["address", "uint256"], [overflow, 3])
    check("a9059cbb", ["address", "uint256"], [zero, 2])
    for allowance in (0, 9, MASK):
        check("095ea7b3", ["address", "uint256"], [spender, allowance])
        check("dd62ed3e", ["address", "address"], [user, spender])
        for amount in (0, 4, 8):
            check("23b872dd", ["address", "address", "uint256"], [user, recipient, amount], spender)
    check("23b872dd", ["address", "address", "uint256"], [user, recipient, 2000], spender)
    check("a9059cbb", raw=bytes.fromhex("a9059cbb"))
    check("a9059cbb", raw=bytes.fromhex("a9059cbb") + encode(["uint256", "uint256"], [1 << 200, 1]))
    check("a9059cbb", ["address", "uint256"], [recipient, 1], value=1)
    check("deadbeef")
    text, mapping = render_recovered(program, structure_flow=True)
    assert len(mapping["internal_interfaces"]) == 10
    assert {"0x226e", "0x260b", "0x2abc"} <= exercised
    assert "function fn_0x260b(word input0, word input1, word input2)" in text
    assert private_calls > 20 and logs > 10
    record_property("deployed_pair_token_cases", cases)
    record_property("deployed_pair_private_calls", private_calls)
    record_property("deployed_pair_private_functions", len(exercised))
    record_property("deployed_pair_logs", logs)
    for name, count in printed.items():
        record_property(name, count)
    record_property("fixture", "deployed-uniswap-v2-pair-token-paths")
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / "uniswap-v2-pair.relations.json").read_bytes()
            + (FIXTURES / "uniswap-v2-pair.semantic.json").read_bytes()
        ).hexdigest(),
    )
    record_property("validation_mode", "stateful-token-paths-no-external-calls")
