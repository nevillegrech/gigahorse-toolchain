"""Execute the printed decompiled view and compare it with independent Py-EVM runs.

DecompiledMachine runs exactly the statement trees in decompiled.sol.txt; hidden
memory plumbing is not executed. Matching outputs, reverts, logs, storage and
external calls on these inputs checks the view's expressions *and* abstractions
on those paths. External results are replayed from the EVM. This is bounded
validation with synthetic storage, not an equivalence proof.
"""

import hashlib

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_hash.auto import keccak

from reconstruction.highlevel.interpreter import DecompiledMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.decompiled_support import DEPLOYED_NEXT, deployed_fixture
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call
from reconstruction_tests.test_weth_execution import deploy_runtime

MASK = (1 << 256) - 1


class Harness:
    def __init__(self, decompiled, reference, initial, monkeypatch):
        self.decompiled, self.reference, self.monkeypatch = decompiled, reference, monkeypatch
        self.state = dict(initial)
        self.initial = initial
        self.cases = self.calls = self.logs = self.reverts = 0

    def check(self, data, *, sender, value=0):
        reference = self.reference
        reference.sender = sender
        output, reverted, observed, _gas = trace_call(reference, data, value, self.monkeypatch)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        pending = iter(observed)

        def replay(invocation):
            actual = next(pending)
            for name in ("opcode", "target", "value", "calldata"):
                assert getattr(invocation, name) == actual[name], (data.hex(), name)
            return ExternalOutcome(actual["returndata"], actual["success"])

        machine = DecompiledMachine(self.decompiled, external_handler=replay)
        result = machine.execute(
            data,
            storage=self.state,
            caller=int(sender, 16),
            address=int(reference.address, 16),
            value=value,
        )
        assert next(pending, None) is None, data.hex()
        assert (result.output, result.reverted) == (output, reverted), (data.hex(), sender)
        assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
        assert reference.commit(data, value) == int(not reverted)
        touched = set(self.initial) | set(result.storage)
        for slot in touched:
            assert result.storage.get(slot, 0) == reference.storage(slot), (data.hex(), slot)
        self.state = result.storage
        self.cases += 1
        self.calls += len(observed)
        self.logs += len(expected_logs)
        self.reverts += reverted


def test_weth_decompiled_view_matches_evm(tmp_path, monkeypatch, record_property):
    _, decompiled, runtime = deployed_fixture(DEPLOYED_NEXT, "weth9", tmp_path / "relations")
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    user, recipient, spender = reference.tester.get_accounts()[:3]
    zero = "0x" + "00" * 20
    user_slot = int.from_bytes(keccak(int(user, 16).to_bytes(32) + (3).to_bytes(32)))
    initial = {2: 18, user_slot: 1000}
    deploy_runtime(reference, runtime, initial)
    harness = Harness(decompiled, reference, initial, monkeypatch)

    def check(selector="", types=(), arguments=(), *, sender=user, value=0, raw=None):
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        harness.check(data, sender=sender, value=value)

    check("2e1a7d4d", ["uint256"], [1])  # ETH transfer fails with an empty balance.
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
    # Dirty upper address bits: the old compiler masks at every use.
    check("a9059cbb", ["uint256", "uint256"], [(1 << 200) | int(recipient, 16), 1])
    check("313ce567")
    assert harness.calls >= 3 and harness.logs > 10 and harness.reverts > 10
    record_property("decompiled_weth_cases", harness.cases)
    record_property("decompiled_weth_external_calls", harness.calls)
    record_property("decompiled_weth_logs", harness.logs)
    record_property("decompiled_weth_reverted_cases", harness.reverts)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
