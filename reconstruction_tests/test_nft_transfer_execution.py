"""Successful NFT state changes and bounded receiver calls from locked bytecode.

Receiver bytecode executes in Py-EVM. Outcomes, GAS and balance observations are
replayed into the recovered caller; this is not recovered world-state execution.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install validation for independent EVM checks")
from eth_abi import encode

from reconstruction.projection import ProjectedMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_calldata_execution import creation_code
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import stack_number, trace_call
from reconstruction_tests.test_weth_execution import deploy_runtime

CORPUS = Path(__file__).resolve().parents[1] / "fixtures/evaluation-next"


def payload_runtime(data, *, reverted=False):
    size = len(data).to_bytes(2)
    return (
        b"\x61"
        + size
        + b"\x61\x00\x0f\x60\x00\x39\x61"
        + size
        + b"\x60\x00"
        + (b"\xfd" if reverted else b"\xf3")
        + data
    )


def test_nft_mints_transfers_and_receivers_match_evm(tmp_path, monkeypatch, record_property):
    program, runtime = evaluation_program(tmp_path, "erc721-collection", corpus=CORPUS)
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    owner, recipient, operator, outsider = reference.tester.get_accounts()[:4]
    initial = {10: int(owner, 16), 12: 1, 14: 10000, 15: 1}
    deploy_runtime(reference, runtime, initial)
    magic = bytes.fromhex("150b7a02")
    error = bytes.fromhex("08c379a0") + encode(["string"], ["receiver rejected"])
    receivers = {}
    for label, returned, failed in (
        ("accept", magic + bytes(28), False),
        ("dirty", magic + bytes([255]) * 28, False),
        ("long", magic + bytes(60), False),
        ("wrong", bytes(32), False),
        ("short", magic, False),
        ("empty", b"", False),
        ("raw_revert", bytes.fromhex("deadbeef"), True),
        ("error_revert", error, True),
    ):
        code = payload_runtime(returned, reverted=failed)
        tx = reference.tester.send_transaction(
            {"from": owner, "gas": 9000000, "data": "0x" + creation_code(code)}
        )
        address = reference.tester.get_transaction_receipt(tx)["contract_address"]
        assert reference.backend.get_code(bytes.fromhex(address[2:])) == code
        receivers[label] = address
    addresses = [owner, recipient, operator, outsider, reference.address, *receivers.values()]
    code_sizes = {
        int(a, 16): len(reference.backend.get_code(bytes.fromhex(a[2:]))) for a in addresses
    }
    states = [dict(initial), dict(initial)]
    printed = Counter()
    cases = failures = callbacks = counter_checks = logs = balance_checks = 0
    computation_type = reference.backend.chain.get_vm().state.computation_class
    captured_counters, observed_balances, environment, block_hashes = [], [], {}, {}

    class Capture:
        def __init__(self, opcode, original):
            self.opcode, self.original, self.mnemonic = opcode, original, original.mnemonic

        def __call__(self, computation):
            root = computation.msg.depth == 0
            pc = computation.code.program_counter - 1
            if root and self.opcode == 0x5B and pc == 0x356B:
                captured_counters.append(stack_number(computation._stack.values[-1]))
            argument = (
                stack_number(computation._stack.values[-1])
                if root and self.opcode in (0x31, 0x40)
                else None
            )
            self.original(computation=computation)
            if not root:
                return
            if self.opcode in (0x31, 0x47):
                target = (
                    int.from_bytes(computation.msg.storage_address)
                    if self.opcode == 0x47
                    else argument & ((1 << 160) - 1)
                )
                observed_balances.append(
                    (self.mnemonic, target, stack_number(computation._stack.values[-1]))
                )
            elif self.opcode in (0x42, 0x43):
                value = stack_number(computation._stack.values[-1])
                assert self.mnemonic not in environment or environment[self.mnemonic] == value
                environment[self.mnemonic] = value
            elif self.opcode == 0x40:
                block_hashes[argument] = stack_number(computation._stack.values[-1])

    class ObserveCounter(ProjectedMachine):
        def _block(self, block_id, plan):
            if block_id == "0x356bB0x3502":
                self.counter_values.append(self._value("0x356b_0x0V0x3502"))
            super()._block(block_id, plan)

    def check(selector, types=(), arguments=(), *, sender=owner, value=0, reverted=False):
        nonlocal cases, failures, callbacks, counter_checks, logs, balance_checks
        data = bytes.fromhex(selector) + encode(types, arguments)
        reference.sender = sender
        captured_counters.clear()
        observed_balances.clear()
        environment.clear()
        block_hashes.clear()
        with monkeypatch.context() as patch:
            for opcode in (0x31, 0x40, 0x42, 0x43, 0x47, 0x5B):
                patch.setitem(
                    computation_type.opcodes,
                    opcode,
                    Capture(opcode, computation_type.opcodes[opcode]),
                )
            output, failed, observed, gas = trace_call(reference, data, value, monkeypatch)
        assert failed == reverted, (selector, arguments, output.hex())
        expected_logs = [(int.from_bytes(a), tuple(t), d) for a, t, d in reference.logs]
        traces, touched = [], set(initial)
        for index, mode in enumerate((False, True)):
            pending = iter(observed)

            def replay(invocation, pending=pending):
                actual = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == actual[name], (selector, arguments, name)
                # The callback encoder, including data length/padding, must match EVM memory.
                assert actual["calldata"][:4] == magic
                return ExternalOutcome(actual["returndata"], actual["success"])

            machine = ObserveCounter(program, structured=mode, external_handler=replay)
            machine.counter_values = []
            result = machine.execute(
                data,
                storage=states[index],
                caller=int(sender, 16),
                address=int(reference.address, 16),
                value=value,
                code_sizes=code_sizes,
                observed_gas_values=gas,
                observed_balance_values=observed_balances,
                block_environment=environment,
                block_hashes=block_hashes,
            )
            assert (result.output, result.reverted) == (output, failed), (selector, arguments)
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            assert machine.counter_values == captured_counters
            assert next(pending, None) is None
            assert next(machine.observed_balances, None) is None
            assert next(machine.observed_gas, None) is None
            states[index] = result.storage
            touched.update(result.storage)
            traces.append(result.blocks)
            printed.update(machine.projection_counts())
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not failed)
        for slot in touched:
            assert states[0].get(slot, 0) == states[1].get(slot, 0) == reference.storage(slot)
        cases += 1
        failures += failed
        callbacks += len(observed)
        counter_checks += len(captured_counters)
        logs += len(expected_logs)
        balance_checks += len(observed_balances)
        return output

    price = 0x11C37937E080000
    check("a723533e", ["uint256"], [12], value=12 * price)
    assert int.from_bytes(check("18160ddd")) == 12
    assert int.from_bytes(check("70a08231", ["address"], [owner])) == 12
    for token in (0, 11):
        assert int.from_bytes(check("6352211e", ["uint256"], [token])) == int(owner, 16)
        assert int.from_bytes(check("4f6ccce7", ["uint256"], [token])) == token
        assert int.from_bytes(check("2f745c59", ["address", "uint256"], [owner, token])) == token
    check("095ea7b3", ["address", "uint256"], [operator, 0])
    assert int.from_bytes(check("081812fc", ["uint256"], [0])) == int(operator, 16)
    check("42842e0e", ["address", "address", "uint256"], [owner, recipient, 0], sender=operator)
    assert int.from_bytes(check("6352211e", ["uint256"], [0])) == int(recipient, 16)
    assert int.from_bytes(check("081812fc", ["uint256"], [0])) == 0
    check("23b872dd", ["address", "address", "uint256"], [recipient, owner, 0], sender=recipient)
    check("a22cb465", ["address", "bool"], [operator, True])
    for token, size in enumerate((0, 1, 31, 32, 33, 65), 1):
        data = bytes((n * 17 + 3) % 256 for n in range(size))
        check(
            "b88d4fde",
            ["address", "address", "uint256", "bytes"],
            [owner, receivers["accept"], token, data],
            sender=operator,
        )
        assert int.from_bytes(check("6352211e", ["uint256"], [token])) == int(
            receivers["accept"], 16
        )
    for token, label in ((7, "dirty"), (8, "long")):
        check(
            "b88d4fde",
            ["address", "address", "uint256", "bytes"],
            [owner, receivers[label], token, b"extra"],
            sender=operator,
        )
        assert int.from_bytes(check("6352211e", ["uint256"], [token])) == int(receivers[label], 16)
    for label in ("wrong", "short", "empty", "raw_revert", "error_revert"):
        result = check(
            "b88d4fde",
            ["address", "address", "uint256", "bytes"],
            [owner, receivers[label], 9, b"rejected payload"],
            sender=operator,
            reverted=True,
        )
        if label == "raw_revert":
            assert result == bytes.fromhex("deadbeef")
        if label == "error_revert":
            assert result == error
        assert int.from_bytes(check("6352211e", ["uint256"], [9])) == int(owner, 16)
    check("42842e0e", ["address", "address", "uint256"], [owner, recipient, 9])
    check(
        "42842e0e", ["address", "address", "uint256"], [owner, "0x" + "00" * 20, 10], reverted=True
    )
    check("23b872dd", ["address", "address", "uint256"], [recipient, owner, 10], reverted=True)
    check(
        "42842e0e",
        ["address", "address", "uint256"],
        [owner, recipient, 10],
        sender=outsider,
        reverted=True,
    )
    assert int.from_bytes(check("18160ddd")) == 12
    assert cases >= 45 and failures >= 8 and callbacks == 13 and counter_checks >= 20
    record_property("deployed_nft_transfer_cases", cases)
    record_property("deployed_nft_transfer_reverts", failures)
    record_property("deployed_nft_receiver_calls", callbacks)
    record_property("deployed_nft_entry_counter_checks", counter_checks)
    record_property("deployed_nft_balance_checks", balance_checks)
    record_property("deployed_nft_transfer_logs", logs)
    for name, count in printed.items():
        record_property(name, count)
    record_property("fixture", "deployed-erc721-mint-transfer-receivers")
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (CORPUS / "erc721-collection.relations.json").read_bytes()
            + (CORPUS / "erc721-collection.semantic.json").read_bytes()
        ).hexdigest(),
    )
    record_property(
        "validation_mode",
        "synthetic-nft-state-receiver-outcomes-gas-balances-replayed-no-reentrancy",
    )
