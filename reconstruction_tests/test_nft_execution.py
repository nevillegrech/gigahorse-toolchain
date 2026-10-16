"""Bounded NFT guards/admin paths from frozen deployed bytecode.

Synthetic state is used. Successful mint/transfer, receiver callbacks and the
helper with an unresolved PHI remain outside these cases. CODECOPY is observed
in Py-EVM rather than inferred from the recovered execution.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install validation for independent EVM checks")
from eth_abi import decode, encode

from reconstruction.projection import ProjectedMachine
from reconstruction.reverts import analyze_reverts
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import stack_number
from reconstruction_tests.test_weth_execution import deploy_runtime

CORPUS = Path(__file__).resolve().parents[1] / "fixtures/evaluation-next"


def test_nft_copied_reasons_early_guards_and_admin_state_match_evm(
    tmp_path, monkeypatch, record_property
):
    program, runtime = evaluation_program(tmp_path, "erc721-collection", corpus=CORPUS)
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    owner, recipient, operator = reference.tester.get_accounts()[:3]
    zero = "0x" + "00" * 20
    initial = {10: int(owner, 16), 14: 10000}
    deploy_runtime(reference, runtime, initial)
    states = [dict(initial), dict(initial)]
    copies, reasons = [], set()
    printed = Counter()
    cases = failures = known_payloads = copy_checks = 0
    summaries = {r["statement"]: r for r in analyze_reverts(program)}
    instructions = {s.id: s for b in program.blocks for s in b.instructions}
    observations = program.constant_verification["code_copy_observations"]
    computation_type = reference.backend.chain.get_vm().state.computation_class
    original = computation_type.opcodes[0x39]

    class CaptureCopy:
        mnemonic = original.mnemonic

        def __call__(self, computation):
            root = computation.msg.depth == 0
            if root:
                args = [stack_number(x) for x in reversed(computation._stack.values)]
                destination, source, size = args[:3]
                pc = computation.code.program_counter - 1
            original(computation=computation)
            if root:
                copied = bytes(computation._memory._bytes[destination : destination + size])
                copies.append((pc, destination, source, size, copied))

    def check(selector="", types=(), arguments=(), *, sender=owner, value=0, raw=None):
        nonlocal cases, failures, known_payloads, copy_checks
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        reference.sender = sender
        copies.clear()
        with monkeypatch.context() as patch:
            patch.setitem(computation_type.opcodes, 0x39, CaptureCopy())
            output, reverted = reference.call(data, value)
        expected_logs = [(int.from_bytes(a), tuple(t), d) for a, t, d in reference.logs]
        traces, touched = [], set(initial)
        for index, mode in enumerate((False, True)):
            machine = ProjectedMachine(program, structured=mode)
            result = machine.execute(
                data,
                storage=states[index],
                caller=int(sender, 16),
                address=int(reference.address, 16),
                value=value,
            )
            assert (result.output, result.reverted) == (output, reverted), (
                selector,
                sender,
                arguments,
            )
            assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
            if reverted and machine.last_revert_statement:
                summary = summaries[machine.last_revert_statement]
                if summary["status"] == "static":
                    assert summary["payload_hex"] == "0x" + output.hex()
                    known_payloads += index == 0
                    if summary["encoding"] == "Error(string)":
                        reason = decode(["string"], output[4:])[0]
                        assert reason == summary["reason"]
                        reasons.add(reason)
            states[index] = result.storage
            touched.update(result.storage)
            traces.append(result.blocks)
            printed.update(machine.projection_counts())
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not reverted)
        for slot in touched:
            assert states[0].get(slot, 0) == states[1].get(slot, 0) == reference.storage(slot)
        for pc, destination, source, size, copied in copies:
            matching = [
                o
                for o in observations
                if hex(pc) in instructions[o["statement"]].original_statements
                and o["memory_offset"] == hex(destination)
                and o["source_offset"] == hex(source)
                and o["byte_length"] == size
                and o["status"] == "established_bytes"
            ]
            assert matching, (hex(pc), destination, source, size)
            assert all(
                o["copied_bytes_sha256"] == hashlib.sha256(copied).hexdigest() for o in matching
            )
            copy_checks += 1
        cases += 1
        failures += reverted

    check("8da5cb5b")
    check("95d89b41")  # Empty synthetic symbol still exercises its return encoder.
    check("70a08231", ["address"], [zero])
    check("6352211e", ["uint256"], [0])
    check("081812fc", ["uint256"], [0])
    check("095ea7b3", ["address", "uint256"], [operator, 0])
    check("23b872dd", ["address", "address", "uint256"], [owner, recipient, 0])
    check("42842e0e", ["address", "address", "uint256"], [owner, recipient, 0])
    check("c87b56dd", ["uint256"], [0])
    check("2f745c59", ["address", "uint256"], [owner, 0])
    check("4f6ccce7", ["uint256"], [0])
    check("a723533e", ["uint256"], [21])  # Inactive sale.
    check("34918dfd", sender=recipient)  # Unauthorized admin.
    check("34918dfd")
    check("eb8d2444")
    check("a723533e", ["uint256"], [21])  # Copied count-limit reason.
    check("a723533e", ["uint256"], [1])  # Copied payment reason.
    check("a22cb465", ["address", "bool"], [owner, True])
    for approved in (False, True):
        check("a22cb465", ["address", "bool"], [operator, approved])
        check("e985e9c5", ["address", "address"], [owner, operator])
    check("f2fde38b", ["address"], [zero])
    check("f2fde38b", ["address"], [recipient])
    check("8da5cb5b")
    check("34918dfd")  # Former owner is no longer authorized.
    check("34918dfd", sender=recipient)
    check("eb8d2444")
    check("8da5cb5b", value=1)
    check("23b872dd", raw=bytes.fromhex("23b872dd"))
    check("deadbeef")
    assert copy_checks >= 6 and known_payloads >= 10 and failures >= 15
    assert "Can only mint 20 tokens at a time" in reasons
    assert "Ether value sent is not correct" in reasons
    record_property("deployed_nft_cases", cases)
    record_property("deployed_nft_reverted_cases", failures)
    record_property("deployed_nft_codecopy_checks", copy_checks)
    record_property("deployed_nft_known_payload_checks", known_payloads)
    record_property("deployed_nft_decoded_reasons", len(reasons))
    for name, count in printed.items():
        record_property(name, count)
    record_property("fixture", "deployed-erc721-guards-and-admin")
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (CORPUS / "erc721-collection.relations.json").read_bytes()
            + (CORPUS / "erc721-collection.semantic.json").read_bytes()
        ).hexdigest(),
    )
    record_property(
        "validation_mode", "synthetic-nft-state-early-guards-admin-no-receiver-execution"
    )
