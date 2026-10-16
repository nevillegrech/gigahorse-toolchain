"""Compare recovered external interactions with independently observed EVM calls.

The EVM supplies external outcomes and GAS observations. This checks the caller's
IR, call arguments, ABI word annotations and returndata handling, not a separate
implementation of the called contracts, gas accounting or world-state execution.
"""

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_tester import PyEVMBackend

from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import Expressions, render_recovered
from reconstruction.semantics import SemanticInfo
from reconstruction.validation import ExternalOutcome, RecoveredMachine
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"
CALLS = {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFA: "STATICCALL"}


def stack_number(value):
    return value if isinstance(value, int) else int.from_bytes(value)


def trace_call(reference, data, value, monkeypatch):
    computation_type = reference.backend.chain.get_vm().state.computation_class
    calls, gas = [], []

    class Capture:
        def __init__(self, opcode, original):
            self.opcode, self.original, self.mnemonic = opcode, original, original.mnemonic

        def __call__(self, computation):
            root = computation.msg.depth == 0
            invocation = None
            if root and self.opcode in CALLS:
                args = [stack_number(x) for x in reversed(computation._stack.values)]
                has_value = self.opcode in {0xF1, 0xF2}
                start = 3 if has_value else 2
                memory = bytes(computation._memory._bytes)
                invocation = {
                    "opcode": CALLS[self.opcode],
                    "target": args[1] & ((1 << 160) - 1),
                    "value": args[2] if has_value else value if self.opcode == 0xF4 else 0,
                    "requested_gas": args[0],
                    "calldata": memory[args[start] : args[start] + args[start + 1]].ljust(
                        args[start + 1], b"\0"
                    ),
                }
            self.original(computation=computation)
            if root and self.opcode == 0x5A:
                gas.append(stack_number(computation._stack.values[-1]))
            if invocation is not None:
                invocation["success"] = bool(stack_number(computation._stack.values[-1]))
                invocation["returndata"] = bytes(computation.return_data)
                calls.append(invocation)

    opcodes = dict(computation_type.opcodes)
    for opcode in (*CALLS, 0x5A):
        opcodes[opcode] = Capture(opcode, opcodes[opcode])
    with monkeypatch.context() as patch:
        patch.setattr(computation_type, "opcodes", opcodes)
        output, reverted = reference.call(data, value)
    return output, reverted, calls, gas


@pytest.mark.parametrize("variant", ("optimized", "via-ir"))
def test_external_calls_match_evm_observations(variant, tmp_path, monkeypatch, record_property):
    stem = "interaction-" + variant
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    program = fixture_program(stem, tmp_path)
    reference = EVMReference(manifest)
    creation = manifest["auxiliary_contracts"]["InteractionTarget"]["creation_bytecode"]
    deployment = reference.tester.send_transaction(
        {"from": reference.sender, "gas": 9000000, "data": "0x" + creation}
    )
    target = reference.tester.get_transaction_receipt(deployment)["contract_address"]
    eoa = reference.tester.get_accounts()[1]
    recipient = reference.tester.get_accounts()[2]
    zero = "0x" + "00" * 20
    code_sizes = {
        int(address, 16): len(reference.backend.get_code(bytes.fromhex(address[2:])))
        for address in (target, eoa, recipient, zero)
    }
    external_by_id = {call.statement: call for call in program.semantics.external_calls}
    storage = [{}, {}]
    case_count, call_count, word_count = 0, 0, 0
    printed_checks = paths = unchecked = 0

    def check(data, value=0):
        nonlocal case_count, call_count, word_count
        nonlocal printed_checks, paths, unchecked
        expected, reverted, observed, gas = trace_call(reference, data, value, monkeypatch)
        traces = []
        for index, mode in enumerate((False, True)):
            pending = iter(observed)

            def replay(invocation, pending=pending, index=index):
                nonlocal word_count
                actual = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == actual[name], (stem, data.hex(), name)
                inferred = external_by_id[invocation.statement]
                if inferred.selector_resolved:
                    assert invocation.calldata[:4].hex() == inferred.selector_candidates[0][2:]
                for word_index, candidates in invocation.inferred_words.items():
                    if len(candidates) == 1:
                        start = 4 + word_index * 32
                        encoded = invocation.calldata[start : start + 32]
                        assert len(encoded) == 32 and int.from_bytes(encoded) == candidates[0]
                        if index == 0:
                            word_count += 1
                return ExternalOutcome(actual["returndata"], actual["success"])

            machine = ProjectedMachine(program, structured=mode, external_handler=replay)
            result = machine.execute(
                data,
                storage=storage[index],
                caller=int(reference.sender, 16),
                address=int(reference.address, 16),
                value=value,
                observed_gas_values=gas,
                code_sizes=code_sizes,
            )
            printed_checks += machine.expression_checks
            paths += machine.storage_path_checks
            unchecked += machine.storage_paths_unchecked
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (expected, reverted), (stem, data.hex())
            assert len(result.external_calls) == len(observed)
            storage[index] = result.storage
            traces.append(result.blocks)
        assert traces[0] == traces[1]
        assert reference.commit(data, value) == int(not reverted)
        assert storage[0].get(0, 0) == storage[1].get(0, 0) == reference.storage(0)
        case_count += 1
        call_count += len(observed)

    def calldata(signature, types, args):
        return bytes.fromhex(manifest["method_identifiers"][signature]) + encode(types, args)

    transfer = bytes.fromhex("a9059cbb")
    balance = bytes.fromhex("70a08231")
    for method in ("pay", "rawTransfer"):
        for to, amount in (
            (recipient, 0),
            (recipient, 1),
            (recipient, 13),
            (zero, 7),
            (recipient, (1 << 256) - 1),
        ):
            check(
                calldata(
                    method + "(address,address,uint256)",
                    ["address", "address", "uint256"],
                    [target, to, amount],
                )
            )
    for token in (target, eoa):
        for owner in (recipient, zero):
            check(calldata("read(address,address)", ["address", "address"], [token, owner]))
    for to in (eoa, target):
        for amount, value in ((0, 0), (1, 0), (7, 10), (100, 1)):
            check(calldata("send(address,uint256)", ["address", "uint256"], [to, amount]), value)
    payloads = [
        b"",
        bytes.fromhex("deadbeef"),
        transfer + encode(["address", "uint256"], [recipient, 1]),
        transfer + encode(["address", "uint256"], [recipient, 13]),
        transfer + encode(["address", "uint256"], [zero, 1]),
        balance + encode(["address"], [recipient]),
        b"\x80" * 97,
    ]
    for method in ("forward", "delegate"):
        for payload in payloads:
            check(calldata(method + "(address,bytes)", ["address", "bytes"], [target, payload]))
        check(calldata(method + "(address,bytes)", ["address", "bytes"], [eoa, b"\x01\x02\x03"]))
    check(calldata("forward(address,bytes)", ["address", "bytes"], [target, payloads[2]]), 1)
    check(b"")
    check(bytes.fromhex("deadbeef"))
    check(bytes.fromhex(manifest["method_identifiers"]["forward(address,bytes)"]))
    assert call_count == 39 and word_count == 24
    record_property("evm_contract_cases", case_count)
    record_property("printed_expression_checks", printed_checks)
    record_property("printed_storage_path_checks", paths)
    record_property("printed_storage_paths_unchecked", unchecked)
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


@pytest.mark.parametrize("child_reverts", (False, True))
@pytest.mark.parametrize("invalid_copy", (False, True))
def test_partial_call_output_and_returndata_bounds_match_evm(child_reverts, invalid_copy):
    backend = PyEVMBackend()
    vm = backend.chain.get_vm()
    target = bytes.fromhex("12" * 20)
    # The child returns/reverts with three bytes. CALL copies those bytes and
    # leaves the rest of the pre-existing 32-byte output buffer intact.
    child_code = bytes.fromhex("62aabbcc5f526003601d") + (b"\xfd" if child_reverts else b"\xf3")
    vm.state.set_code(target, child_code)
    code = b"\x7f" + b"\xff" * 32 + bytes.fromhex("5f52")
    code += bytes.fromhex("60205f5f5f5f73") + target + bytes.fromhex("6207a120f1602052")
    code += bytes.fromhex("3d604052")
    if invalid_copy:
        code += bytes.fromhex("5f60045f3e")  # even a zero-length copy checks its source offset
    code += bytes.fromhex("60605ff3")
    sender = backend.account_keys[0].public_key.to_canonical_address()
    actual = vm.execute_bytecode(
        origin=sender,
        gas_price=0,
        gas=1000000,
        to=b"\x34" * 20,
        sender=sender,
        value=0,
        data=b"",
        code=code,
    )
    constants = {
        "zero": "0x0",
        "three": "0x3",
        "four": "0x4",
        "word": "0x20",
        "two_words": "0x40",
        "size": "0x60",
        "sentinel": "0x" + "ff" * 32,
        "target": "0x" + target.hex(),
        "gas": "0x7a120",
    }
    instructions = [
        Instruction("store", "MSTORE", [], ["zero", "sentinel"], []),
        Instruction(
            "call", "CALL", ["ok"], ["gas", "target", "zero", "zero", "zero", "zero", "word"], []
        ),
        Instruction("flag", "MSTORE", [], ["word", "ok"], []),
        Instruction("size", "RETURNDATASIZE", ["retlen"], [], []),
        Instruction("length", "MSTORE", [], ["two_words", "retlen"], []),
    ]
    if invalid_copy:
        instructions.append(Instruction("copy", "RETURNDATACOPY", [], ["zero", "four", "zero"], []))
    instructions.append(Instruction("return", "RETURN", [], ["zero", "size"], []))
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
    )
    for mode in (False, True):
        result = RecoveredMachine(
            program,
            structured=mode,
            external_handler=lambda _: ExternalOutcome(bytes.fromhex("aabbcc"), not child_reverts),
        ).execute(b"")
        assert (result.output, result.reverted) == (actual.output, actual.is_error)
        if not invalid_copy:
            assert result.output[:32] == bytes.fromhex("aabbcc") + b"\xff" * 29
            assert int.from_bytes(result.output[32:64]) == int(not child_reverts)
            assert int.from_bytes(result.output[64:96]) == 3


def test_returndata_size_snapshot_survives_a_later_external_call():
    backend = PyEVMBackend()
    vm = backend.chain.get_vm()
    first, second = bytes.fromhex("12" * 20), bytes.fromhex("13" * 20)
    vm.state.set_code(first, bytes.fromhex("62aabbcc5f526003601df3"))
    vm.state.set_code(second, b"\x00")

    def call_code(target):
        return bytes.fromhex("5f5f5f5f5f73") + target + bytes.fromhex("6207a120f1")

    # Keep the first size on the EVM stack until after the second call clears
    # returndata. Inlining this read at MSTORE would incorrectly write zero.
    code = call_code(first) + bytes.fromhex("503d") + call_code(second)
    code += bytes.fromhex("505f523d60205260405ff3")
    sender = backend.account_keys[0].public_key.to_canonical_address()
    actual = vm.execute_bytecode(
        origin=sender,
        gas_price=0,
        gas=1000000,
        to=b"\x34" * 20,
        sender=sender,
        value=0,
        data=b"",
        code=code,
    )
    constants = {
        "zero": "0x0",
        "gas": "0x7a120",
        "first": "0x" + first.hex(),
        "second": "0x" + second.hex(),
        "word": "0x20",
        "size": "0x40",
    }
    instructions = [
        Instruction(
            "first", "CALL", ["ok1"], ["gas", "first", "zero", "zero", "zero", "zero", "zero"], []
        ),
        Instruction("snapshot", "RETURNDATASIZE", ["old"], [], []),
        Instruction(
            "second", "CALL", ["ok2"], ["gas", "second", "zero", "zero", "zero", "zero", "zero"], []
        ),
        Instruction("save-old", "MSTORE", [], ["zero", "old"], []),
        Instruction("snapshot-new", "RETURNDATASIZE", ["new"], [], []),
        Instruction("save-new", "MSTORE", [], ["word", "new"], []),
        Instruction("return", "RETURN", [], ["zero", "size"], []),
    ]
    semantics = SemanticInfo(
        schema_version=3,
        storage_fields=[],
        storage_accesses=[],
        arguments=[],
        memory_values={},
        constants=constants,
        guards=[],
        calls=[],
        call_returns=[],
        warnings=[],
    )
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        semantics,
    )
    text, _ = render_recovered(program, structure_flow=True)
    old_name = Expressions(program, program.functions[0]).name("old")
    assert f"{old_name} = evm.returndatasize();" in text
    assert f"evm.mstore(0x0, {old_name});" in text
    for mode in (False, True):
        outcomes = iter(
            [ExternalOutcome(bytes.fromhex("aabbcc"), True), ExternalOutcome(b"", True)]
        )
        result = RecoveredMachine(
            program, structured=mode, external_handler=lambda _, outcomes=outcomes: next(outcomes)
        ).execute(b"")
        assert (result.output, result.reverted) == (actual.output, actual.is_error)
        assert int.from_bytes(result.output[:32]) == 3
        assert int.from_bytes(result.output[32:]) == 0
