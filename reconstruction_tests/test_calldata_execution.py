"""Validate raw ABI views and caller behavior on the deployed Multicall3 runtime.

External outcomes and GAS values come from Py-EVM, as in the interaction suite.
Each modeled calldata load is also checked against an independently observed
EVM load at its original bytecode PC. This is bounded caller/view validation;
it does not prove the emitted text or arbitrary contracts equivalent.
"""

import hashlib
from collections import Counter

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import decode, encode

from reconstruction.calldata import CalldataViews
from reconstruction.projection import ProjectedMachine
from reconstruction.returns import decode_encoding
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.test_evaluation import evaluation_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import stack_number, trace_call


def creation_code(runtime):
    size = len(runtime).to_bytes(2).hex()
    return "61" + size + "61000f60003961" + size + "6000f3" + runtime.hex()


def test_deployed_multicall_views_and_behavior_match_evm(tmp_path, monkeypatch, record_property):
    program, runtime = evaluation_program(tmp_path)
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})

    def deploy(code):
        transaction = reference.tester.send_transaction(
            {
                "from": reference.sender,
                "gas": 9000000,
                "data": "0x" + creation_code(bytes.fromhex(code)),
            }
        )
        return reference.tester.get_transaction_receipt(transaction)["contract_address"]

    echo = deploy("366000600037366000f3")
    failure = deploy("63deadbeef6000526004601cfd")
    eoa = reference.tester.get_accounts()[1]
    bindings = {
        variable: binding
        for function in program.functions
        for variable, binding in CalldataViews(program, function).bindings.items()
    }
    total_cases, total_loads, total_values, total_calls = 0, 0, 0, 0
    printed = Counter()
    decoded_returns = 0
    decoded_selectors = set()
    layouts = {r.statement: r for r in program.return_layouts}
    reference_types = {
        "82ad56cb": ["(bool,bytes)[]"],
        "174dea71": ["(bool,bytes)[]"],
        "bce38bd7": ["(bool,bytes)[]"],
        "252dba42": ["uint256", "bytes[]"],
        "399542e9": ["uint256", "bytes32", "(bool,bytes)[]"],
        "c3077fa9": ["uint256", "bytes32", "(bool,bytes)[]"],
    }

    def normalize(value, shape):
        if shape["kind"] == "tuple":
            return [normalize(v, s) for v, s in zip(value, shape["items"], strict=True)]
        if shape["kind"] == "array":
            return [normalize(v, shape["element"]) for v in value]
        if shape["kind"] == "byte_sequence":
            return value
        return int.from_bytes(value) if isinstance(value, bytes) else int(value)

    def check(data, value=0):
        nonlocal total_cases, total_loads, total_values, total_calls, decoded_returns
        observed_loads = []
        block_environment = {}
        block_hashes = {}
        computation_type = reference.backend.chain.get_vm().state.computation_class
        original = computation_type.opcodes[0x35]
        original_number = computation_type.opcodes[0x43]
        original_hash = computation_type.opcodes[0x40]

        class CaptureHash:
            mnemonic = original_hash.mnemonic

            def __call__(self, computation):
                root = computation.msg.depth == 0
                if root:
                    number = stack_number(computation._stack.values[-1])
                original_hash(computation=computation)
                if root:
                    block_hashes[number] = stack_number(computation._stack.values[-1])

        class CaptureNumber:
            mnemonic = original_number.mnemonic

            def __call__(self, computation):
                original_number(computation=computation)
                if computation.msg.depth == 0:
                    block_environment["NUMBER"] = stack_number(computation._stack.values[-1])

        class CaptureLoad:
            mnemonic = original.mnemonic

            def __call__(self, computation):
                root = computation.msg.depth == 0
                if root:
                    pc = computation.code.program_counter - 1
                    address = stack_number(computation._stack.values[-1])
                original(computation=computation)
                if root:
                    observed_loads.append(
                        (pc, address, stack_number(computation._stack.values[-1]))
                    )

        with monkeypatch.context() as patch:
            patch.setitem(computation_type.opcodes, 0x35, CaptureLoad())
            patch.setitem(computation_type.opcodes, 0x43, CaptureNumber())
            patch.setitem(computation_type.opcodes, 0x40, CaptureHash())
            expected, reverted, calls, gas = trace_call(reference, data, value, monkeypatch)
        traces = []
        for mode in (False, True):
            counts = Counter(observed_loads)
            pending = iter(calls)
            checks, loads = 0, 0

            class CheckedMachine(ProjectedMachine):
                def _instruction(self, stmt, block_id, counts=counts):
                    nonlocal checks, loads
                    address = (
                        self._value(stmt.operands[0]) if stmt.opcode == "CALLDATALOAD" else None
                    )
                    if stmt.opcode == "RETURN":
                        self.return_statement = stmt.id
                    super()._instruction(stmt, block_id)
                    for variable in stmt.definitions:
                        binding = bindings.get(variable)
                        if binding is None:
                            continue
                        actual = self._value(variable)
                        assert (
                            binding[0].evaluate(data, self.constants | self.variables) == actual
                        ), stmt.id
                        checks += 1
                        if stmt.opcode == "CALLDATALOAD":
                            candidates = [
                                (int(pc, 16), address, actual) for pc in stmt.original_statements
                            ]
                            match = next((key for key in candidates if counts[key]), None)
                            assert match is not None, (stmt.id, candidates)
                            counts[match] -= 1
                            loads += 1

            def replay(invocation, pending=pending):
                observed = next(pending)
                for name in ("opcode", "target", "value", "requested_gas", "calldata"):
                    assert getattr(invocation, name) == observed[name], (data.hex(), name)
                return ExternalOutcome(observed["returndata"], observed["success"])

            machine = CheckedMachine(program, structured=mode, external_handler=replay)
            result = machine.execute(
                data,
                value=value,
                caller=int(reference.sender, 16),
                address=int(reference.address, 16),
                observed_gas_values=gas,
                block_environment=block_environment,
                block_hashes=block_hashes,
            )
            printed.update(machine.projection_counts())
            assert next(pending, None) is None
            assert (result.output, result.reverted) == (expected, reverted), data.hex()
            if not result.reverted:
                layout = layouts[machine.return_statement]
                assert layout.status == "candidate_dynamic_encoding" and layout.shape is not None
                actual_values = decode_encoding(result.output, layout.shape)
                typed_values = decode(reference_types[data[:4].hex()], expected)
                assert actual_values == normalize(typed_values, layout.shape)
                if not mode:
                    decoded_returns += 1
                    decoded_selectors.add(data[:4].hex())
            traces.append(result.blocks)
            if not mode:
                total_loads += loads
                total_values += checks
        assert traces[0] == traces[1]
        total_cases += 1
        total_calls += len(calls)

    def calldata(selector, types, arguments):
        return bytes.fromhex(selector) + encode(types, arguments)

    payloads = [b"", b"hello", b"\xff" * 47, bytes(range(256))]
    for payload in payloads:
        check(calldata("82ad56cb", ["(address,bool,bytes)[]"], [[(echo, False, payload)]]))
        check(calldata("252dba42", ["(address,bytes)[]"], [[(echo, payload)]]))
        check(calldata("bce38bd7", ["bool", "(address,bytes)[]"], [False, [(echo, payload)]]))
        check(
            calldata("174dea71", ["(address,bool,uint256,bytes)[]"], [[(echo, False, 3, payload)]]),
            3,
        )
        check(calldata("399542e9", ["bool", "(address,bytes)[]"], [False, [(echo, payload)]]))
        check(calldata("c3077fa9", ["(address,bytes)[]"], [[(echo, payload)]]))
    for calls in (
        [],
        [(eoa, False, b"a")],
        [(failure, False, b"x")],
        [(failure, True, b"x"), (echo, False, b"last")],
    ):
        check(calldata("82ad56cb", ["(address,bool,bytes)[]"], [calls]))
    for required in (False, True):
        for calls in ([], [(failure, b"x")], [(failure, b"x"), (echo, b"ok")]):
            check(calldata("bce38bd7", ["bool", "(address,bytes)[]"], [required, calls]))
            check(calldata("399542e9", ["bool", "(address,bytes)[]"], [required, calls]))
    for calls, value in (
        ([], 0),
        ([], 1),
        ([(echo, False, 3, b"a")], 2),
        ([(echo, False, 3, b"a")], 4),
        ([(failure, True, 2, b"a"), (echo, False, 3, b"b")], 5),
    ):
        check(calldata("174dea71", ["(address,bool,uint256,bytes)[]"], [calls]), value)
    check(calldata("252dba42", ["(address,bytes)[]"], [[]]))
    check(calldata("252dba42", ["(address,bytes)[]"], [[(failure, b"fail")]]))
    check(calldata("c3077fa9", ["(address,bytes)[]"], [[]]))
    check(calldata("c3077fa9", ["(address,bytes)[]"], [[(failure, b"fail")]]))
    valid = calldata("82ad56cb", ["(address,bool,bytes)[]"], [[(echo, False, b"data")]])
    for position, number in (
        (4, 1 << 255),
        (36, 1 << 255),
        (68, (1 << 256) - 1),
        (100, 1 << 200),
        (132, 2),
        (164, 1 << 255),
        (196, 1 << 255),
    ):
        modified = bytearray(valid)
        modified[position : position + 32] = number.to_bytes(32)
        check(bytes(modified))
    for length in (4, 35, 67, 131, len(valid) - 1, len(valid) - 28):
        check(valid[:length])
    assert total_cases == 62 and total_loads > 100 and total_calls > 20
    assert decoded_selectors == set(reference_types) and decoded_returns > 30
    record_property("deployed_evm_contract_cases", total_cases)
    for name, count in printed.items():
        record_property(name, count)
    record_property("deployed_evm_calldata_loads", total_loads)
    record_property("deployed_evm_view_values", total_values)
    record_property("deployed_evm_external_calls", total_calls)
    record_property("deployed_evm_decoded_return_cases", decoded_returns)
    record_property("deployed_evm_decoded_return_selectors", len(decoded_selectors))
    record_property("validation_mode", "external-results-replayed-and-calldata-loads-observed")
    record_property("fixture", "deployed-multicall3")
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
