"""Behavioral checks against independently executed EVM bytecode (validation extra)."""

import hashlib
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_tester import EthereumTester, PyEVMBackend
from eth_tester.backends.pyevm.main import EVMSpoofTransaction, _execute_and_revert_transaction

from reconstruction.projection import ProjectedMachine
from reconstruction.validation import UnsupportedExecution, arithmetic
from reconstruction_tests.test_controlflow import fixture_program

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


class EVMReference:
    def __init__(self, manifest):
        self.backend = PyEVMBackend()
        self.tester = EthereumTester(backend=self.backend)
        self.sender = self.tester.get_accounts()[0]
        deployment = self.tester.send_transaction(
            {"from": self.sender, "gas": 9000000, "data": "0x" + manifest["creation_bytecode"]}
        )
        self.address = self.tester.get_transaction_receipt(deployment)["contract_address"]

    def call(self, data, value=0):
        transaction = {
            "from": bytes.fromhex(self.sender[2:]),
            "to": bytes.fromhex(self.address[2:]),
            "gas": 9000000,
            "data": data,
            "value": value,
        }
        unsigned = self.backend._get_normalized_and_unsigned_evm_transaction(transaction, "latest")
        computation = _execute_and_revert_transaction(
            self.backend.chain, EVMSpoofTransaction(unsigned, from_=transaction["from"]), "latest"
        )
        self.logs = list(computation.get_log_entries())
        return computation.output, computation.is_error

    def commit(self, data, value=0):
        transaction = self.tester.send_transaction(
            {
                "from": self.sender,
                "to": self.address,
                "gas": 9000000,
                "data": "0x" + data.hex(),
                "value": value,
            }
        )
        return self.tester.get_transaction_receipt(transaction)["status"]

    def storage(self, slot):
        result = self.backend.get_storage(bytes.fromhex(self.address[2:]), slot)
        return result if isinstance(result, int) else int.from_bytes(result)


@pytest.mark.parametrize("variant", ("optimized", "via-ir"))
def test_original_evm_matches_cfg_and_structured_execution(variant, tmp_path, record_property):
    stem = "control-flow-" + variant
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    program = fixture_program(stem, tmp_path)
    reference = EVMReference(manifest)
    raw, structured = [ProjectedMachine(program, structured=mode) for mode in (False, True)]
    raw_storage, structured_storage = {}, {}
    cases = 0
    expression_checks = storage_paths = unchecked_paths = 0

    def check(data, value=0):
        nonlocal raw_storage, structured_storage, cases
        nonlocal expression_checks, storage_paths, unchecked_paths
        expected, reverted = reference.call(data, value)
        context = {
            "caller": int(reference.sender, 16),
            "address": int(reference.address, 16),
            "value": value,
        }
        before = reference.storage(0)
        result = raw.execute(data, storage=raw_storage, **context)
        converted = structured.execute(data, storage=structured_storage, **context)
        for machine in (raw, structured):
            expression_checks += machine.expression_checks
            storage_paths += machine.storage_path_checks
            unchecked_paths += machine.storage_paths_unchecked
        assert (result.output, result.reverted) == (expected, reverted), (variant, data.hex())
        assert (converted.output, converted.reverted) == (expected, reverted), (variant, data.hex())
        assert result.blocks == converted.blocks, (variant, data.hex())
        assert reference.commit(data, value) == int(not reverted)
        assert result.storage.get(0, 0) == converted.storage.get(0, 0) == reference.storage(0)
        if reverted:
            assert result.storage.get(0, 0) == before
        raw_storage, structured_storage = result.storage, converted.storage
        cases += 1

    def calldata(signature, types, arguments):
        return bytes.fromhex(manifest["method_identifiers"][signature]) + encode(types, arguments)

    for n in (0, 1, 2, 3, 7, 8, 9, 30, 31, 32, 64, 65):
        for signature in ("sum(uint256)", "swap(uint256)"):
            check(calldata(signature, ["uint256"], [n]))
    for n, m in ((0, 0), (0, 8), (1, 1), (2, 3), (3, 4), (8, 8), (9, 1), (1, 9)):
        check(calldata("nested(uint256,uint256)", ["uint256", "uint256"], [n, m]))
    for flag, left, right in (
        (False, 4, 5),
        (True, 4, 5),
        (True, (1 << 256) - 1, 0),
        (False, 0, (1 << 256) - 1),
    ):
        check(
            calldata(
                "choose(bool,uint256,uint256)", ["bool", "uint256", "uint256"], [flag, left, right]
            )
        )
    rng = random.Random(20261015)
    for _ in range(24):
        check(calldata("sum(uint256)", ["uint256"], [rng.randrange(66)]))
        check(
            calldata(
                "nested(uint256,uint256)",
                ["uint256", "uint256"],
                [rng.randrange(9), rng.randrange(9)],
            )
        )
    for n in (0, 1, 5, 32, 33, 4):
        check(calldata("persist(uint256)", ["uint256"], [n]))
    check(calldata("persist(uint256)", ["uint256"], [1]), value=1)
    check(b"")
    check(bytes.fromhex("deadbeef"))
    check(bytes.fromhex(manifest["method_identifiers"]["sum(uint256)"]))
    invalid_bool = bytes.fromhex(
        manifest["method_identifiers"]["choose(bool,uint256,uint256)"]
    ) + encode(["uint256"] * 3, [2, 1, 1])
    check(invalid_bool)
    record_property("evm_contract_cases", cases)
    record_property("printed_expression_checks", expression_checks)
    record_property("printed_storage_path_checks", storage_paths)
    record_property("printed_storage_paths_unchecked", unchecked_paths)
    record_property("fixture", stem)
    record_property("bytecode_sha256", manifest["bytecode_sha256"])
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / f"{stem}.relations.json").read_bytes()
            + (FIXTURES / f"{stem}.semantic.json").read_bytes()
        ).hexdigest(),
    )


def test_parallel_phi_swap_and_arithmetic_boundaries():
    assert arithmetic("SDIV", [(1 << 256) - 9, 2]) == (1 << 256) - 4
    assert arithmetic("SMOD", [(1 << 256) - 9, 2]) == (1 << 256) - 1
    assert arithmetic("DIV", [9, 0]) == 0
    assert arithmetic("SHL", [256, 1]) == 0
    assert arithmetic("SAR", [256, (1 << 256) - 1]) == (1 << 256) - 1
    with pytest.raises(UnsupportedExecution):
        arithmetic("UNKNOWN", [])


@pytest.mark.parametrize(
    "op,args,opcode",
    [
        ("SUB", [1, 2], 0x03),
        ("ADD", [(1 << 256) - 1, 1], 0x01),
        ("MUL", [1 << 255, 2], 0x02),
        ("DIV", [7, 0], 0x04),
        ("SDIV", [(1 << 256) - 9, 2], 0x05),
        ("SDIV", [1 << 255, (1 << 256) - 1], 0x05),
        ("SMOD", [(1 << 256) - 9, 2], 0x07),
        ("SMOD", [9, (1 << 256) - 2], 0x07),
        ("ADDMOD", [(1 << 256) - 1, 7, 11], 0x08),
        ("MULMOD", [1 << 255, 9, 13], 0x09),
        ("ADDMOD", [3, 4, 0], 0x08),
        ("EXP", [2, 256], 0x0A),
        ("SIGNEXTEND", [0, 255], 0x0B),
        ("SIGNEXTEND", [0, 127], 0x0B),
        ("SIGNEXTEND", [32, (1 << 256) - 1], 0x0B),
        ("SLT", [1 << 255, 1], 0x12),
        ("SGT", [1, (1 << 256) - 1], 0x13),
        ("BYTE", [0, 0xFF << 248], 0x1A),
        ("BYTE", [32, (1 << 256) - 1], 0x1A),
        ("SHL", [256, 1], 0x1B),
        ("SHL", [255, 1], 0x1B),
        ("SHR", [256, 1 << 255], 0x1C),
        ("SAR", [512, 1 << 255], 0x1D),
        ("SAR", [255, 1], 0x1D),
        ("NOT", [0], 0x19),
    ],
)
def test_validation_word_semantics_match_independent_evm(op, args, opcode):
    backend = PyEVMBackend()
    sender = backend.account_keys[0].public_key.to_canonical_address()
    code = b"".join(b"\x7f" + arg.to_bytes(32) for arg in reversed(args))
    code += bytes([opcode]) + bytes.fromhex("5f5260205ff3")
    computation = backend.chain.get_vm().execute_bytecode(
        origin=sender,
        gas_price=0,
        gas=1000000,
        to=b"\x00" * 20,
        sender=sender,
        value=0,
        data=b"",
        code=code,
    )
    assert not computation.is_error
    assert arithmetic(op, args) == int.from_bytes(computation.output)
