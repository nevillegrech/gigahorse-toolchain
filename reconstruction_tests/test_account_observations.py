"""Balance reads use an ordered, target-checked independent execution trace."""

import hashlib

import pytest

from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine
from reconstruction.validation import UnsupportedExecution


@pytest.mark.parametrize("opcode", ("SELFBALANCE", "BALANCE"))
def test_observed_account_balances_match_evm_and_reject_other_targets(opcode, record_property):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    prefix = b"\x47" if opcode == "SELFBALANCE" else b"\x30\x31"
    runtime = prefix + bytes.fromhex("60005260206000f3")
    instructions = []
    if opcode == "BALANCE":
        instructions.append(Instruction("address", "ADDRESS", ["target"], [], ["0x0"]))
    instructions.extend(
        [
            Instruction(
                "balance",
                opcode,
                ["balance"],
                ["target"] if opcode == "BALANCE" else [],
                [hex(len(prefix) - 1)],
            ),
            Instruction("store", "MSTORE", [], ["zero", "balance"], [hex(len(prefix) + 2)]),
            Instruction("return", "RETURN", [], ["zero", "width"], [hex(len(runtime) - 1)]),
        ]
    )
    program = Program(
        {"zero": "0x0", "width": "0x20"},
        {},
        [Function("root", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex(),
    )
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    address = int(reference.address, 16)
    for value in (0, 1, 37):
        expected, reverted = reference.call(b"", value)
        assert not reverted and int.from_bytes(expected) == value
        for mode in (False, True):
            result = ProjectedMachine(program, structured=mode).execute(
                b"",
                address=address,
                value=value,
                observed_balance_values=[(opcode, address, value)],
            )
            assert (result.output, result.reverted) == (expected, reverted)
    machine = ProjectedMachine(program, structured=True)
    with pytest.raises(UnsupportedExecution, match="independent observed balance"):
        machine.execute(b"", address=address)
    for observation in (
        (opcode, address + 1, 0),
        ("BALANCE" if opcode == "SELFBALANCE" else "SELFBALANCE", address, 0),
    ):
        with pytest.raises(UnsupportedExecution, match="operation/target disagrees"):
            machine.execute(b"", address=address, observed_balance_values=[observation])
    record_property("observed_balance_evm_cases", 3)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())
