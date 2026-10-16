"""Storage accessors must preserve captured values, ranges and evidence."""

from dataclasses import replace

import pytest

from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.semantics import SemanticInfo, StorageAccess, StorageField, Term
from reconstruction.storage_reads import StorageReads
from reconstruction.validation import UnsupportedExecution


def captured_byte(*, barrier=None, mask=255, shift=0):
    constants = {"slot": "0x0", "mask": hex(mask), "new": "0x7", "size": "0x20"}
    load = Instruction("load", "SLOAD", ["captured"], ["slot"], ["0x2"])
    instructions = [load]
    if barrier == "SSTORE":
        instructions.append(Instruction("write", "SSTORE", [], ["slot", "new"], ["0x7"]))
    elif barrier:
        instructions.append(Instruction("barrier", barrier, [], [], []))
    value = "captured"
    if shift:
        constants["shift"] = hex(shift)
        instructions.append(Instruction("shift", "SHR", ["shifted"], ["shift", value], []))
        value = "shifted"
    instructions += [
        Instruction("byte", "AND", ["byte_value"], [value, "mask"], ["0xa"]),
        Instruction("store", "MSTORE", [], ["slot", "byte_value"], ["0xd"]),
        Instruction("return", "RETURN", [], ["slot", "size"], ["0x12"]),
    ]
    low = shift // 8
    construct = Term("TightlyPackedVariable", (Term("Constant", ("0x0",)), str(low), str(low)))
    access = StorageAccess(
        "byte", "ACCESS", "storage", Term("ConstantIndex", ("0x0",)), construct, ["byte_value"], []
    )
    field = StorageField(
        f"slot_0_bytes_{low}_{low}",
        "storage",
        "0x0",
        "TightlyPackedVariable",
        low,
        low,
        ["bool", "uint8"],
        ["load", "byte"],
    )
    semantics = SemanticInfo(3, [field], [access], [], {}, constants, [], [], [], [])
    function = Function("0x0", ["0x0"], [], None, [], ["0x0"])
    program = Program(
        constants, {}, [function], [Block("0x0", instructions, [], [])], [], [], semantics
    )
    return program, access, instructions[-3]


def test_clean_packed_read_has_complete_source_and_bit_evidence():
    program, access, instruction = captured_byte(shift=16)
    proof = StorageReads(program, program.functions[0]).proof(access, instruction)
    assert proof and proof.source_load == "load" and (proof.shift, proof.mask) == (16, 255)
    assert {"load", "shift", "byte"} <= set(proof.evidence)
    text, mapping = render_recovered(program, structure_flow=True)
    assert " = slot_0_bytes_2_2;" in text
    assert len(mapping["storage_read_proofs"]) == 1
    line = next(line for line in mapping["lines"] if line["inference"] == "storage-read")
    assert {"load", "shift", "byte"} <= set(line["ir_statements"])
    for initial in (0, 0x123456, (1 << 256) - 1):
        machine = ProjectedMachine(program, structured=True)
        result = machine.execute(b"", storage={0: initial})
        assert int.from_bytes(result.output) == (initial >> 16) & 255
        assert machine.storage_read_checks == 1


@pytest.mark.parametrize(
    "barrier",
    (
        "SSTORE",
        "TSTORE",
        "CALL",
        "DELEGATECALL",
        "STATICCALL",
        "CALLPRIVATE",
        "CREATE",
        "CREATE2",
        "OPAQUE_INSTRUCTION",
    ),
)
def test_storage_or_call_effect_withholds_a_live_accessor(barrier):
    program, access, instruction = captured_byte(barrier=barrier)
    assert StorageReads(program, program.functions[0]).proof(access, instruction) is None
    text, mapping = render_recovered(program, structure_flow=True)
    assert " = slot_0_bytes_0_0;" not in text
    assert " = evm.and(" in text and not mapping["storage_read_proofs"]


def test_changed_byte_and_unknown_length_are_not_supported_accessor_proofs():
    program, access, instruction = captured_byte(mask=1)
    assert StorageReads(program, program.functions[0]).proof(access, instruction) is None
    program, access, instruction = captured_byte()
    assert (
        StorageReads(program, program.functions[0]).proof(
            replace(access, kind="LENGTH"), instruction
        )
        is None
    )
    wrong_slot = replace(access, index=Term("ConstantIndex", ("0x1",)))
    assert StorageReads(program, program.functions[0]).proof(wrong_slot, instruction) is None


def test_stale_packed_alias_preserves_original_load_against_evm(tmp_path):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_execution import EVMReference
    from reconstruction_tests.test_weth_execution import deploy_runtime

    program, _, _ = captured_byte(barrier="SSTORE")
    runtime = bytes.fromhex("600054600760005560ff1660005260206000f3")
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    initial = {0: 0x123412}
    deploy_runtime(reference, runtime, initial)
    expected, reverted = reference.call(b"")
    assert not reverted and int.from_bytes(expected) == 18
    for mode in (False, True):
        machine = ProjectedMachine(program, structured=mode)
        result = machine.execute(b"", storage=initial)
        assert (result.output, result.reverted) == (expected, reverted)
        assert result.storage == {0: 7}
        assert machine.storage_read_checks == 0
    assert reference.commit(b"") == 1 and reference.storage(0) == 7


def test_validator_rejects_an_injected_incorrect_byte_accessor(monkeypatch):
    program, _, instruction = captured_byte(mask=1)
    clean, clean_access, clean_stmt = captured_byte()
    incorrect = StorageReads(clean, clean.functions[0]).proof(clean_access, clean_stmt)
    assert incorrect is not None
    original = StorageReads.proof

    def faulty(self, candidate, stmt):
        # Pretend the original AND had masked a whole byte instead of one bit.
        return incorrect if stmt.id == instruction.id else original(self, candidate, stmt)

    monkeypatch.setattr(StorageReads, "proof", faulty)
    with pytest.raises(UnsupportedExecution, match="Printed storage read disagrees"):
        ProjectedMachine(program, structured=True).execute(b"", storage={0: 18})


def test_one_mutating_branch_withholds_a_cross_block_alias():
    program, access, instruction = captured_byte()
    tail = program.blocks[0].instructions[1:]
    constants = program.constants
    constants.update({"right": "0x20", "join": "0x30"})
    program.blocks = [
        Block(
            "0x0",
            [
                program.blocks[0].instructions[0],
                Instruction("input", "CALLDATALOAD", ["condition"], ["slot"], []),
                Instruction("branch", "JUMPI", [], ["right", "condition"], []),
            ],
            ["0x20", "0x10"],
            ["0x10"],
        ),
        Block("0x10", [Instruction("left-jump", "JUMP", [], ["join"], [])], ["0x30"], []),
        Block(
            "0x20",
            [
                Instruction("write", "SSTORE", [], ["slot", "new"], []),
                Instruction("right-jump", "JUMP", [], ["join"], []),
            ],
            ["0x30"],
            [],
        ),
        Block("0x30", tail, [], []),
    ]
    program.functions[0].blocks = [b.id for b in program.blocks]
    assert StorageReads(program, program.functions[0]).proof(access, instruction) is None
    for condition in (0, 1):
        result = ProjectedMachine(program, structured=True).execute(
            condition.to_bytes(32), storage={0: 18}
        )
        assert int.from_bytes(result.output) == 18
        assert result.storage == {0: 7 if condition else 18}
    program.blocks[2].instructions.pop(0)
    assert StorageReads(program, program.functions[0]).proof(access, instruction)
