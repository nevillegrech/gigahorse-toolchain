"""Private interfaces must distinguish data from control and keep call order."""

import pytest

from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.presentation import InternalInterfaces, LocalNames
from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.semantics import SemanticInfo


def private_program():
    constants = {"zero": "0x0", "one": "0x1", "size": "0x20", "target": "0x100", "resume": "0x20"}
    root = Block(
        "0x0",
        [
            Instruction("load", "CALLDATALOAD", ["x"], ["zero"], ["0x0"]),
            Instruction(
                "call", "CALLPRIVATE", ["answer"], ["target", "x", "resume", "one"], ["0x5"]
            ),
        ],
        [],
        [],
    )
    after = Block(
        "after",
        [
            Instruction("store", "MSTORE", [], ["zero", "answer"], ["0x20"]),
            Instruction("end", "RETURN", [], ["zero", "size"], ["0x23"]),
        ],
        [],
        [],
    )
    child = Block(
        "child",
        [
            Instruction("add", "ADD", ["sum"], ["left", "right"], ["0x100"]),
            Instruction("ret", "RETURNPRIVATE", [], ["control", "sum"], ["0x101"]),
        ],
        [],
        [],
    )
    semantics = SemanticInfo(
        3, [], [], [], {}, constants, [], [("0x0", "helper")], [("0x0", "helper", "after")], []
    )
    return Program(
        constants,
        {},
        [
            Function("0x0", ["0x0"], [], None, [], ["0x0", "after"]),
            Function("helper", ["child"], [], None, ["left", "control", "right"], ["child"]),
        ],
        [root, after, child],
        [],
        [],
        semantics,
    )


def test_control_in_middle_is_omitted_without_reordering_data_or_losing_evidence():
    program = private_program()
    interfaces = InternalInterfaces(program)
    assert interfaces.hidden == {"helper": 1}
    text, mapping = render_recovered(program, structure_flow=True)
    assert "function fn_helper(word input0, word input2)" in text
    assert "fn_helper(evm.calldataload(0x0), 0x1)" in text
    assert "return_internal(u256(input0 + input2));" in text
    proof = mapping["internal_interfaces"][0]
    assert proof["omitted_index"] == 1
    assert set(proof["ir_statements"]) == {"call", "ret"}
    assert proof["bytecode_offsets"] == ["0x101", "0x5"]
    assert proof == program.to_dict()["internal_interfaces"][0]
    for mode in (False, True):
        machine = ProjectedMachine(program, structured=mode)
        for value in (0, 17, (1 << 256) - 1):
            result = machine.execute(value.to_bytes(32))
            assert not result.reverted
            assert int.from_bytes(result.output) == (value + 1) % (1 << 256)


@pytest.mark.parametrize(
    "fault",
    [
        "data-use",
        "returned-data",
        "redefined",
        "ambiguous-callee",
        "missing-continuation",
        "wrong-arity",
        "conflicting-edge",
        "foreign-continuation",
    ],
)
def test_uncertain_or_data_bearing_return_input_is_kept(fault):
    program = private_program()
    root, _after, child = program.blocks
    if fault == "data-use":
        child.instructions.insert(0, Instruction("save", "MSTORE", [], ["zero", "control"], []))
    elif fault == "returned-data":
        child.instructions[-1].operands.append("control")
    elif fault == "redefined":
        child.instructions.insert(0, Instruction("replace", "MOV", ["control"], ["one"], []))
    elif fault == "ambiguous-callee":
        program.semantics.calls.append(("0x0", "other"))
    elif fault == "missing-continuation":
        program.semantics.call_returns.clear()
    elif fault == "wrong-arity":
        root.instructions[-1].operands.pop()
    elif fault == "conflicting-edge":
        root.successors = ["child"]
    else:
        program.semantics.call_returns = [("0x0", "helper", "child")]
    assert not InternalInterfaces(program).hidden
    text, _ = render_recovered(program)
    assert "function fn_helper(word input0, word input1, word input2)" in text


def test_local_names_are_distinct_and_can_be_traced_to_ir_definitions():
    program = private_program()
    helper = program.functions[1]
    helper.formal_variables = ["temp1", "control", "state_word1"]
    child = program.blocks[-1]
    child.instructions.insert(0, Instruction("sload", "SLOAD", ["input0"], ["zero"], ["0xff"]))
    names = LocalNames(program, helper, InternalInterfaces(program))
    assert len(names.names) == len(set(names.names.values()))
    row = next(v for v in names.metadata()["variables"] if v["ir_variable"] == "input0")
    assert row["ir_definitions"] == ["sload"] and row["bytecode_offsets"] == ["0xff"]
