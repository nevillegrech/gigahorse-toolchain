"""Printed expressions must have assigned temporaries and preserve word semantics."""

import pytest

from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import PrintedExpressions, ProjectedMachine
from reconstruction.recovered import Expressions, render_recovered
from reconstruction.semantics import SemanticInfo
from reconstruction.validation import UnsupportedExecution


def deep_program(opcode):
    instructions = [Instruction("load", "CALLDATALOAD", ["x0"], ["zero"], ["0x0"])]
    for index in range(1, 41):
        operands = [f"x{index - 1}"] + (["one"] if opcode == "ADD" else [])
        instructions.append(Instruction(f"s{index}", opcode, [f"x{index}"], operands, []))
    instructions += [
        Instruction("store", "MSTORE", [], ["zero", "x40"], ["0x31"]),
        Instruction("return", "RETURN", [], ["zero", "size"], ["0x32"]),
    ]
    constants = {"zero": "0x0", "one": "0x1", "size": "0x20"}
    semantics = SemanticInfo(3, [], [], [], {}, constants, [], [], [], [])
    return Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        semantics,
    )


@pytest.mark.parametrize("opcode", ["MOV", "ADD"])
def test_bounded_expansion_keeps_every_referenced_assignment(opcode):
    program = deep_program(opcode)
    expressions = Expressions(program, program.functions[0])
    assert expressions.materialized
    text, evidence = render_recovered(program, structure_flow=True)
    for variable in expressions.materialized:
        line_number = next(
            i
            for i, line in enumerate(text.splitlines(), 1)
            if f"{expressions.name(variable)} = evm." in line
        )
        definition = expressions.definitions[variable]
        assert any(
            entry["line"] == line_number and definition.id in entry["ir_statements"]
            for entry in evidence["lines"]
        )
    mask = (1 << 256) - 1
    for seed in (0, 17, mask - 20, mask):
        machine = ProjectedMachine(program, structured=True)
        result = machine.execute(seed.to_bytes(32))
        expected = seed if opcode == "MOV" else (seed + 40) & mask
        assert not result.reverted and int.from_bytes(result.output) == expected
        assert machine.expression_checks >= len(expressions.materialized) + 4


def test_validator_catches_the_original_missing_temporary(monkeypatch):
    monkeypatch.setattr(Expressions, "_retain_referenced_temporaries", lambda *_: None)
    machine = ProjectedMachine(deep_program("MOV"), structured=True)
    with pytest.raises(UnsupportedExecution, match="Printed temporary has no assignment"):
        machine.execute((17).to_bytes(32))


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("u256(0 - 1)", (1 << 256) - 1),
        ("u256(7 << 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)", 0),
        ("evm.not(0)", (1 << 256) - 1),
        ("evm.sdiv(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 2)", 0),
        ("word(2 != 0)", 1),
    ],
)
def test_printed_expression_word_semantics(expression, expected):
    assert PrintedExpressions({}, {}, b"").value(expression) == expected


def test_printed_expression_rejects_arbitrary_python():
    for text in ("__import__('os').getcwd()", "[x for x in ()]", "(lambda: 1)()"):
        with pytest.raises(UnsupportedExecution):
            PrintedExpressions({}, {}, b"").value(text)
