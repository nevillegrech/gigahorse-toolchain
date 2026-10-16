"""Raw ABI views must preserve actual accesses, including malformed encodings."""

import random

import pytest

from reconstruction.calldata import MASK, CalldataViews, analyze_calldata
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.recovered import Expressions, render_recovered
from reconstruction.semantics import Argument, SemanticInfo
from reconstruction_tests.test_evaluation import evaluation_program


def tuple_array_program():
    operations = [
        ("head", "CALLDATALOAD", ["four"]),
        ("base", "ADD", ["four", "head"]),
        ("data", "ADD", ["base", "word"]),
        ("stride", "SHL", ["five", "i"]),
        ("entry", "ADD", ["stride", "data"]),
        ("relative", "CALLDATALOAD", ["entry"]),
        ("element", "ADD", ["relative", "data"]),
        ("target", "CALLDATALOAD", ["element"]),
        ("field", "ADD", ["two_words", "element"]),
        ("payload_relative", "CALLDATALOAD", ["field"]),
        ("payload", "ADD", ["element", "payload_relative"]),
        ("length", "CALLDATALOAD", ["payload"]),
        ("start", "ADD", ["word", "payload"]),
    ]
    instructions = [
        Instruction(v, op, [v], args, [hex(n)]) for n, (v, op, args) in enumerate(operations)
    ]
    instructions.append(
        Instruction("copy", "CALLDATACOPY", [], ["destination", "start", "length"], ["0x40"])
    )
    block = Block("entry", instructions, [], [])
    function = Function("method", ["entry"], ["0x12345678"], None, [], ["entry"])
    constants = {"four": "0x4", "word": "0x20", "two_words": "0x40", "five": "0x5"}
    semantics = SemanticInfo(
        3,
        [],
        [],
        [Argument("method", 0, ["base"], "array", ["word"], [])],
        {},
        constants,
        [],
        [],
        [],
        [],
    )
    return Program(constants, {}, [function], [block], [], [], semantics), function


def word(value):
    return value.to_bytes(32)


def encoded_array():
    tuples = []
    for target, allow_failure, payload in ((0x1234, 0, b"hello"), (0x5678, 1, b"\xff" * 47)):
        tuples.append(
            word(target)
            + word(allow_failure)
            + word(96)
            + word(len(payload))
            + payload.ljust((len(payload) + 31) // 32 * 32, b"\0")
        )
    return (
        bytes.fromhex("12345678")
        + word(32)
        + word(2)
        + word(64)
        + word(64 + len(tuples[0]))
        + b"".join(tuples)
    )


def test_tuple_array_and_nested_byte_copy_have_bytecode_evidence():
    program, function = tuple_array_program()
    views = CalldataViews(program, function)
    data = encoded_array()
    assert len(views.root_info) == 1 and len(views.byte_copies) == 1
    for index, target, size in ((0, 0x1234, 5), (1, 0x5678, 47)):
        environment = {"i": index}
        assert views.bindings["target"][0].evaluate(data, environment) == target
        assert views.bindings["length"][0].evaluate(data, environment) == size
        start = views.bindings["start"][0].evaluate(data, environment)
        assert data[start : start + size] == (b"hello" if index == 0 else b"\xff" * 47)
    expression = Expressions(program, function).value("start")
    assert expression.text == "cd_arg0.element(v_i).dynamic_field(0x2).data_offset"
    assert {
        "head",
        "base",
        "relative",
        "element",
        "payload_relative",
        "payload",
        "start",
    } <= expression.evidence
    program.calldata_views = analyze_calldata(program)
    text, mapping = render_recovered(program)
    assert "raw_calldata_view cd_arg0" in text
    assert "dynamic_field(0x2).length" in text
    assert mapping["calldata_views"][0]["byte_copies"][0]["statement"] == "copy"
    assert mapping["calldata_accessors"]["element(i)"].startswith("raw_calldata_view")
    line = next(line for line in mapping["lines"] if "copy" in line["ir_statements"])
    assert {"0x0", "0x1", "0xc", "0x40"} <= set(line["bytecode_offsets"])


@pytest.mark.parametrize("length", [0, 4, 35, 36, 68, 101, 511])
def test_raw_views_keep_wraparound_and_zero_padding(length):
    program, function = tuple_array_program()
    views = CalldataViews(program, function)
    rng = random.Random(176 + length)
    data = rng.randbytes(length)
    for index in (0, 1, (1 << 251) + 1, MASK):
        # Evaluate the original TAC independently in statement order.
        values = {name: int(value, 16) for name, value in program.constants.items()}
        values["i"] = index
        for stmt in program.blocks[0].instructions[:-1]:
            a = [values[v] for v in stmt.operands]
            if stmt.opcode == "CALLDATALOAD":
                number = int.from_bytes(data[a[0] : a[0] + 32].ljust(32, b"\0"))
            elif stmt.opcode == "SHL":
                number = a[1] << a[0]
            else:
                number = a[0] + a[1]
            values[stmt.definitions[0]] = number & MASK
            binding = views.bindings.get(stmt.definitions[0])
            if binding:
                assert binding[0].evaluate(data, {"i": index}) == number & MASK


def test_large_indices_wrap_without_adding_an_array_check():
    program, function = tuple_array_program()
    views = CalldataViews(program, function)
    data = encoded_array()
    assert views.bindings["target"][0].evaluate(data, {"i": (1 << 251) + 1}) == 0x5678
    # A malformed offset wraps the view base to zero. It still reads raw bytes;
    # the bounds/revert guards in the contract, not this view, reject such input.
    data = data[:4] + word(MASK - 3) + data[36:]
    assert views.bindings["base"][0].evaluate(data, {}) == 0
    assert views.bindings["data"][0].evaluate(data, {}) == 32


@pytest.mark.parametrize(
    "fault",
    ["head-bias", "word-argument", "unaligned-stride", "ambiguous-definition", "conflicting-kind"],
)
def test_unsupported_or_conflicting_shapes_do_not_create_array_views(fault):
    program, function = tuple_array_program()
    instructions = {s.id: s for s in program.blocks[0].instructions}
    if fault == "head-bias":
        instructions["base"].operands[0] = "word"
    elif fault == "word-argument":
        program.semantics.arguments[0].kind = "word"
    elif fault == "unaligned-stride":
        instructions["stride"].opcode = "MUL"
        program.constants["five"] = "0x1f"
    elif fault == "conflicting-kind":
        program.semantics.arguments.append(Argument("method", 0, ["base"], "struct", ["word"], []))
    else:
        program.blocks[0].instructions.append(
            Instruction("other", "ADD", ["base"], ["word", "head"], [])
        )
    views = CalldataViews(program, function)
    assert not views.byte_copies
    assert not any(access.view.steps for access, _ in views.bindings.values())


def test_view_does_not_invent_types_from_address_masks_or_byte_copies():
    program, function = tuple_array_program()
    before = program.semantics.arguments[0].type_candidates.copy()
    views = CalldataViews(program, function)
    assert before == program.semantics.arguments[0].type_candidates == ["word"]
    metadata = views.metadata(function.id)
    assert "no-added-checks" in metadata["semantics"]
    assert "address" not in str(metadata) and "allowFailure" not in str(metadata)


def test_normalization_handles_commuted_addition_and_multiplication():
    program, function = tuple_array_program()
    instructions = {s.id: s for s in program.blocks[0].instructions}
    for stmt in instructions.values():
        if stmt.opcode == "ADD":
            stmt.operands.reverse()
    instructions["stride"].opcode = "MUL"
    instructions["stride"].operands = ["i", "word"]
    views = CalldataViews(program, function)
    assert views.bindings["target"][0].evaluate(encoded_array(), {"i": 1}) == 0x5678
    assert (
        views.render(views.bindings["start"][0], str)
        == "cd_arg0.element(i).dynamic_field(0x2).data_offset"
    )


def test_deployed_tuple_paths_are_inferred_without_abi_ground_truth(tmp_path):
    program, _ = evaluation_program(tmp_path)
    assert len(program.calldata_views) == 6
    assert sum(len(f["byte_copies"]) for f in program.calldata_views) == 6
    text, mapping = render_recovered(program, structure_flow=True)
    assert ".dynamic_field(0x2).data_offset" in text
    assert ".dynamic_field(0x2).length" in text
    assert "allowFailure" not in text and "aggregate3" not in text
    assert len(mapping["calldata_views"]) == 6
    statements = {s.id for b in program.blocks for s in b.instructions}
    for function in mapping["calldata_views"]:
        assert all(set(b["evidence"]) <= statements for b in function["bindings"])
