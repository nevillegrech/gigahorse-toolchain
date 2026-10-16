"""Native hint verification must respect aliases, joins and private-call contexts."""

import pytest

from reconstruction.constants import resolve_constants, unverified_constant_hints
from reconstruction.model import Block, Function, Instruction, Program


def instruction(ident, opcode, definitions=(), operands=()):
    return Instruction(ident, opcode, list(definitions), list(operands), [])


def straight_program(extra, candidate=0x11223344):
    constants = {
        "cell": "0x80",
        "word": "0x11223344",
        "other": "0x7",
        "zero": "0x0",
        "loaded": hex(candidate),
    }
    statements = [
        instruction("initialize", "MSTORE", operands=["cell", "word"]),
        *extra,
        instruction("read", "MLOAD", ["loaded"], ["cell"]),
        instruction("end", "STOP"),
    ]
    program = Program(
        constants,
        {},
        [Function("0x0", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", statements, [], [])],
        [],
        [],
    )
    return program, constants


@pytest.mark.parametrize(
    "destination,unchanged",
    [(96, True), (97, False), (128, False), (129, False), (159, False), (160, True)],
)
def test_known_write_ranges_preserve_only_disjoint_word_hints(destination, unchanged):
    program, candidates = straight_program(
        [instruction("write", "MSTORE", operands=["destination", "other"])]
    )
    candidates["destination"] = hex(destination)
    hints = unverified_constant_hints(program, candidates)
    assert ("loaded" not in hints) == unchanged
    resolved = resolve_constants(program, candidates)
    # A contradicted native hint and a separately established replacement stay distinct.
    if destination == 128:
        assert program.constant_hints["loaded"] == "0x11223344"
        assert resolved["loaded"] == program.derived_constants["loaded"] == "0x7"
    assert program.constant_verification["initial_memory"] == "unknown"
    assert {"initialize", "write", "read"} <= set(program.constant_verification["ir_statements"])


def test_overlapping_mcopy_uses_a_snapshot():
    program, candidates = straight_program(
        [instruction("copy", "MCOPY", operands=["destination", "cell", "length"])],
        candidate=0x112233,
    )
    candidates.update(destination="0x81", length="0x20")
    assert "loaded" not in unverified_constant_hints(program, candidates)
    candidates["loaded"] = "0x11223344"
    assert "loaded" in unverified_constant_hints(program, candidates)


def test_memory_join_cannot_keep_a_fact_from_just_one_branch():
    constants = {
        "cell": "0x80",
        "word": "0x11223344",
        "other": "0x7",
        "zero": "0x0",
        "loaded": "0x11223344",
    }
    blocks = [
        Block(
            "0x0",
            [
                instruction("store", "MSTORE", operands=["cell", "word"]),
                instruction("input", "CALLDATALOAD", ["flag"], ["zero"]),
                instruction("branch", "JUMPI", operands=["then_target", "flag"]),
            ],
            ["then", "join"],
            ["join"],
        ),
        Block(
            "then",
            [
                instruction("replace", "MSTORE", operands=["cell", "other"]),
                instruction("jump", "JUMP", operands=["join_target"]),
            ],
            ["join"],
            [],
        ),
        Block(
            "join",
            [instruction("read", "MLOAD", ["loaded"], ["cell"]), instruction("end", "STOP")],
            [],
            [],
        ),
    ]
    program = Program(
        constants,
        {"then_target": "then", "join_target": "join"},
        [Function("0x0", ["0x0"], [], None, [], [b.id for b in blocks])],
        blocks,
        [],
        [],
    )
    assert "loaded" in unverified_constant_hints(program, constants)
    assert "loaded" not in resolve_constants(program, constants)
    assert "loaded" not in program.derived_constants


def test_private_call_proofs_are_context_sensitive_and_use_return_edges():
    constants = {
        "cell": "0x80",
        "word": "0x11223344",
        "other": "0x7",
        "zero": "0x0",
        "child_target": "0x100",
        "argument": "0x11223344",
        "loaded": "0x11223344",
        "first": "0x11223344",
        "second": "0x11223344",
    }
    blocks = [
        Block(
            "0x0",
            [instruction("first_call", "CALLPRIVATE", ["first"], ["child_target", "word"])],
            [],
            [],
        ),
        Block(
            "next",
            [instruction("second_call", "CALLPRIVATE", ["second"], ["child_target", "other"])],
            [],
            [],
        ),
        Block("end", [instruction("stop", "STOP")], [], []),
        Block(
            "child",
            [
                instruction("store", "MSTORE", operands=["cell", "argument"]),
                instruction("read", "MLOAD", ["loaded"], ["cell"]),
                instruction("return", "RETURNPRIVATE", operands=["zero", "loaded"]),
            ],
            [],
            [],
        ),
    ]
    functions = [
        Function("0x0", ["0x0"], [], None, [], ["0x0", "next", "end"]),
        Function("child", ["child"], [], None, ["argument"], ["child"]),
    ]
    program = Program(constants, {}, functions, blocks, [], [])
    hints = unverified_constant_hints(
        program,
        constants,
        [("0x0", "child"), ("next", "child")],
        [("0x0", "child", "next"), ("next", "child", "end")],
    )
    assert "first" not in hints
    assert {"argument", "loaded", "second"} <= hints.keys()
    resolved = resolve_constants(
        program,
        constants,
        [("0x0", "child"), ("next", "child")],
        [("0x0", "child", "next"), ("next", "child", "end")],
    )
    assert resolved["second"] == "0x7"
    assert {"argument", "loaded"}.isdisjoint(program.derived_constants)


def test_an_opaque_caller_invalidates_its_callees_global_value_hints():
    constants = {
        "one": "0x1",
        "two": "0x2",
        "zero": "0x0",
        "target": "0x100",
        "opaque_target": "0x200",
        "argument": "0x1",
    }
    blocks = [
        Block("0x0", [instruction("first", "CALLPRIVATE", ["answer"], ["target", "one"])], [], []),
        Block("next", [instruction("unmodeled", "CALLPRIVATE", [], ["opaque_target"])], [], []),
        Block("end", [instruction("stop", "STOP")], [], []),
        Block(
            "child", [instruction("ret", "RETURNPRIVATE", operands=["zero", "argument"])], [], []
        ),
        Block(
            "opaque",
            [
                instruction("another_context", "CALLPRIVATE", ["other_answer"], ["target", "two"]),
                instruction("ambiguous", "JUMP", operands=["unknown_jump"]),
            ],
            ["left", "right"],
            [],
        ),
        Block("left", [instruction("left_stop", "STOP")], [], []),
        Block("right", [instruction("right_stop", "STOP")], [], []),
    ]
    program = Program(
        constants,
        {},
        [
            Function("0x0", ["0x0"], [], None, [], ["0x0", "next", "end"]),
            Function("child", ["child"], [], None, ["argument"], ["child"]),
            Function("opaque", ["opaque"], [], None, [], ["opaque", "left", "right"]),
        ],
        blocks,
        [],
        [],
    )
    child = next(b for b in blocks if b.id == "child")
    child.instructions = [
        instruction("flag", "CALLDATALOAD", ["flag"], ["zero"]),
        instruction("branch", "JUMPI", operands=["bad_target", "flag"]),
    ]
    child.successors, child.fallthrough = ["child_bad", "child_ret"], ["child_ret"]
    blocks.extend(
        [
            Block(
                "child_ret",
                [instruction("ret", "RETURNPRIVATE", operands=["zero", "argument"])],
                [],
                [],
            ),
            Block(
                "child_bad",
                [
                    instruction("save", "MSTORE", operands=["zero", "argument"]),
                    instruction("child_revert", "REVERT", operands=["zero", "word_size"]),
                ],
                [],
                [],
            ),
        ]
    )
    program.functions[1].blocks = ["child", "child_bad", "child_ret"]
    program.block_targets["bad_target"] = "child_bad"
    constants["word_size"] = "0x20"
    resolved = resolve_constants(
        program,
        constants,
        [("0x0", "child"), ("next", "opaque"), ("opaque", "child")],
        [("0x0", "child", "next"), ("next", "opaque", "end")],
    )
    assert resolved["answer"] == "0x1"  # This particular known invocation remains useful.
    assert "argument" not in resolved  # The opaque path can invoke it with 2.
    assert program.constant_hints["argument"] == "0x1"
    assert "child_revert" not in program.revert_memory
