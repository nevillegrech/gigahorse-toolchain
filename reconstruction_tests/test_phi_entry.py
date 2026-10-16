"""Entry-loop values remain distinct from the values on local back edges."""

import hashlib

import pytest

from reconstruction.constant_memory import proof_is_current
from reconstruction.constants import resolve_constants
from reconstruction.controlflow import structure_function
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction.semantics import SemanticInfo


def entry_loop_program():
    # The EVM stack at the helper entry is [return PC, limit, counter].
    return_pc, header, body, exit_pc = 13, 22, 31, 38
    runtime = (
        b"\x61"
        + return_pc.to_bytes(2)
        + bytes.fromhex("60203560003561")
        + header.to_bytes(2)
        + b"\x56"
        + bytes.fromhex("5b60005260206000f3")
        + bytes.fromhex("5b8181101561")
        + exit_pc.to_bytes(2)
        + b"\x57"
        + bytes.fromhex("60010161")
        + header.to_bytes(2)
        + b"\x56"
        + bytes.fromhex("5b90509056")
    )
    assert runtime[header] == runtime[exit_pc] == 0x5B and runtime[body] == 0x60
    h, b, e, r = map(hex, (header, body, exit_pc, return_pc))
    constants = {
        "zero": "0x0",
        "width": "0x20",
        "one": "0x1",
        "target": h,
        "body": b,
        "exit": e,
        "header": h,
    }

    def ins(name, op, defs=(), uses=(), pc=None):
        return Instruction(name, op, list(defs), list(uses), [hex(pc)] if pc is not None else [])

    blocks = [
        Block(
            "0x0",
            [
                ins("limit_load", "CALLDATALOAD", ["limit"], ["width"], 5),
                ins("start_load", "CALLDATALOAD", ["start"], ["zero"], 8),
                ins("call", "CALLPRIVATE", ["answer"], ["target", "start", "limit"], 12),
            ],
            [],
            [],
        ),
        Block(
            r,
            [
                ins("store", "MSTORE", uses=["zero", "answer"], pc=16),
                ins("return", "RETURN", uses=["zero", "width"], pc=21),
            ],
            [],
            [],
        ),
        Block(
            h,
            [
                ins("phi", "PHI", ["counter"], ["initial", "next"]),
                ins("less", "LT", ["less"], ["counter", "bound"], 25),
                ins("done", "ISZERO", ["done"], ["less"], 26),
                ins("branch", "JUMPI", uses=["exit", "done"], pc=30),
            ],
            [b, e],
            [b],
        ),
        Block(
            b,
            [
                ins("increment", "ADD", ["next"], ["counter", "one"], 33),
                ins("back", "JUMP", uses=["header"], pc=37),
            ],
            [h],
            [],
        ),
        Block(e, [ins("private_return", "RETURNPRIVATE", uses=["zero", "counter"], pc=42)], [], []),
    ]
    functions = [
        Function("root", ["0x0"], [], None, [], ["0x0", r]),
        Function("helper", [h], [], None, ["initial", "bound"], [h, b, e]),
    ]
    p = Program(
        constants,
        {"header": h, "exit": e},
        functions,
        blocks,
        [],
        [],
        phi_inputs=[("phi", b, "next")],
        runtime_bytecode=runtime.hex(),
        phi_entry_inputs=[("phi", "initial")],
    )
    calls, returns = [("0x0", "helper")], [("0x0", "helper", r)]
    p.constants = resolve_constants(p, constants, calls, returns)
    p.semantics = SemanticInfo(3, [], [], [], {}, p.constants, [], calls, returns, [])
    return p, runtime


def test_entry_loop_seeds_once_and_preserves_iterations_against_evm(record_property):
    pytest.importorskip("eth_tester")
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    p, runtime = entry_loop_program()
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    plan = structure_function(p, p.functions[1])
    assert not plan.unresolved_phis and plan.resolved_phis == {"phi"}
    assert [(c.destination, c.source) for c in plan.entry_copies] == [("counter", "initial")]
    text, mapping = render_recovered(p, structure_flow=True)
    assert "simultaneous function-entry PHI assignment" in text
    assert "phi_unordered" not in text
    assert any(x["entry_assignments"] for x in mapping["control_flow"])
    cases = [(0, 0), (0, 1), (0, 7), (3, 9), (8, 2), (255, 260)]
    for start, limit in cases:
        data = start.to_bytes(32) + limit.to_bytes(32)
        expected, reverted = reference.call(data)
        assert not reverted and int.from_bytes(expected) == max(start, limit)
        for mode in (False, True):
            actual = ProjectedMachine(p, structured=mode).execute(data)
            assert (actual.output, actual.reverted) == (expected, reverted)
    record_property("entry_phi_evm_cases", len(cases))
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


@pytest.mark.parametrize("mutation", ("missing", "ambiguous", "not_formal", "wrong_block"))
def test_entry_loop_never_guesses_a_missing_or_invalid_initial_value(mutation):
    p, _ = entry_loop_program()
    assert proof_is_current(p)
    if mutation == "missing":
        p.phi_entry_inputs.clear()
    elif mutation == "ambiguous":
        p.phi_entry_inputs.append(("phi", "bound"))
    elif mutation == "not_formal":
        p.phi_entry_inputs[:] = [("phi", "next")]
    else:
        p.functions[1].entries[:] = [hex(31)]
    plan = structure_function(p, p.functions[1])
    assert plan.unresolved_phis == ["phi"]
    assert not plan.entry_copies
    assert not proof_is_current(p)
