import json
from pathlib import Path

from reconstruction.controlflow import Region, structure_function
from reconstruction.model import Block, Function, Instruction, Program, load_program
from reconstruction.recovered import render_recovered
from reconstruction_tests.memory_links import write_links
from src.tac_schema import TACRelations

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


def fixture_program(stem, directory):
    data = {}
    for suffix in ("relations", "semantic"):
        data.update(json.loads((FIXTURES / f"{stem}.{suffix}.json").read_text()))
    TACRelations(data).write_dir(directory)
    (Path(directory) / "bytecode.hex").write_text((FIXTURES / f"{stem}.hex").read_text())
    write_links(Path(directory), FIXTURES / stem)
    return load_program(directory)


def descendants(region: Region):
    yield region
    for child in region.children:
        yield from descendants(child)


def test_precise_branch_merge_has_predecessor_specific_assignments(tmp_path):
    program = fixture_program("storage-via-ir", tmp_path)
    function = next(f for f in program.functions if "0xf6e00e0f" in f.selectors)
    plan = structure_function(program, function)
    assert plan.region is not None and not plan.unresolved_phis
    assert len(plan.resolved_phis) == 2
    values = {copy.source for copies in plan.copies.values() for copy in copies}
    assert {"0x79", "0x91"} <= values
    text, source_map = render_recovered(program, structure_flow=True)
    assert "simultaneous PHI edge assignment" in text
    assert "phi_unordered" not in text
    assert "goto " not in text
    assert "tailcall selector_" in text
    assert "evm.callprivate" not in text
    assert all(item["status"] == "structured" for item in source_map["control_flow"])


def test_native_loop_plans_preserve_all_reachable_blocks(tmp_path):
    for stem in ("control-flow-optimized", "control-flow-via-ir"):
        program = fixture_program(stem, tmp_path / stem)
        loop_count = 0
        for function in program.functions:
            plan = structure_function(program, function)
            assert plan.region is not None, plan.warnings
            assert not plan.unresolved_phis, plan.warnings
            nodes = list(descendants(plan.region))
            represented = {node.block for node in nodes if node.kind == "block"}
            assert represented == plan.reachable_blocks
            loop_count += sum(node.kind == "loop" for node in nodes)
        assert loop_count >= 5  # sum, persist, swap and the two nested loops.
        text, source_map = render_recovered(program, structure_flow=True)
        assert "while (true)" in text and "continue;" in text
        assert "break;" in text
        assert "phi_unordered" not in text
        assert "goto " not in text
        ids = {stmt.id for block in program.blocks for stmt in block.instructions}
        assert all(set(line["ir_statements"]) <= ids for line in source_map["lines"])


def test_ambiguous_phi_is_retained_instead_of_guessed(tmp_path):
    program = fixture_program("storage-via-ir", tmp_path)
    phi, pred, _value = program.phi_inputs[0]
    statement = next(s for b in program.blocks for s in b.instructions if s.id == phi)
    alternative = next(
        variable
        for variable in statement.operands
        if (phi, pred, variable) not in program.phi_inputs
    )
    program.phi_inputs.append((phi, pred, alternative))
    function = next(f for f in program.functions if "0xf6e00e0f" in f.selectors)
    plan = structure_function(program, function)
    assert phi in plan.unresolved_phis and phi not in plan.resolved_phis
    text, source_map = render_recovered(program, structure_flow=True)
    assert "UNCERTAIN" in text and "phi_unordered" in text
    assert any(item["status"] == "structured-partial" for item in source_map["control_flow"])


def test_irreducible_cycle_stays_explicit():
    def branch(ident, destination, zero):
        stmt = Instruction(ident, "JUMPI", [], [destination, "condition"], [ident])
        return Block(ident, [stmt], [destination, zero], [zero])

    blocks = [
        branch("entry", "a", "b"),
        branch("a", "b", "exit"),
        branch("b", "a", "exit"),
        Block("exit", [Instruction("return", "STOP", [], [], [])], [], []),
    ]
    function = Function("fn", ["entry"], [], None, [], [b.id for b in blocks])
    program = Program({}, {"a": "a", "b": "b"}, [function], blocks, [], [])
    plan = structure_function(program, function)
    assert plan.region is None
    assert any("cycle" in warning for warning in plan.warnings)


def test_unknown_multi_destination_jump_stays_explicit():
    jump = Instruction("jump", "JUMP", [], ["dynamic"], [])
    blocks = [
        Block("entry", [jump], ["one", "two"], []),
        Block("one", [Instruction("s1", "STOP", [], [], [])], [], []),
        Block("two", [Instruction("s2", "STOP", [], [], [])], [], []),
    ]
    function = Function("fn", ["entry"], [], None, [], [b.id for b in blocks])
    plan = structure_function(Program({}, {}, [function], blocks, [], []), function)
    assert plan.region is None and "Multiple jump outcomes" in plan.warnings[0]


def test_phi_at_function_entry_needs_an_external_frame_value():
    phi = Instruction("phi", "PHI", ["merged"], ["initial", "next"], [])
    header = Block(
        "header",
        [phi, Instruction("test", "JUMPI", [], ["exit", "condition"], [])],
        ["body", "exit"],
        ["body"],
    )
    body = Block("body", [Instruction("back", "JUMP", [], ["header"], [])], ["header"], [])
    exit_block = Block("exit", [Instruction("stop", "STOP", [], [], [])], [], [])
    function = Function("fn", ["header"], [], None, ["initial"], ["header", "body", "exit"])
    program = Program(
        {},
        {"header": "header", "exit": "exit"},
        [function],
        [header, body, exit_block],
        [],
        [],
        phi_inputs=[("phi", "body", "next")],
    )
    plan = structure_function(program, function)
    assert "phi" in plan.unresolved_phis
    assert "phi" not in plan.resolved_phis


def _dispatcher_with_fallback_jump(fallback_selectors):
    """Old solc dispatch segment: no selector matched -> PUSH2 <fallback>; JUMP."""
    blocks = [
        Block(
            "0x0",
            [
                Instruction("0x1", "CONST", ["target"], [], []),
                Instruction("0x2", "CALLDATASIZE", ["size"], [], []),
                Instruction("0x3", "JUMPI", [], ["target", "size"], []),
            ],
            ["0x10", "0x8"],
            ["0x8"],
        ),
        # The native CFG has no edge into the other function's entry.
        Block(
            "0x8",
            [
                Instruction("0x9", "CONST", ["fallback"], [], []),
                Instruction("0xc", "JUMP", [], ["fallback"], []),
            ],
            [],
            [],
        ),
        Block("0x10", [Instruction("0x11", "STOP", [], [], [])], [], []),
        Block("0x40", [Instruction("0x41", "STOP", [], [], [])], [], []),
    ]
    dispatcher = Function("0x0", ["0x0"], [], None, [], ["0x0", "0x8", "0x10"])
    fallback = Function("0x40", ["0x40"], fallback_selectors, None, [], ["0x40"])
    program = Program(
        {"target": "0x10", "fallback": "0x40"}, {}, [dispatcher, fallback], blocks, [], []
    )
    return program, dispatcher


def test_jump_into_public_entry_is_a_tail_call_only_when_opted_in():
    program, dispatcher = _dispatcher_with_fallback_jump(["0x00000000"])
    plan = structure_function(program, dispatcher, public_tail_jumps=True)
    assert plan.region is not None and not plan.warnings
    assert plan.transfers["0x8"].kind == "end" and plan.transfers["0x8"].callee == "0x40"
    # Older views do not lift tail jumps: they keep the explicit CFG.
    plain = structure_function(program, dispatcher)
    assert plain.region is None and "Multiple jump outcomes" in plain.warnings[0]
    # A private (selector-less) target is not a public entry.
    program, dispatcher = _dispatcher_with_fallback_jump([])
    plan = structure_function(program, dispatcher, public_tail_jumps=True)
    assert plan.region is None
