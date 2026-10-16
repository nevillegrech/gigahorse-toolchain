"""Incomplete or inconsistent IR, and failures in one function, stay visible and local."""

from dataclasses import replace

import pytest

from reconstruction.highlevel import view as view_module
from reconstruction.highlevel.memory_liveness import ANY
from reconstruction.highlevel.view import build_decompiled
from reconstruction.model import load_program
from reconstruction_tests.decompiled_support import DEPLOYED_NEXT, deployed_fixture
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_size_limits import chained_reuse_program


def test_conflicting_ir_operand_becomes_an_unordered_phi(tmp_path):
    """A statement with two IR values for one operand is never resolved by picking one."""
    program = fixture_program("storage-via-ir", tmp_path)
    function = next(f for f in program.functions if f.selectors)
    blocks = {b.id: b for b in program.blocks}
    statements = [s for b in function.blocks for s in blocks[b].instructions]
    target = next(s for s in statements if s.opcode == "ISZERO")
    other = next(
        d
        for s in statements
        for d in s.definitions
        if s.opcode not in {"PHI", "CONST"} and d != target.operands[0]
    )
    with (tmp_path / "TAC_Use.csv").open("a") as stream:
        stream.write(f"{target.id}\t{other}\t0\n")
    changed = load_program(tmp_path)
    blocks = {b.id: b for b in changed.blocks}
    block = next(b for b in changed.blocks if any(s.id == target.id for s in b.instructions))
    rewritten = next(s for s in block.instructions if s.id == target.id)
    phi = block.instructions[0]
    assert rewritten.operands == [f"{target.id}_operand0"]
    assert phi.id == f"{target.id}_phi0" and phi.opcode == "PHI"
    assert phi.definitions == [f"{target.id}_operand0"]
    assert set(phi.operands) == {target.operands[0], other}
    assert phi.original_statements == rewritten.original_statements
    assert any(f"modeled as an unordered PHI {phi.id}" in w for w in changed.warnings)
    text = build_decompiled(changed).text
    merged = [line for line in text.splitlines() if "phi(" in line]
    assert merged and all("UNCERTAIN" in line for line in merged)


def test_store_with_a_missing_operand_stays_a_marked_raw_operation():
    program, _ = chained_reuse_program(steps=2)
    block = program.blocks[0]
    block.instructions = [
        replace(s, operands=["zero"]) if s.opcode == "MSTORE" else s for s in block.instructions
    ]
    text = build_decompiled(program).text
    line = next(line for line in text.splitlines() if "mstore(" in line)
    assert "UNCERTAIN: MSTORE has 1 of its 2 operands in the IR" in line


def test_a_failing_function_costs_only_that_function(tmp_path, monkeypatch):
    program, decompiled, _ = deployed_fixture(DEPLOYED_NEXT, "weth9", tmp_path / "relations")
    deposit = next(f for f in program.functions if f.selectors == ["0xd0e30db0"])
    original = view_module.prepare_function

    def failing(context, function):
        if function.id == deposit.id:
            raise RuntimeError("injected failure")
        return original(context, function)

    monkeypatch.setattr(view_module, "prepare_function", failing)
    with pytest.raises(RuntimeError):
        build_decompiled(program)  # tests run strict: no silent fallback
    monkeypatch.setenv("RECONSTRUCTION_STRICT", "0")
    fallback = build_decompiled(program)
    text = fallback.text
    assert "readable view not produced for this function (RuntimeError: injected failure)" in text
    assert "function deposit(/* arguments not recovered */) public /* payability unresolved */" in (
        text
    )
    # Every other function prints exactly as before.
    for view in decompiled.views:
        if view.function.id == deposit.id:
            continue
        other = next(v for v in fallback.views if v.function.id == view.function.id)
        assert repr(other.body) == repr(view.body)
    # A call into the failed function may read any memory.
    summaries = view_module.memory_summaries(fallback.context, [], {"deposit"})
    assert any(r.base == ANY for r in summaries.entry_of("deposit").ranges)
