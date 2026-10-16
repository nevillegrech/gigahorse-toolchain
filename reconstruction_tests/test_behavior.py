"""Behavior summaries must retain ambiguous or unproved cases explicitly."""

from copy import deepcopy

import pytest

from reconstruction.behavior import analyze_behavior
from reconstruction.controlflow import plan_metadata, structure_function
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.recovered import render_recovered
from reconstruction.semantics import StorageField
from reconstruction_tests.test_evaluation import evaluation_program


@pytest.mark.parametrize("opcode", ["RETURN", "REVERT", "STOP", "SELFDESTRUCT", "INVALID"])
def test_evm_halt_ignores_continuation_and_preserves_original_edge(opcode):
    blocks = [
        Block("entry", [Instruction("halt", opcode, [], [], ["0x10"])], ["after"], []),
        Block("after", [Instruction("stop", "STOP", [], [], ["0x11"])], [], []),
    ]
    function = Function("fn", ["entry"], [], None, [], [b.id for b in blocks])
    program = Program({}, {}, [function], blocks, [], [])
    plan = structure_function(program, function)
    assert plan.region is not None and plan.reachable_blocks == {"entry"}
    assert plan.transfers["entry"].targets == ()
    assert plan.transfers["entry"].ignored_terminal_targets == ("after",)
    assert blocks[0].successors == ["after"]
    metadata = plan_metadata(plan)
    assert metadata["transfers"]["entry"]["statement"] == "halt"
    assert metadata["warnings"]


def test_internal_return_with_successors_remains_uncertain():
    blocks = [
        Block("entry", [Instruction("return", "RETURNPRIVATE", [], [], [])], ["after"], []),
        Block("after", [Instruction("stop", "STOP", [], [], [])], [], []),
    ]
    function = Function("fn", ["entry"], [], None, [], [b.id for b in blocks])
    plan = structure_function(Program({}, {}, [function], blocks, [], []), function)
    assert plan.region is None and "has successors" in plan.warnings[0]


def test_deployed_proxy_has_observed_roles_and_forwarding_evidence(tmp_path):
    program, _ = evaluation_program(tmp_path, "usdc-proxy")
    behavior = program.behavior
    assert len(behavior.storage_roles) == 2
    assert {r.alias for r in behavior.storage_roles} == {
        "role_delegate_target_word",
        "role_caller_check_word",
    }
    assert len(behavior.delegate_sites) == 6
    for site in behavior.delegate_sites:
        assert site.whole_calldata and site.return_data_forwarding == "established_in_recovered_cfg"
        assert site.caller_gates and all(g["comparison"] == "not-equal" for g in site.caller_gates)
    text, mapping = render_recovered(program, structure_flow=True)
    assert all(f["status"] == "structured" for f in mapping["control_flow"])
    assert "Caller check on this path: msg.sender != low160(role_caller_check_word)" in text
    assert "role_delegate_target_word =" in text
    assert "proxy_admin" not in text and "upgradeTo" not in text
    instructions = {s.id for b in program.blocks for s in b.instructions}
    assert all(set(s.evidence) <= instructions for s in behavior.delegate_sites)
    assert all(set(r.evidence) <= instructions for r in behavior.storage_roles)
    assert (
        sum(
            bool(t["ignored_terminal_targets"])
            for f in mapping["control_flow"]
            for t in f["transfers"].values()
        )
        == 5
    )


@pytest.mark.parametrize(
    "fault",
    [
        "input-overwrite",
        "output-overwrite",
        "stale-size",
        "inverted-outcome",
        "unknown-target",
        "high-bits-target",
    ],
)
def test_proxy_summary_does_not_hide_missing_proof(tmp_path, fault):
    program, _ = evaluation_program(tmp_path, "usdc-proxy")
    function = next(f for f in program.functions if f.selectors == ["0x00000000"])
    blocks = {b.id: b for b in program.blocks}
    block = next(
        blocks[b]
        for b in function.blocks
        if any(s.opcode == "DELEGATECALL" for s in blocks[b].instructions)
    )
    call = next(s for s in block.instructions if s.opcode == "DELEGATECALL")
    zero = call.operands[2]
    if fault == "input-overwrite":
        block.instructions.insert(
            block.instructions.index(call), Instruction("clobber", "MSTORE", [], [zero, zero], [])
        )
    elif fault == "output-overwrite":
        copy = next(s for s in block.instructions if s.opcode == "RETURNDATACOPY")
        block.instructions.insert(
            block.instructions.index(copy) + 1,
            Instruction("clobber", "MSTORE", [], [zero, zero], []),
        )
    elif fault == "stale-size":
        size = next(s for s in block.instructions if s.opcode == "RETURNDATASIZE")
        block.instructions.remove(size)
        block.instructions.insert(block.instructions.index(call), size)
    elif fault == "inverted-outcome":
        branch = block.instructions[-1]
        branch.operands[1] = call.definitions[0]  # Original branch is EQ(success, 0).
    elif fault == "unknown-target":
        call.operands[1] = "unknown_target"
    else:
        target = call.operands[1]
        program.semantics.constants["high_mask"] = hex(1 << 200)
        block.instructions.insert(
            block.instructions.index(call),
            Instruction("mask-target", "AND", ["masked_target"], [target, "high_mask"], []),
        )
        call.operands[1] = "masked_target"
    site = next(s for s in analyze_behavior(program).delegate_sites if s.statement == call.id)
    if fault == "input-overwrite":
        assert site.whole_calldata is None
    elif fault in {"unknown-target", "high-bits-target"}:
        assert site.target_slot is None
    else:
        assert site.return_data_forwarding == "unresolved"
    assert site.limitations


def test_role_alias_does_not_merge_overlapping_storage_declarations(tmp_path):
    program, _ = evaluation_program(tmp_path, "usdc-proxy")
    field = deepcopy(program.semantics.storage_fields[0])
    program.semantics.storage_fields.append(
        StorageField(
            "packed", "storage", field.slot, "TightlyPackedVariable", 0, 19, ["address"], []
        )
    )
    behavior = analyze_behavior(program)
    assert next(r for r in behavior.storage_roles if r.slot == field.slot).alias is None
    assert program.semantics.storage_fields[0] == field


def test_caller_comparison_is_not_a_gate_when_both_arms_reach_delegation(tmp_path):
    program, _ = evaluation_program(tmp_path, "usdc-proxy")
    function = next(f for f in program.functions if f.selectors == ["0x00000000"])
    check = next(c for c in program.behavior.caller_checks if c.function == function.id)
    blocks = {b.id: b for b in program.blocks}
    branch = structure_function(program, function).transfers[check.block]
    failure = next(t for t in branch.targets if blocks[t].instructions[-1].opcode == "REVERT")
    continuation = next(t for t in branch.targets if t != failure)
    blocks[failure].instructions = [Instruction("bypass", "JUMP", [], ["continuation"], [])]
    blocks[failure].successors = [continuation]
    blocks[failure].fallthrough = []
    program.block_targets["continuation"] = continuation
    site = next(s for s in analyze_behavior(program).delegate_sites if s.function == function.id)
    assert site.whole_calldata and not site.caller_gates
