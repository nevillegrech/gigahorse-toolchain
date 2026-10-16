"""Check saved loop values against original compiler output and rendered operands."""

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_hash.auto import keccak

from reconstruction.projection import ProjectedMachine
from reconstruction.recovered import render_recovered
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import stack_number

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"


@pytest.mark.parametrize("variant", ["optimized", "via-ir"])
def test_loop_snapshots_match_evm(variant, tmp_path, monkeypatch, record_property):
    stem = "expression-" + variant
    manifest = json.loads((FIXTURES / f"{stem}.json").read_text())
    assert (
        hashlib.sha256((FIXTURES / manifest["source"]).read_bytes()).hexdigest()
        == manifest["source_sha256"]
    )
    assert (
        hashlib.sha256(bytes.fromhex((FIXTURES / f"{stem}.hex").read_text())).hexdigest()
        == manifest["bytecode_sha256"]
    )
    program = fixture_program(stem, tmp_path)
    recovered = {selector for function in program.functions for selector in function.selectors}
    assert {"0x" + value for value in manifest["method_identifiers"].values()} <= recovered
    reference = EVMReference(manifest)
    writes = []
    computation_type = reference.backend.chain.get_vm().state.computation_class
    original = computation_type.opcodes[0x55]

    class CaptureWrite:
        mnemonic = original.mnemonic

        def __call__(self, computation):
            if computation.msg.depth == 0:
                writes.append(
                    (
                        stack_number(computation._stack.values[-1]),
                        stack_number(computation._stack.values[-2]),
                    )
                )
            original(computation=computation)

    monkeypatch.setitem(computation_type.opcodes, 0x55, CaptureWrite())

    class CheckedMachine(ProjectedMachine):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.writes = []

        def _instruction(self, stmt, block_id):
            if stmt.opcode == "SSTORE":
                self.writes.append(tuple(self._value(v) for v in stmt.operands))
            super()._instruction(stmt, block_id)

    cases = 0
    checks = paths = 0

    def check(signature, arguments, expected=None, expected_storage=None):
        nonlocal cases, checks, paths
        data = bytes.fromhex(manifest["method_identifiers"][signature]) + encode(
            ["uint256"] * len(arguments), arguments
        )
        writes.clear()
        output, reverted = reference.call(data)
        observed_state = dict(writes)
        if expected is not None:
            assert not reverted and int.from_bytes(output) == expected
        for mode in (False, True):
            machine = CheckedMachine(program, structured=mode)
            actual = machine.execute(data, caller=int(reference.sender, 16))
            assert (actual.output, actual.reverted) == (output, reverted), (signature, arguments)
            assert machine.writes == writes
            assert actual.storage == ({} if reverted else observed_state)
            checks += machine.expression_checks
            paths += machine.storage_path_checks
            if expected_storage is not None:
                assert actual.storage == expected_storage
        if expected_storage is not None:
            assert reference.commit(data) == 1
            assert all(reference.storage(k) == v for k, v in expected_storage.items())
        cases += 1

    mask = (1 << 256) - 1
    for n in (1, 2, 3, 8):
        for seed in (0, 17, mask):
            check(
                "captureConditional(uint256,uint256)",
                [n, seed],
                seed ^ 0xA5,
                {0: seed ^ (n - 1)},
            )
            check(
                "captureFirst(uint256,uint256)",
                [n, seed],
                seed ^ 0xA5,
                {0: ((seed + n - 1) & mask) ^ 0xA5},
            )
            for which in (0, n - 1):
                slot = int.from_bytes(keccak((seed ^ which).to_bytes(32) + (11).to_bytes(32)))
                check(
                    "captureMapping(uint256,uint256,uint256)",
                    [n, which, seed],
                    seed,
                    {0: seed ^ (n - 1), slot: seed},
                )
    for n in (0, 9, mask):
        check("captureFirst(uint256,uint256)", [n, 17])
        check("captureMapping(uint256,uint256,uint256)", [n, n, 17])
    text, mapping = render_recovered(program, structure_flow=True)
    assert all(f["status"] == "structured" for f in mapping["control_flow"])
    assert "while (true)" in text
    assert "A stored word may precede a later execution" in text
    for signature in ("captureFirst(uint256,uint256)", "captureConditional(uint256,uint256)"):
        selector = "0x" + manifest["method_identifiers"][signature]
        function = next(f for f in program.functions if selector in f.selectors)
        layout = next(r for r in program.return_layouts if r.function == function.id)
        assert layout.status == "unresolved" and not layout.words
    record_property("evm_contract_cases", cases)
    record_property("printed_expression_checks", checks)
    record_property("printed_storage_path_checks", paths)
    record_property("fixture", stem)
    record_property("bytecode_sha256", manifest["bytecode_sha256"])
    record_property(
        "facts_sha256",
        hashlib.sha256(
            (FIXTURES / f"{stem}.relations.json").read_bytes()
            + (FIXTURES / f"{stem}.semantic.json").read_bytes()
        ).hexdigest(),
    )
