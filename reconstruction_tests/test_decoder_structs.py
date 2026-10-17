"""Calldata structs read through ABI decoder helpers, and selectors shared with internal code."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.highlevel.lift import ProgramContext, decoder_checks, decoder_pointer_reads
from reconstruction.highlevel.view import dispatched_selectors
from reconstruction.model import Block, Function, Program
from reconstruction_tests.decompiled_support import compiler_fixture
from reconstruction_tests.test_decompiled_execution import Harness
from reconstruction_tests.test_execution import EVMReference

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/reconstruction"
POSITION = "(address,uint24,int24,uint256,address)"
_spec = importlib.util.spec_from_file_location("heldout", ROOT / "scripts/evaluate-heldout.py")
heldout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(heldout)


def _fixture(variant, tmp_path):
    manifest = json.loads((FIXTURES / f"decoder-{variant}.json").read_text())
    program, decompiled = compiler_fixture(f"decoder-{variant}", tmp_path / variant)
    return manifest, program, decompiled


def _header(text, selector):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith(f"// 0x{selector}"))
    return next(line.strip() for line in lines[start:] if line.strip().startswith("function "))


def _struct(text, header):
    name = re.search(r"\((?:uint256 varg0, )?(S\d+) varg\d\)", header).group(1)
    return re.search(rf"^    struct {name} \{{ (.*?) \}}$", text, re.M).group(1)


def test_decoder_helper_structs_are_one_parameter(tmp_path):
    """Optimized legacy code: shared decoder helpers return the struct as a pointer."""
    manifest, program, decompiled = _fixture("optimized", tmp_path)
    text, ids = decompiled.text, manifest["method_identifiers"]
    context = ProgramContext.build(program, tmp_path / "optimized")

    def function(signature):
        return next(f for f in program.functions if f.selectors == ["0x" + ids[signature]])

    # The struct is the whole head: its check (inside the helper) equals the head check.
    opened = function(f"open({POSITION})")
    assert (4, 160) in decoder_checks(context, opened)
    assert decoder_pointer_reads(context, opened)[0] == [(0, 5)]
    # After a uint256: the struct decoder is called with its head position (36).
    shifted = function(f"shifted(uint256,{POSITION})")
    assert decoder_pointer_reads(context, shifted)[0] == [(1, 5)]
    # Every function prints one struct parameter, typed where each field is validated.
    open_header = _header(text, ids[f"open({POSITION})"])
    assert _struct(text, open_header) == "address f0; uint24 f1; int24 f2; uint256 f3; address f4;"
    assert re.search(
        r"\(uint256 varg0, S\d+ varg1\)", _header(text, ids[f"shifted(uint256,{POSITION})"])
    )
    # Fields scaled() never reads still belong to the struct its decoder checks (160 bytes);
    # a uint128 check on a uint256 field that is also used raw does not narrow it.
    scaled = _header(text, ids[f"scaled({POSITION})"])
    assert _struct(text, scaled).split("; ")[3] == "uint256 f3"
    score = heldout.score(heldout.parse_view(text), heldout.abi_functions(manifest["abi"]))
    assert score["wrong_claims"] == [] and score["selectors_recovered"] == len(ids)


def test_inlined_decoder_structs_from_where_fields_are_validated(tmp_path):
    """via-IR inlines the decoder: a struct that is not the whole head has its own
    check; a whole-head struct is known from fields validated where they are read."""
    manifest, _, decompiled = _fixture("via-ir", tmp_path)
    text, ids = decompiled.text, manifest["method_identifiers"]
    for name in ("open", "quote"):
        header = _header(text, ids[f"{name}({POSITION})"])
        assert re.search(r"\(S\d+ varg0\)", header), header
    assert _struct(text, _header(text, ids[f"open({POSITION})"])) == (
        "address f0; uint24 f1; int24 f2; uint256 f3; address f4;"
    )
    assert re.search(
        r"\(uint256 varg0, S\d+ varg1\)", _header(text, ids[f"shifted(uint256,{POSITION})"])
    )
    # A uint128 check at entry is indistinguishable from a decoder validator: no struct is
    # inferred for scaled(), and its amount word is not narrowed by the check.
    scaled = _header(text, ids[f"scaled({POSITION})"])
    assert "uint128" not in scaled


@pytest.mark.parametrize("variant", ["optimized", "via-ir"])
def test_decoder_fixture_view_matches_evm(variant, tmp_path, monkeypatch, record_property):
    manifest, _, decompiled = _fixture(variant, tmp_path)
    reference = EVMReference(manifest)
    owner, other = reference.tester.get_accounts()[:2]
    harness = Harness(decompiled, reference, {}, monkeypatch)
    ids = manifest["method_identifiers"]

    def call(signature, types, values):
        harness.check(bytes.fromhex(ids[signature]) + encode(types, values), sender=owner)

    def raw(signature, words):
        data = bytes.fromhex(ids[signature]) + b"".join(w.to_bytes(32) for w in words)
        harness.check(data, sender=owner)

    position = [POSITION]
    for amount in (0, 7, 2**130):
        for tick in (-5, 0, 2**23 - 1):
            call(f"open({POSITION})", position, [(owner, 3000, tick, amount, other)])
    call("credit(address)", ["address"], [other])
    call("credit(address)", ["address"], [owner])
    dirty = (0xBEEF << 160) | 0x1234
    clean = [int(owner, 16), 500, 7, 9, int(other, 16)]
    # Each field validated as the EVM does: a dirty word reverts where the field is read.
    for index, bad in ((0, dirty), (1, 1 << 30), (2, 1 << 40), (4, dirty)):
        words = list(clean)
        words[index] = bad
        raw(f"open({POSITION})", words)
        raw(f"scaled({POSITION})", words)
    # quote() reads the recipient only when amount > 100: a dirty recipient reverts only then.
    for amount in (5, 101):
        words = list(clean)
        words[3], words[4] = amount, dirty
        raw(f"quote({POSITION})", words)
        words[4] = int(other, 16)
        raw(f"quote({POSITION})", words)
    for bonus in (0, 11):
        call(
            f"shifted(uint256,{POSITION})",
            ["uint256", *position],
            [bonus, (owner, 1, -1, 3, other)],
        )
    raw(f"shifted(uint256,{POSITION})", [1, dirty, 1, 1, 1, 1])
    for amount in (0, 2**127, 2**128, 2**200):
        words = list(clean)
        words[3] = amount
        raw(f"scaled({POSITION})", words)
    raw(f"open({POSITION})", clean[:3])  # short calldata: the decoder's bounds check
    assert harness.reverts >= 8
    record_property(f"decoder_fixture_cases_{variant}", harness.cases)


def _program(functions):
    return Program({}, {}, functions, [Block("0x0", [], [], [])], [], [])


def test_a_selector_shared_with_an_internal_function_stays_with_the_entry():
    """The dispatcher passes no stack arguments; a claimant with formals is internal."""
    entry = Function("0x2b2", ["0x2b2"], ["0x52bbbe29"], None, [], ["0x0"])
    internal = Function("0x496a", ["0x496a"], ["0x52bbbe29"], None, ["a", "b", "c", "d"], ["0x0"])
    result = dispatched_selectors(_program([entry, internal]))
    assert [f.selectors for f in result.functions] == [["0x52bbbe29"], []]
    assert [f.selectors for f in _program([entry, internal]).functions][1] == ["0x52bbbe29"]
    # No single argument-free claimant (or no second claimant): nothing to decide.
    twin = Function("0x3ff", ["0x3ff"], ["0x52bbbe29"], None, [], ["0x0"])
    unchanged = _program([entry, twin, internal])
    assert dispatched_selectors(unchanged) is unchanged
    alone = _program([internal])
    assert dispatched_selectors(alone) is alone
