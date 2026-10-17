"""Vyper dispatchers (linear checks, selector tables), executed against Py-EVM."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction_tests.decompiled_support import compiler_fixture
from reconstruction_tests.test_decompiled_execution import Harness
from reconstruction_tests.test_execution import EVMReference
from src.selector_table import selector_table

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/reconstruction"
VARIANTS = ["v0216", "v039", "v0310", "v0310-codesize"]
_spec = importlib.util.spec_from_file_location("heldout", ROOT / "scripts/evaluate-heldout.py")
heldout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(heldout)


def _manifest(variant):
    return json.loads((FIXTURES / f"vyper-{variant}.json").read_text())


def _fixture(variant, tmp_path):
    program, decompiled = compiler_fixture(f"vyper-{variant}", tmp_path / variant)
    return _manifest(variant), program, decompiled


def _code(stem):
    return bytes.fromhex((FIXTURES / f"{stem}.hex").read_text().strip().removeprefix("0x"))


def _dispatcher(text):
    return re.search(r"function __function_selector__\(\) private \{\n(.*?)\n    \}", text, re.S)[1]


def test_selector_tables_are_found_by_executing_the_dispatcher():
    ids = {int(s, 16) for s in _manifest("v0310")["method_identifiers"].values()}
    # Linear dispatchers (and solc) jump to pushed addresses only: nothing to resolve.
    for stem in ("vyper-v0216", "vyper-v039", "parameter-optimized", "decoder-via-ir"):
        table = selector_table(_code(stem))
        assert not table.jumps and not table.entries, stem
    # Sparse ("gas"): every selector reaches one bucket jump; its targets are the buckets.
    sparse = selector_table(_code("vyper-v0310"))
    assert len(sparse.jumps) == 1 and not sparse.entries
    assert sparse.routed == ids and sparse.fallback_reverts
    # A fallback that does anything but revert(0, 0) (here: STOP) is not vouched for,
    # so the dispatcher is not printed as a chain ending in revert().
    halting = _code("vyper-v0310").hex().replace("5b5f5ffd", "5b5f5f00")
    assert not selector_table(bytes.fromhex(halting)).fallback_reverts
    # Dense ("codesize"): only real selectors reach the jump, each to its own handler,
    # with the dispatcher's own checks (value, calldata size) recovered by execution.
    dense = selector_table(_code("vyper-v0310-codesize"))
    selectors = {selector for _, selector, _ in dense.entries}
    assert selectors == ids and dense.routed == ids and dense.fallback_reverts
    payable = {selector for _, selector, flag in dense.entries if flag}
    assert payable == {int(_manifest("v0310")["method_identifiers"]["deposit()"], 16)}
    sizes = {
        s: dense.min_sizes[int(i, 16)] for s, i in _manifest("v0310")["method_identifiers"].items()
    }
    assert sizes["owner()"] == 4 and sizes["transfer(address,uint256)"] == 68
    assert sizes["add_liquidity(uint256[2],uint256)"] == 100


@pytest.mark.parametrize("variant", VARIANTS)
def test_every_vyper_function_is_recovered_without_wrong_claims(variant, tmp_path):
    manifest, _, decompiled = _fixture(variant, tmp_path)
    text, ids = decompiled.text, manifest["method_identifiers"]
    score = heldout.score(heldout.parse_view(text), heldout.abi_functions(manifest["abi"]))
    assert score["selectors_recovered"] == len(ids) == 13
    assert score["wrong_claims"] == []
    assert score["payability"]["correct"] == len(ids)
    # A static array parameter from the dictionary signature is one parameter.
    assert "function add_liquidity(uint256[2] varg0, uint256 varg2) public nonpayable" in text
    assert "varg0[1]" in text
    dispatcher = _dispatcher(text)
    if variant.startswith("v0310"):
        # The table lookup prints as the selector chain executing it established.
        assert "Selector table (rule selector-table)" in dispatcher
        assert "not structured" not in dispatcher and "Selector table (Vyper 0.3.10+)" in text
        assert dispatcher.count("if (msg.sig == ") == len(ids)
    else:
        assert "Selector table" not in text
    if variant == "v0216":
        # One value check after the payable function covers every later selector.
        assert dispatcher.index("deposit()") < dispatcher.index("require(!msg.value);")


@pytest.mark.parametrize("variant", VARIANTS)
def test_vyper_fixture_view_matches_evm(variant, tmp_path, monkeypatch, record_property):
    manifest, _, decompiled = _fixture(variant, tmp_path)
    reference = EVMReference(manifest)
    owner, other = reference.tester.get_accounts()[:2]
    initial = {slot: reference.storage(slot) for slot in range(8) if reference.storage(slot)}
    harness = Harness(decompiled, reference, initial, monkeypatch)
    ids = manifest["method_identifiers"]

    def call(signature, types=(), values=(), *, sender=owner, value=0):
        data = bytes.fromhex(ids[signature]) + encode(list(types), list(values))
        harness.check(data, sender=sender, value=value)

    call("deposit()", value=10)
    call("deposit()", value=5, sender=other)
    call("transfer(address,uint256)", ["address", "uint256"], [other, 4])
    call("transfer(address,uint256)", ["address", "uint256"], [other, 400])  # underflow
    call("transfer(address,uint256)", ["address", "uint256"], [other, 1], value=1)  # value
    call("set_fee(uint256)", ["uint256"], [7])
    call("set_fee(uint256)", ["uint256"], [700])  # over 100
    call("set_fee(uint256)", ["uint256"], [5], sender=other)  # not the owner
    for amount, i in ((1000, -1), (1000, 2), (0, 0)):
        call("quote(uint256,int128)", ["uint256", "int128"], [amount, i])
    for x, y in ((3, 4), (-1, 4)):  # converting a negative int128 reverts
        call("scaled(int128,uint256)", ["int128", "uint256"], [x, y])
    for first in (True, False):
        call("pick(address,address,bool)", ["address", "address", "bool"], [owner, other, first])
    call("add_liquidity(uint256[2],uint256)", ["uint256[2]", "uint256"], [[3, 4], 7])
    call("add_liquidity(uint256[2],uint256)", ["uint256[2]", "uint256"], [[3, 4], 8])
    call("add_liquidity(uint256[2],uint256)", ["uint256[2]", "uint256"], [[1, 1], 0], value=1)
    for getter in ("total()", "owner()", "fee()", "paused()"):
        call(getter)
        call(getter, value=1)  # nonpayable getters
    for account in (owner, other):
        call("balances(address)", ["address"], [account])
    call("pause(bool)", ["bool"], [True])
    call("deposit()", value=1)  # paused
    # Dirty argument words are rejected, as the compiled clamps do.
    dirty = (0xBEEF << 160) | 0x1234
    selector = bytes.fromhex(ids["transfer(address,uint256)"])
    harness.check(selector + dirty.to_bytes(32) + (1).to_bytes(32), sender=owner)
    harness.check(bytes.fromhex(ids["pause(bool)"]) + (2).to_bytes(32), sender=owner)
    # Calldata that names no function, or is too short: the dispatcher's fallback.
    for data in (bytes.fromhex("12345678"), b"\x01", b"", selector[:3]):
        harness.check(data, sender=owner)
    harness.check(selector + (1).to_bytes(32), sender=owner)  # missing an argument
    assert harness.reverts >= 12
    record_property(f"vyper_fixture_cases_{variant}", harness.cases)


def test_value_check_after_a_reentrancy_lock_makes_the_function_nonpayable():
    """Vyper 0.2 checks its @nonreentrant lock before msg.value: a call with value
    reverts without data either way, so the check still marks the function."""
    from reconstruction.highlevel.ir import Assign, Binary, Call, Const, Env, Require, Unary, Var
    from reconstruction.highlevel.passes import FunctionState, leading_callvalue_check

    lock = Var("stor_lock", None)
    value = Require(Unary("!", Env("msg.value")))

    def body(*before):
        return [*before, value, Require(Binary(">", Var("varg0", None), Const(0)))]

    prefix = (Require(Unary("!", lock)), Assign((lock,), Const(1)))
    state = FunctionState(body(*prefix))
    leading_callvalue_check(state, public=True)
    assert state.nonpayable is value and value not in state.body and len(state.body) == 3
    # Not past a call, a revert with data, or in the dispatcher (whose check stays in
    # its body to apply to what it dispatches).
    for before, public in (
        ((Assign((lock,), Call("fn_0x1", ())),), True),
        ((Require(Unary("!", lock), payload=Const(1)),), True),
        (prefix, False),
    ):
        state = FunctionState(body(*before))
        leading_callvalue_check(state, public=public)
        assert state.nonpayable is None and value in state.body
    # Merged with the calldata size check (Vyper 0.3): split, size check kept.
    merged = Require(
        Unary("!", Binary("|", Env("msg.value"), Binary("<", Env("msg.data.length"), Const(68))))
    )
    state = FunctionState([merged])
    leading_callvalue_check(state, public=True)
    assert state.nonpayable.condition == Unary("!", Env("msg.value"))
    assert state.body[0].condition == Binary(">=", Env("msg.data.length"), Const(68))
