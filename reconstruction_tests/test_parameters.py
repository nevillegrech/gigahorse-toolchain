"""Parameter layouts and 160-bit types: printed as the code proves, executed against Py-EVM."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode

from reconstruction.highlevel.lift import ProgramContext, decoder_head_size
from reconstruction.highlevel.naming import Dictionary, load_names
from reconstruction.highlevel.view import build_decompiled, collect_keys
from reconstruction_tests.decompiled_support import compiler_fixture
from reconstruction_tests.test_decompiled_execution import Harness
from reconstruction_tests.test_execution import EVMReference

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/reconstruction"
VARIANTS = ["optimized", "via-ir"]
SETTLE = "settle(address,(address,address,uint256,uint256),uint256)"
_spec = importlib.util.spec_from_file_location("heldout", ROOT / "scripts/evaluate-heldout.py")
heldout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(heldout)


def _fixture(variant, tmp_path):
    manifest = json.loads((FIXTURES / f"parameter-{variant}.json").read_text())
    program, decompiled = compiler_fixture(f"parameter-{variant}", tmp_path / variant)
    return manifest, program, decompiled


def _selector(manifest, signature):
    return bytes.fromhex(manifest["method_identifiers"][signature])


def _header(text, selector):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith(f"// 0x{selector}"))
    return next(line.strip() for line in lines[start:] if line.strip().startswith("function "))


@pytest.mark.parametrize("variant", VARIANTS)
def test_view_claims_are_right_against_the_abi(variant, tmp_path):
    manifest, _, decompiled = _fixture(variant, tmp_path)
    text = decompiled.text
    ids = manifest["method_identifiers"]
    # Static struct parameters: one parameter each (four head words), fields in the body.
    assert re.search(r" S\d+ varg1, uint256 varg5\)", _header(text, ids[SETTLE]))
    assert re.search(
        r"\(S\d+ varg0, uint256 varg4\)",
        _header(text, ids["settleMemory((address,address,uint256,uint256),uint256)"]),
    )
    assert "struct S0 {" in text and "varg1.f2" in text
    # A word read past the one-word head is not a parameter.
    tail = _header(text, ids["tail(bytes)"])
    assert tail.startswith("function 0x") and "(dynamic varg0)" in tail
    assert "beyond the 1-word head the ABI decoder checks" in text
    # Scored with the held-out scorer against the compiler's ABI: nothing wrong.
    score = heldout.score(heldout.parse_view(text), heldout.abi_functions(manifest["abi"]))
    assert score["wrong_claims"] == [] and score["selectors_recovered"] == len(ids)
    if variant == "optimized":
        # uint160 values used as numbers (an argument, a stored price) are not addresses.
        assert "(uint160 varg0)" in _header(text, ids["setPrice(uint160)"])
        assert "(uint160 varg0)" in _header(text, ids["scaled(uint160)"])
        # A computed 160-bit return prints as uint160 (the same mask).
        assert "return uint160(varg0 * 3);" in text
        assert "settle" not in _header(text, ids[SETTLE]) and "(address varg0," in _header(
            text, ids[SETTLE]
        )
    assert "price() public nonpayable returns (uint160)" in text
    assert "owner() public nonpayable returns (address)" in text
    # Declared wider than its mask: the uses keep address(...).
    assert "idToAddress(uint256 varg0)" in _header(text, ids["idToAddress(uint256)"])
    assert "return address(varg0);" in text


@pytest.mark.parametrize("variant", VARIANTS)
def test_parameter_fixture_view_matches_evm(variant, tmp_path, monkeypatch, record_property):
    manifest, _, decompiled = _fixture(variant, tmp_path)
    reference = EVMReference(manifest)
    owner, other = reference.tester.get_accounts()[:2]
    harness = Harness(decompiled, reference, {0: 3, 1: int(owner, 16)}, monkeypatch)
    dirty = (0xDEAD << 160) | 0x1234

    def call(signature, types, values, sender=owner):
        harness.check(_selector(manifest, signature) + encode(types, values), sender=sender)

    order = ["address", "(address,address,uint256,uint256)", "uint256"]
    maker, taker = int(owner, 16), int(other, 16)
    for caller in (maker, taker, 0x77):
        for amount, price in ((0, 0), (3, 5), (2**128, 2**127)):
            call(SETTLE, order, [f"0x{caller:040x}", (owner, other, amount, price), 9])
    # Dirty address words in the struct are rejected by the ABI decoder, as in the EVM.
    raw = encode(order, [owner, (owner, other, 1, 2), 3])
    for word in (1, 2):
        bad = bytearray(raw)
        bad[32 * word : 32 * word + 12] = b"\xab" * 12
        harness.check(_selector(manifest, SETTLE) + bytes(bad), sender=owner)
    memory = "settleMemory((address,address,uint256,uint256),uint256)"
    for amount, fee in ((0, 0), (7, 11), (2**200, 3)):
        call(
            memory,
            ["(address,address,uint256,uint256)", "uint256"],
            [(owner, other, amount, 13), fee],
        )
    for value in (0, 5, 2**158):
        call("setPrice(uint160)", ["uint160"], [value])
        call("price()", [], [])
        call("scaled(uint160)", ["uint160"], [value + 1])
    call("setPrice(uint160)", ["uint160"], [9], sender=other)  # not the owner: reverts
    for value in (0, 7, 2**160 - 1):
        call("triple(uint160)", ["uint160"], [value])
    harness.check(_selector(manifest, "triple(uint160)") + dirty.to_bytes(32), sender=owner)
    call("owner()", [], [])
    for word in (0, 1, dirty, 2**256 - 1):
        harness.check(_selector(manifest, "idToAddress(uint256)") + word.to_bytes(32), sender=owner)
    for data in (b"", b"x" * 31, b"y" * 70, bytes(range(200))):
        call("tail(bytes)", ["bytes"], [data])
    assert harness.reverts >= 3
    record_property(f"parameter_fixture_cases_{variant}", harness.cases)


def test_dictionary_names_the_decoder_contradicts_are_rejected(tmp_path):
    manifest, program, _ = _fixture("optimized", tmp_path)
    context = ProgramContext.build(program, tmp_path / "optimized")
    selector = "0x" + manifest["method_identifiers"][SETTLE]
    settle = next(f for f in program.functions if f.selectors == [selector])
    assert decoder_head_size(context, settle) == 192  # six head words
    keys = collect_keys(context)

    def names_with(signature):
        names = load_names(*keys)
        names.functions = Dictionary(None, None, {**names.functions.matches, selector: [signature]})
        return names

    # A colliding 0-parameter name (as dictionary spam does): rejected, not printed.
    collided = build_decompiled(program, tmp_path / "optimized", names_with("spam_xyz()")).text
    assert (
        "dictionary name spam_xyz() [dict] rejected: the ABI decoder requires 192 bytes" in collided
    )
    assert "function spam_xyz(" not in collided and f"function {selector}(" in collided
    # The real signature is kept, and its tuple decides the grouping.
    named = build_decompiled(program, tmp_path / "optimized", names_with(SETTLE)).text
    assert (
        f"// {selector} {SETTLE} [dict]" in named
        and "function settle(address varg0, S0 varg1" in named
    )
    assert "rejected" not in named


def test_signature_settles_address_against_uint160(tmp_path):
    """A 160-bit mask or validator cannot tell address from uint160; the signature can."""
    manifest, program, _ = _fixture("optimized", tmp_path)
    context = ProgramContext.build(program, tmp_path / "optimized")
    selector = "0x" + manifest["method_identifiers"]["setPrice(uint160)"]
    names = load_names(*collect_keys(context))
    names.functions = Dictionary(
        None, None, {**names.functions.matches, selector: ["setPrice(uint160)"]}
    )
    decompiled = build_decompiled(program, tmp_path / "optimized", names)
    view = next(v for v in decompiled.views if v.function.selectors == [selector])
    [argument] = view.arguments
    assert argument.type == "uint160" and "uint160 in the hash-matched signature" in argument.reason
    assert "function setPrice(uint160 varg0)" in decompiled.text


def test_scorer_compares_struct_parameters_word_by_word():
    text = (
        "    struct S0 { address f0; uint256 f1; }\n\n"
        "    // 0x11111111\n    function f(S0 varg0) public nonpayable {\n"
    )
    view = heldout.parse_view(text)
    assert view["0x11111111"]["types"] == ["(address,uint256)"]
    assert heldout.compare_tuple("(address,uint256)", "(address,uint8)") == "unresolved"
    assert heldout.compare_tuple("(address,uint256)", "(address,uint256)") == "correct"
    assert heldout.compare_tuple("(address,uint256)", "((address,uint256))") == "correct"
    assert heldout.compare_tuple("(address,address)", "(uint256,address)") == "wrong"
    assert heldout.compare_tuple("(address,uint256)", "(address,uint256,uint256)") == "wrong"
