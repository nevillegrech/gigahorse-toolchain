"""Static checks of the readable decompiled view (no EVM needed)."""

import re

import pytest

from reconstruction.highlevel.ir import Binary, Call, Const, Env, Index, Unary, Var
from reconstruction.highlevel.memory_liveness import AddressModel, Live, Range
from reconstruction.highlevel.printer import expression
from reconstruction.highlevel.simplify import simplify
from reconstruction.highlevel.view import build_decompiled
from reconstruction_tests.decompiled_support import (
    COMPILER_STEMS,
    DEPLOYED_IDS,
    compiler_fixture,
    deployed_fixture,
)

ADDRESS_MASK = (1 << 160) - 1
WORD = (1 << 256) - 1


def ev(*ids):
    return frozenset(ids)


# --- expression rewriting ------------------------------------------------------


def test_masks_become_casts_and_redundant_casts_vanish():
    x = Var("x", "0x1")
    assert expression(simplify(Binary("&", Const(ADDRESS_MASK), x))) == "address(x)"
    assert (
        expression(simplify(Binary("&", Env("msg.sender", 160), Const(ADDRESS_MASK))))
        == "msg.sender"
    )
    nested = Binary("&", Const(ADDRESS_MASK), Binary("&", Const(ADDRESS_MASK), x))
    assert expression(simplify(nested)) == "address(x)"
    assert expression(simplify(Binary("&", x, Const(0xFF)))) == "uint8(x)"
    high = WORD ^ ((1 << 224) - 1)
    assert expression(simplify(Binary("&", x, Const(high)))) == "bytes4(x)"


def test_selector_extraction_is_msg_sig_for_shift_and_division_forms():
    word = Index(Env("msg.data"), Const(0))
    assert expression(simplify(Binary(">>", word, Const(224)))) == "msg.sig"
    divided = Binary("&", Binary("/", word, Const(1 << 224)), Const(0xFFFFFFFF))
    assert expression(simplify(divided)) == "msg.sig"


def test_linear_arithmetic_cancels_terms_modulo_2_256():
    length = Env("msg.data.length")
    expr = Binary("-", Binary("+", Binary("-", length, Const(4)), Const(4)), Const(4))
    assert expression(simplify(expr)) == "msg.data.length - 4"
    a, b = Var("a", "0xa"), Var("b", "0xb")
    assert expression(simplify(Binary("-", Binary("+", a, b), a))) == "b"
    # Wrapping constants fold modulo 2**256.
    assert simplify(Binary("+", Const(WORD), Const(2))) == Const(1)


def test_state_reads_are_not_cancelled_as_equal_terms():
    gas = Call("gasleft")
    expr = Binary("-", Binary("+", gas, Const(1)), gas)
    assert "gasleft" in expression(simplify(expr))


def test_negations_and_signed_comparisons():
    a, b = Var("a", "0xa"), Var("b", "0xb")
    assert expression(simplify(Unary("!", Binary("<", a, b)))) == "a >= b"
    assert expression(simplify(Unary("!", Binary("s<", a, Const(32))))) == "int256(a) >= 32"
    assert expression(simplify(Unary("!", Unary("!", Binary("==", a, b))))) == "a == b"
    assert expression(simplify(Unary("!", Unary("!", a)))) == "bool(a)"


def test_simplification_never_drops_evidence():
    x = Var("x", "0x1", evidence=ev("s1"))
    mask = Const(ADDRESS_MASK, evidence=ev("s2"))
    expr = Binary(
        "&", mask, Binary("&", x, Const(ADDRESS_MASK, evidence=ev("s3"))), evidence=ev("s4")
    )
    result = simplify(expr)
    assert result.all_evidence() >= {"s1", "s2", "s3", "s4"}
    folded = simplify(
        Unary("!", Unary("!", Const(1, evidence=ev("c")), evidence=ev("i1")), evidence=ev("i2"))
    )
    assert folded.all_evidence() >= {"c", "i1", "i2"}


def test_printer_uses_solidity_precedence_with_clarifying_parentheses():
    a, b, c = (Var(n, n) for n in "abc")
    assert expression(Binary("&", Binary("+", a, b), c)) == "(a + b) & c"
    assert expression(Binary("-", a, Binary("-", b, c))) == "a - (b - c)"
    assert expression(Binary("==", Binary("&", a, b), c)) == "(a & b) == c"


# --- memory liveness -------------------------------------------------------------


def test_liveness_kills_only_fully_overwritten_bytes():
    live = Live([Range(None, 0, 64)])
    after = live.kill(Range(None, 0, 32))
    assert after.ranges == frozenset({Range(None, 32, 32)})
    assert after.observes(Range(None, 32, 32))
    assert not after.observes(Range(None, 0, 32))


def test_scratch_space_and_heap_are_disjoint_but_unknown_bases_are_not():
    heap = Range("heap:v0", 0, 32)
    scratch = Range(None, 0, 64)
    assert not Live([heap]).observes(scratch)
    assert Live([Range("var:v1", 0, 32)]).observes(scratch)
    assert Live([Range("any", 0, None)]).observes(Range(None, 0x1000, 32))
    model = AddressModel({"fp"})
    assert model.range(Binary("+", Var("fp", "0xf"), Const(36)), 32) == Range("heap:fp", 36, 32)


# --- whole-program invariants --------------------------------------------------------

LOCAL = re.compile(r"\bv\d+\b")


def _undefined_locals(text: str) -> list[str]:
    """Locals read in a function but never assigned anywhere in it."""
    problems = []
    text = "\n".join(line.split("//", 1)[0] for line in text.splitlines())
    for function in re.split(r"\n    function ", text)[1:]:
        assigned = set(re.findall(r"\b(v\d+)\b[^=\n]*?=(?!=)", function))
        assigned |= set(re.findall(r"\(([^()]*)\) = ", function))
        names = {n for group in assigned for n in LOCAL.findall(group)} | assigned
        used = set(LOCAL.findall(function))
        missing = used - names
        if missing:
            problems.append(function.split("(", 1)[0] + ": " + ", ".join(sorted(missing)))
    return problems


def _check_view(program, decompiled):
    mapping = decompiled.mapping
    statements = {s.id for b in program.blocks for s in b.instructions}
    assert mapping["unaccounted_ir_statements"] == []
    for entry in mapping["lines"]:
        assert set(entry["ir_statements"]) <= statements
    assert _undefined_locals(decompiled.text) == []
    uncertain_lines = {e["line"] for e in mapping["lines"] if e.get("uncertainty")}
    for number, line in enumerate(decompiled.text.splitlines(), 1):
        if "UNCERTAIN:" in line:
            assert number in uncertain_lines, line


@pytest.mark.parametrize("stem", COMPILER_STEMS)
def test_compiler_fixture_views_account_for_every_ir_statement(stem, tmp_path):
    program, decompiled = compiler_fixture(stem, tmp_path / "relations")
    _check_view(program, decompiled)
    again = build_decompiled(program, tmp_path / "relations")
    assert again.text == decompiled.text


@pytest.mark.parametrize(("corpus", "ident"), DEPLOYED_IDS, ids=[i for _, i in DEPLOYED_IDS])
def test_deployed_views_account_for_every_ir_statement(corpus, ident, tmp_path):
    program, decompiled, _ = deployed_fixture(corpus, ident, tmp_path / "relations")
    _check_view(program, decompiled)


def test_weth_reads_like_its_source(tmp_path):
    _, decompiled, _ = deployed_fixture(*DEPLOYED_IDS[4], tmp_path / "relations")
    text = decompiled.text
    for line in [
        "mapping (address => uint256) _balanceOf; // STORAGE[0x3]",
        "mapping (address => mapping (address => uint256)) _allowance; // STORAGE[0x4]",
        "uint8 _decimals; // STORAGE[0x2] bytes 0..0",
        "event Approval(address indexed, address indexed, uint256);",
        "function approve(address varg0, uint256 varg1) public nonpayable returns (bool) {",
        "_allowance[msg.sender][varg0] = varg1;",
        "emit Approval(msg.sender, varg0, varg1);",
        "function deposit() public payable {",
        "_balanceOf[msg.sender] = _balanceOf[msg.sender] + msg.value;",
        "emit Deposit(msg.sender, msg.value);",
        "msg.sender.transfer(varg0);",
        "if (varg2 != msg.sender && _allowance[varg2][msg.sender] != uint256.max) {",
        "return _allowance[varg0][varg1];",
    ]:
        assert line in text, line
    # No raw memory plumbing survives in the token logic.
    body = text.split("function fn_")[1].split("\n    }\n")[0]
    assert "MEM[" not in body and "keccak256" not in body


def test_morpho_view_keeps_unverified_call_inputs_and_decodes_reasons(tmp_path):
    corpus, ident = DEPLOYED_IDS[-1]
    assert ident == "morpho-liquidator"
    _, decompiled, _ = deployed_fixture(corpus, ident, tmp_path / "relations")
    text = decompiled.text
    # Reasons Dedaub shows (and "swap", which Dedaub left as 0x73776170).
    for reason in ("!owner", "!morpho", "approve", "min profit", "swap"):
        assert f'Error("{reason}")' in text, reason
    assert "address _owner; // STORAGE[0x0] bytes 0..19; named after getter owner()" in text
    assert "function MORPHO() public nonpayable returns (address) {" in text
    # flashLoan(address,uint256,bytes) has an undecoded dynamic argument: the
    # memory that builds it must stay printed, not be absorbed into the call.
    body = text.split("// 0x441c1495")[1].split("\n    }\n")[0]
    assert "flashLoan(" in body and "UNCERTAIN" in body
    assert "CALLDATACOPY(" in body and "= varg0;" in body and "= varg4;" in body
