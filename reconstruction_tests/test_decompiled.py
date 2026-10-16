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
    # Constant conditions are folded away, whatever width the constant was built with.
    assert not re.search(r"\bif \((true|false|0|1)\)|require\((true|1)\)", decompiled.text)
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


def test_morpho_view_decodes_struct_coding_and_reasons(tmp_path):
    corpus, ident = DEPLOYED_IDS[-1]
    assert ident == "morpho-liquidator"
    _, decompiled, _ = deployed_fixture(corpus, ident, tmp_path / "relations")
    text = decompiled.text
    # Reasons Dedaub shows (and "swap", which Dedaub left as 0x73776170).
    for reason in ("!owner", "!morpho", "approve", "min profit", "swap"):
        assert f'Error("{reason}")' in text, reason
    assert "address _owner; // STORAGE[0x0] bytes 0..19; named after getter owner()" in text
    assert "function MORPHO() public nonpayable returns (address) {" in text
    # The flash-loan data is one struct: encoded by the owner entry point and
    # decoded by the callback, so both name the same declaration.
    struct = "struct S0 { uint256 f0; address f1; uint256 f2; address f3; bytes f4; address f5; address f6; }"
    assert struct in text
    callback = text.split("// 0x31f57072")[1].split("\n    }\n")[0]
    assert "function 0x31f57072(uint256 varg0, bytes varg1)" in callback
    assert "v0 = abi.decode(varg1, (S0));" in callback
    assert "CALLDATACOPY(" not in callback and "msg.data[varg1.data" not in callback
    assert ".0x2c3c9157(v0.f0); // staticcall\n" in callback  # its input is verified
    owner = text.split("// 0x441c1495")[1].split("\n    }\n")[0]
    encode = "v31 = abi.encode(S0(varg0, varg1, varg2, varg4, varg5, address(v7), address(v8)));"
    assert encode in owner
    assert (
        ".flashLoan(address(v7), varg3, v31); // flashLoan(address,uint256,bytes) [dict]\n" in owner
    )
    assert "UNCERTAIN" not in owner and "CALLDATACOPY(" not in owner and "MCOPY(" not in owner
    lines = [
        entry
        for entry in decompiled.mapping["lines"]
        if "solc-abi-decode" in entry.get("rules", [])
    ]
    assert len(lines) == 1 and len(lines[0]["abstracted_ir_statements"]) > 50


def test_output_and_map_do_not_depend_on_hash_seed(tmp_path):
    """Text and map are byte-identical across PYTHONHASHSEED (set-iteration order)."""
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = (
        "import hashlib, json, sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from reconstruction.highlevel import naming\n"
        "naming.CACHE_DIR = Path(sys.argv[2]) / 'no-cache'\n"
        "from reconstruction_tests.decompiled_support import DEDAUB, DEPLOYED_NEXT, deployed_fixture\n"
        "digests = {}\n"
        "for corpus, ident in ((DEPLOYED_NEXT, 'ens-registry'), (DEDAUB, 'morpho-liquidator')):\n"
        "    _, d, _ = deployed_fixture(corpus, ident, Path(sys.argv[2]) / ident)\n"
        "    blob = d.text + json.dumps(d.mapping, sort_keys=False, default=str)\n"
        "    digests[ident] = hashlib.sha256(blob.encode()).hexdigest()\n"
        "print(json.dumps(digests))\n"
    )
    root = Path(__file__).resolve().parents[1]
    results = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        done = subprocess.run(
            [sys.executable, "-c", script, str(root), str(tmp_path / seed)],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        results.append(json.loads(done.stdout.strip().splitlines()[-1]))
    assert results[0] == results[1]
