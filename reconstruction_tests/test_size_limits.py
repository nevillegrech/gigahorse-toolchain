"""Chained reuse of pure values stays bounded in the decompiled view and still executes."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from reconstruction.constants import resolve_constants
from reconstruction.highlevel.abi_codec import FORM_LIMIT, Tracker
from reconstruction.highlevel.ir import Binary, Var
from reconstruction.highlevel.lift import INLINE_SIZE_LIMIT
from reconstruction.highlevel.view import build_decompiled
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.semantics import SemanticInfo

STEPS = 20
MASK = (1 << 256) - 1
ROOT = Path(__file__).resolve().parents[1]
# Without the limits the render does not finish (3**20 nodes); fail, don't hang.
RENDER_SECONDS = 120


def chained_reuse_program(steps: int = STEPS):
    """`x = msg.data[0]`, then `steps` times `x = x * x + x`; return x.

    Each step reads x three times (DUP1 DUP1 MUL ADD), so inlining every pure
    value would print about 3**steps nodes for the returned word.
    """
    runtime = bytes.fromhex("600035") + bytes.fromhex("80800201") * steps
    runtime += bytes.fromhex("60005260206000f3")
    constants = {"zero": "0x0", "width": "0x20"}

    def ins(name, op, defs=(), uses=(), pc=None):
        return Instruction(name, op, list(defs), list(uses), [hex(pc)] if pc is not None else [])

    body = [ins("load", "CALLDATALOAD", ["x0"], ["zero"], 2)]
    for k in range(steps):
        pc = 3 + 4 * k
        body.append(ins(f"mul{k}", "MUL", [f"m{k}"], [f"x{k}", f"x{k}"], pc + 2))
        body.append(ins(f"add{k}", "ADD", [f"x{k + 1}"], [f"m{k}", f"x{k}"], pc + 3))
    end = 3 + 4 * steps
    body.append(ins("store", "MSTORE", uses=["zero", f"x{steps}"], pc=end + 2))
    body.append(ins("return", "RETURN", uses=["zero", "width"], pc=end + 7))
    program = Program(
        constants,
        {},
        [Function("root", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", body, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex(),
    )
    program.constants = resolve_constants(program, constants, [], [])
    program.semantics = SemanticInfo(3, [], [], [], {}, program.constants, [], [], [], [])
    return program, runtime


def expected(word: int, steps: int = STEPS) -> int:
    for _ in range(steps):
        word = (word * word + word) & MASK
    return word


def render_bounded() -> dict:
    """Render in a child process with a deadline, so an unbounded pass fails the test."""
    script = (
        "import json, sys\n"
        "from reconstruction.highlevel.view import build_decompiled\n"
        "from reconstruction_tests.test_size_limits import chained_reuse_program\n"
        "d = build_decompiled(chained_reuse_program()[0])\n"
        "json.dump({'text': d.text, 'lines': d.mapping['lines']}, sys.stdout)\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=RENDER_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"rendering chained reuse took over {RENDER_SECONDS}s")
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout)


def test_chained_reuse_is_printed_through_bounded_locals():
    rendered = render_bounded()
    code = [line for line in rendered["text"].splitlines() if line.strip()]
    limited = [line for line in code if f"not inlined: over {INLINE_SIZE_LIMIT} nodes" in line]
    # Inlined, the return value alone would be 3**20 nodes; each printed line stays short.
    assert limited and len(limited) < STEPS
    assert max(len(line) for line in code) < 4000
    rules = [entry for entry in rendered["lines"] if "inline-size-limit" in entry.get("rules", ())]
    assert len(rules) == len(limited)
    # Every size-limited line still carries the IR statements it computes.
    assert all(entry["ir_statements"] for entry in rules)


def test_chained_reuse_view_matches_evm(record_property):
    pytest.importorskip("eth_tester")
    from reconstruction.highlevel.interpreter import DecompiledMachine
    from reconstruction_tests.test_calldata_execution import creation_code
    from reconstruction_tests.test_execution import EVMReference

    render_bounded()  # fails instead of hanging if a limit regresses
    program, runtime = chained_reuse_program()
    decompiled = build_decompiled(program)
    reference = EVMReference({"creation_bytecode": creation_code(runtime)})
    cases = [0, 1, 2, 3, 0xFF, 1 << 128, MASK, MASK - 1, 0x1234567890ABCDEF << 64]
    for word in cases:
        data = word.to_bytes(32)
        output, reverted = reference.call(data)
        assert not reverted and int.from_bytes(output) == expected(word)
        result = DecompiledMachine(decompiled).execute(data)
        assert (result.output, result.reverted) == (output, reverted), hex(word)
    record_property("size_limit_evm_cases", len(cases))
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_large_canonical_forms_become_distinct_atoms():
    tracker = Tracker(frozenset())
    value: object = Var("a", "a")
    for _ in range(12):
        value = Binary("+", Binary("*", value, value), value)
    first, second = tracker.canon(value), tracker.canon(value)
    # Too large to compare: an atom equal to nothing, not even another copy.
    assert first[0] == "large" and first != second
    small = Binary("+", Var("a", "a"), Var("b", "b"))
    assert tracker.canon(small) == tracker.canon(small)
    assert FORM_LIMIT >= 64
