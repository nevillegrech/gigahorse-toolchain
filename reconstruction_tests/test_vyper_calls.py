"""Vyper 0.2 internal calls: return addresses kept in memory, results pushed in a loop."""

from src.vyper_stack_loops import StackLoop, stack_loops

OPS = {
    "STOP": 0x00, "ADD": 0x01, "SUB": 0x03, "LT": 0x10, "GT": 0x11, "ISZERO": 0x15, "CALLDATALOAD": 0x35,
    "POP": 0x50, "MLOAD": 0x51, "MSTORE": 0x52, "JUMP": 0x56, "JUMPI": 0x57, "JUMPDEST": 0x5B,
    "SWAP1": 0x90,
}  # fmt: skip


def assemble(*items) -> bytes:
    """Ops by name; ints are PUSH2 immediates (labels are resolved by the caller)."""
    out = bytearray()
    for item in items:
        if isinstance(item, int):
            out += bytes([0x61]) + item.to_bytes(2, "big")
        else:
            out.append(OPS[item])
    return bytes(out)


def return_loop(counter: list, slot=0x1E0, base=0x200, iszero=True) -> tuple[bytes, dict]:
    """A Vyper 0.2 return: a block setting the counter (`counter` computes its value)
    falls into the push loop's head at 0x100; the loop body is at 0x120 and the
    exit returns through mload(0x140)."""
    head, body, exit_ = 0x100, 0x120, 0x150
    prefix = assemble("JUMPDEST", *counter, slot, "MSTORE")
    code = bytearray(head - len(prefix)) + prefix  # STOPs before the block
    code += assemble(
        "JUMPDEST", 0, slot, "MLOAD", "GT", *(["ISZERO", "ISZERO"] if iszero else []),
        body, "JUMPI", exit_, "JUMP",
    )  # fmt: skip
    code = code.ljust(body, b"\x00")
    code += assemble(
        "JUMPDEST", 32, slot, "MLOAD", "SUB", base, "ADD", "MLOAD",
        32, slot, "MLOAD", "SUB", slot, "MSTORE", head, "JUMP",
    )  # fmt: skip
    code = code.ljust(exit_, b"\x00") + assemble("JUMPDEST", 0x140, "MLOAD", "JUMP")
    # The counter's value expression is the last one or two instructions before
    # `PUSH2 slot; MSTORE` (a push, or a push and an MLOAD).
    tail = 3 if counter[-1] != "MLOAD" else 4
    return bytes(code), {"value": head - 4 - tail, "load_next": body + 14}


def test_return_loop_count_is_found_by_executing_the_block_setting_it():
    # Vyper 0.2.12: MEM[L] = 0x40 directly.
    code, at = return_loop([0x40])
    assert stack_loops(code) == [StackLoop(at["value"], (0x220, 0x200), pop_before=at["load_next"])]
    # Vyper 0.2.16: through memory (MEM[0xc0] = 0x60; MEM[L] = MEM[0xc0]), no ISZERO pair.
    code, at = return_loop([0x60, 0xC0, "MSTORE", 0xC0, "MLOAD"], iszero=False)
    loads = (0x240, 0x220, 0x200)
    assert stack_loops(code) == [StackLoop(at["value"], loads, pop_before=at["load_next"])]
    # The words are pushed last first: the first word ends on top, as the loop leaves it.


def test_return_loop_is_left_alone_unless_its_count_is_a_known_word_multiple():
    unknown = [0x04, "CALLDATALOAD", 0xC0, "MSTORE", 0xC0, "MLOAD"]  # a size from calldata
    assert stack_loops(return_loop(unknown)[0]) == []
    assert stack_loops(return_loop([0x30])[0]) == []  # not a whole number of words
    # The counter among the words read: the loop changes what it pushes.
    assert stack_loops(return_loop([0x40], slot=0x220)[0]) == []
    # A memory write the emulation does not follow forgets the stored size.
    clobbered = [0x60, 0xC0, "MSTORE", 0x00, 0x04, "CALLDATALOAD", "MSTORE", 0xC0, "MLOAD"]
    assert stack_loops(return_loop(clobbered)[0]) == []


def frame_loops(start=0x140, end=0x200, slot=0x200) -> tuple[bytes, dict]:
    """Vyper 0.2.4 saving a frame (MEM[start:end]) on the stack before a call, then
    restoring it: each loop is one block ending in a JUMPI out, then a jump back."""
    save, restore = 0x40, 0x80
    code = bytearray(save - 8) + assemble("JUMPDEST", start, slot, "MSTORE")  # sets MEM[L]
    code += assemble(
        "JUMPDEST", slot, "MLOAD", "MLOAD", 32, slot, "MLOAD", "ADD", slot, "MSTORE",
        end, slot, "MLOAD", "LT", "ISZERO", restore - 8, "JUMPI", save, "JUMP",
    )  # fmt: skip
    code = code.ljust(restore - 8, b"\x00") + assemble("JUMPDEST", end - 32, slot, "MSTORE")
    code += assemble(
        "JUMPDEST", slot, "MLOAD", "MSTORE", 32, slot, "MLOAD", "SUB", slot, "MSTORE",
        start, slot, "MLOAD", "LT", "ISZERO", "ISZERO", 0xC0, "JUMPI", restore, "JUMP",
    )  # fmt: skip
    return bytes(code), {"save": save, "restore": restore}


def test_frame_save_and_restore_loops_move_every_frame_word():
    code, at = frame_loops()
    save, restore = stack_loops(code)
    # Saved first word first; restored last word first (the top of the stack).
    assert save == StackLoop(at["save"] - 7, loads=(0x140, 0x160, 0x180, 0x1A0, 0x1C0, 0x1E0),
                             pop_before=at["save"] + 6)  # fmt: skip
    assert restore == StackLoop(at["restore"] - 7, stores=(0x1E0, 0x1C0, 0x1A0, 0x180, 0x160, 0x140),
                                keep_before=at["restore"] + 5)  # fmt: skip
    # The counter inside the frame: the loops change the words they move.
    assert stack_loops(frame_loops(slot=0x1A0)[0]) == []


def _calls_fixture(tmp_path):
    import json
    from pathlib import Path

    from reconstruction_tests.decompiled_support import compiler_fixture

    root = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"
    manifest = json.loads((root / "vyper-calls-v0216.json").read_text())
    _, decompiled = compiler_fixture("vyper-calls-v0216", tmp_path / "calls")
    return manifest, decompiled


def test_internal_calls_are_functions_with_their_results(tmp_path):
    import importlib.util
    import re
    from pathlib import Path

    manifest, decompiled = _calls_fixture(tmp_path)
    text = decompiled.text
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("heldout", root / "scripts/evaluate-heldout.py")
    heldout = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(heldout)
    score = heldout.score(heldout.parse_view(text), heldout.abi_functions(manifest["abi"]))
    assert score["selectors_recovered"] == len(manifest["method_identifiers"]) == 7
    assert score["wrong_claims"] == []
    assert score["payability"]["correct"] == 7
    # owner(): Vyper returns the stored address word unmasked, so it prints as uint256.
    assert score["returns"] == {"correct": 6, "unresolved": 1, "wrong": 0}
    # Each return goes back to its caller: no unresolved jump, nothing unstructured.
    assert "not structured" not in text and "unresolved" not in text
    # _scaled, _pair and _bump are private functions (_first_above, called once, is
    # inlined); _pair's two words come back from the loop that pushes them.
    assert len(re.findall(r"function fn_0x[0-9a-f]+\(.*\) private", text)) == 3
    assert re.search(r"\(v\d+, v\d+\) = fn_0x[0-9a-f]+\(", text)
    assert re.search(r"private returns \(uint256, uint256\)", text)


def test_internal_calls_view_matches_evm(tmp_path, monkeypatch):
    import pytest

    pytest.importorskip("eth_tester", reason="install the validation extra")
    from eth_abi import encode

    from reconstruction_tests.test_decompiled_execution import Harness
    from reconstruction_tests.test_execution import EVMReference

    manifest, decompiled = _calls_fixture(tmp_path)
    reference = EVMReference(manifest)
    owner, other = reference.tester.get_accounts()[:2]
    initial = {slot: reference.storage(slot) for slot in range(4) if reference.storage(slot)}
    harness = Harness(decompiled, reference, initial, monkeypatch)
    ids = manifest["method_identifiers"]

    def call(signature, values=(), *, sender=owner, value=0):
        types = signature[signature.index("(") + 1 : -1]
        types = types.split(",") if types else []
        harness.check(
            bytes.fromhex(ids[signature]) + encode(types, list(values)), sender=sender, value=value
        )

    for x in (5, 999, 1000, 2**255):  # _bump's limit; _scaled's overflow checks
        call("first(uint256)", [x])
    for x, y in ((9, 4), (4, 9), (7, 7), (2**255, 0)):  # both branches of _pair
        call("second(uint256,uint256)", [x, y])
    call("third(uint256)", [20])
    call("third(uint256)", [3])
    call("third(uint256)", [20], sender=other)  # not the owner
    for n in (0, 1, 3, 4, 9):  # the loop's break and its natural end
        call("summed(uint256)", [n])
    for x in (0, 25, 40, 1000):  # returned from inside _first_above's loop, or after it
        call("above(uint256)", [x])
    for getter in ("total()", "owner()"):
        call(getter)
    call("first(uint256)", [1], value=1)  # nonpayable
    assert harness.reverts >= 5


def test_saved_frames_are_restored_around_internal_calls(tmp_path, monkeypatch):
    """Vyper 0.2.12 saves a caller with more than 10 locals on the stack in a loop
    and restores it after the call (nested in _deep): the rewritten loops keep every
    local, and the results land where they are used."""
    import json
    import re
    from pathlib import Path

    import pytest

    from reconstruction_tests.decompiled_support import compiler_fixture

    root = Path(__file__).resolve().parents[1] / "fixtures/reconstruction"
    manifest = json.loads((root / "vyper-frames-v0212.json").read_text())
    code = bytes.fromhex((root / "vyper-frames-v0212.hex").read_text().strip())
    loops = stack_loops(code)
    assert sorted(len(loop.loads) for loop in loops if loop.loads and loop.pop_before) == [
        2, 11, 13, 13, 13, 14,
    ]  # fmt: skip
    assert sorted(len(loop.stores) for loop in loops if loop.stores) == [11, 13, 13, 13, 14]
    _, decompiled = compiler_fixture("vyper-frames-v0212", tmp_path / "frames")
    text = decompiled.text
    assert "not structured" not in text and "unresolved" not in text
    assert "PHI inputs" not in text
    # _scale is called four times; the rest, called once, are inlined.
    assert len(re.findall(r"function fn_0x[0-9a-f]+\(.*\) private", text)) == 1

    pytest.importorskip("eth_tester", reason="install the validation extra")
    from eth_abi import encode

    from reconstruction_tests.test_decompiled_execution import Harness
    from reconstruction_tests.test_execution import EVMReference

    reference = EVMReference(manifest)
    owner = reference.tester.get_accounts()[0]
    harness = Harness(decompiled, reference, {}, monkeypatch)
    ids = manifest["method_identifiers"]
    for a, b in ((1, 2), (7, 0), (1000, 99), (5, 100), (2**255, 1), (2**200, 1), (0, 0)):
        data = bytes.fromhex(ids["many(uint256,uint256)"]) + encode(["uint256", "uint256"], [a, b])
        harness.check(data, sender=owner)
    harness.check(bytes.fromhex(ids["total()"]), sender=owner)
    assert harness.reverts >= 2  # _bump's limit, an overflow
