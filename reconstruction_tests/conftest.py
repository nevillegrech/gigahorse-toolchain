"""Cross-check the printed decompiled view against every IR-machine execution.

Existing behavioral tests execute recovered IR with RecoveredMachine and compare
it with Py-EVM. This hook re-executes each structured-mode case with the
DecompiledMachine (which runs the statement trees printed in decompiled.sol.txt),
replaying the same external outcomes, and requires identical output, revert
status, logs, storage and external call operands. Constructs the decompiled
machine cannot execute are counted and reported, never treated as agreement.
Set DECOMPILED_CROSSCHECK=0 to disable.
"""

from __future__ import annotations

import os
from collections import Counter

import pytest

STATS: Counter[str] = Counter()
UNSUPPORTED: Counter[str] = Counter()
_CACHE: dict[int, object] = {}


def _decompiled(program):
    from reconstruction.highlevel.view import build_decompiled

    key = id(program)
    if key not in _CACHE:
        _CACHE[key] = (program, build_decompiled(program))
    return _CACHE[key][1]


def _reason(exc) -> str:
    """Unsupported reason with any expression shown as printed in the view."""
    from reconstruction.highlevel.ir import Expr
    from reconstruction.highlevel.printer import expression

    text = str(exc)
    for arg in getattr(exc, "args", ()):
        if isinstance(arg, Expr):
            text = expression(arg)
    return text[:160]


def _nonzero(storage: dict[int, int]) -> dict[int, int]:
    return {slot: value for slot, value in storage.items() if value}


def crosscheck(machine, calldata, kwargs, result, outcomes) -> None:
    from reconstruction.highlevel.interpreter import DecompiledMachine
    from reconstruction.validation import UnsupportedExecution

    try:
        decompiled = _decompiled(machine.program)
    except Exception as exc:  # pragma: no cover - surfaced as a failure below
        raise AssertionError(f"decompiled view failed to build: {exc!r}") from exc
    pending = list(outcomes)

    def replay(invocation):
        if not pending:
            raise AssertionError("decompiled view made an extra external call")
        recorded, outcome = pending.pop(0)
        for name in ("opcode", "target", "value", "calldata"):
            if getattr(invocation, name) != getattr(recorded, name):
                raise AssertionError(
                    f"decompiled external call {name} differs: "
                    f"{getattr(invocation, name)!r} != {getattr(recorded, name)!r}"
                )
        return outcome

    other = DecompiledMachine(decompiled, external_handler=replay)
    try:
        mine = other.execute(
            calldata,
            storage=kwargs.get("storage"),
            caller=kwargs.get("caller", 1),
            address=kwargs.get("address", 2),
            value=kwargs.get("value", 0),
            observed_balance_values=kwargs.get("observed_balance_values", ()),
            code_sizes=kwargs.get("code_sizes"),
            block_environment=kwargs.get("block_environment"),
            block_hashes=kwargs.get("block_hashes"),
        )
    except UnsupportedExecution as exc:
        STATS["unsupported"] += 1
        UNSUPPORTED[_reason(exc)] += 1
        return
    assert not pending, (
        f"decompiled view skipped an external call on {calldata.hex()} value={kwargs.get('value', 0)}"
    )
    from reconstruction.highlevel.interpreter import describe_trace

    assert (mine.output, mine.reverted) == (result.output, result.reverted), (
        f"decompiled view diverges on {calldata.hex()}: "
        f"{(mine.output.hex()[:80], mine.reverted)} != {(result.output.hex()[:80], result.reverted)}\n"
        f"last decompiled statements:\n{describe_trace(other.trace)}"
    )
    assert [(log.address, log.topics, log.data) for log in mine.logs] == [
        (log.address, log.topics, log.data) for log in result.logs
    ], f"decompiled view logs diverge on {calldata.hex()}"
    assert _nonzero(mine.storage) == _nonzero(result.storage), (
        f"decompiled view storage diverges on {calldata.hex()}"
    )
    STATS["agree"] += 1
    STATS["uncertain_lines_agreeing"] += int(other.uncertain_executed > 0)
    STATS["external_calls"] += len(outcomes)
    STATS["logs"] += len(result.logs)
    STATS["reverted"] += int(result.reverted)


@pytest.fixture(autouse=True)
def _decompiled_crosscheck(monkeypatch):
    if os.environ.get("DECOMPILED_CROSSCHECK", "1") == "0":
        yield
        return
    from reconstruction.validation import RecoveredMachine

    original = RecoveredMachine.execute

    def execute(self, calldata, **kwargs):
        handler = self.external_handler
        outcomes = []
        if handler is not None:

            def recording(invocation, handler=handler):
                outcome = handler(invocation)
                outcomes.append((invocation, outcome))
                return outcome

            self.external_handler = recording
        try:
            result = original(self, calldata, **kwargs)
        finally:
            self.external_handler = handler
        if self.structured:
            crosscheck(self, calldata, kwargs, result, outcomes)
        return result

    monkeypatch.setattr(RecoveredMachine, "execute", execute)
    yield


def pytest_terminal_summary(terminalreporter):
    if not STATS:
        return
    terminalreporter.section("decompiled view cross-check")
    terminalreporter.write_line(
        f"agreeing executions: {STATS['agree']} "
        f"(external calls {STATS['external_calls']}, logs {STATS['logs']}, reverted {STATS['reverted']}, "
        f"executions through UNCERTAIN lines {STATS['uncertain_lines_agreeing']}); "
        f"unsupported: {STATS['unsupported']}"
    )
    for reason, count in UNSUPPORTED.most_common(12):
        terminalreporter.write_line(f"  unsupported x{count}: {reason}")
