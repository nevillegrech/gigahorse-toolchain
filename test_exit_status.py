"""
Tests for the exit status of the programs that gigahorse runs, and for the log of a failure.
Stub scripts replace the programs, so Souffle does not run.
"""

import argparse
import logging
import queue
import re
import signal
import time

import pytest

import gigahorse
from src.runners import (
    AbstractFactGenerator,
    DecompilationException,
    DecompilerFactGenerator,
    TimeoutException,
)

# ulimit keeps the core dump of the crash out of the core dump store of the host
SEGFAULT = "ulimit -c 0\nkill -SEGV $$\n"
NOT_UTF8 = "printf '\\377\\n' >&2\n"

# A stub decompiler binary that writes the files of a complete decompilation
WRITE_DECOMPILER_OUTPUT = """
for arg in "$@"; do
  case "$arg" in --output=*) out="${arg#--output=}" ;; esac
done
touch "$out/Analytics_JumpToMany.csv" "$out/TAC_Def.csv"
"""


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a client crash with no stderr output is not an error",
)
def test_crash_of_a_souffle_client_is_an_error_without_stderr_output(
    make_script, analysis_executor, tmp_path, caplog
):
    make_script("client.dl_compiled", SEGFAULT)
    caplog.set_level(logging.INFO)

    errors, timeouts = analysis_executor.run_souffle_client(
        "client.dl", str(tmp_path), str(tmp_path), time.time(), False
    )

    assert errors == ["client.dl"]
    assert timeouts == []
    assert (tmp_path / "client.dl.err").read_text() == ""
    assert f"client.dl exited with status {-signal.SIGSEGV}" in caplog.text


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: the harness ignores the exit status of a script client",
)
def test_script_client_that_exits_with_an_error_status_is_an_error(
    make_script, analysis_executor, tmp_path, caplog
):
    client = make_script("client.sh", "exit 1\n")
    caplog.set_level(logging.INFO)

    errors, timeouts = analysis_executor.run_script_client(
        client, str(tmp_path), str(tmp_path), time.time()
    )

    assert errors == ["client.sh"]
    assert timeouts == []
    assert "client.sh exited with status 1" in caplog.text


@pytest.mark.xfail(
    strict=True,
    raises=UnicodeDecodeError,
    reason="master: stderr that is not UTF-8 raises UnicodeDecodeError",
)
def test_stderr_that_is_not_utf8_does_not_raise(make_script, analysis_executor, tmp_path):
    make_script("client.dl_compiled", NOT_UTF8)
    script_client = make_script("client.sh", NOT_UTF8)

    souffle_result = analysis_executor.run_souffle_client(
        "client.dl", str(tmp_path), str(tmp_path), time.time(), False
    )
    script_result = analysis_executor.run_script_client(
        script_client, str(tmp_path), str(tmp_path), time.time()
    )

    # Souffle stderr with no error keyword is not an error
    assert souffle_result == ([], [])
    # Any stderr output of a script client stays an error
    assert script_result == (["client.sh"], [])


def make_decompiler(analysis_executor, disable_scalable_fallback: bool) -> DecompilerFactGenerator:
    run_args = argparse.Namespace(
        context_depth=None,
        disable_scalable_fallback=disable_scalable_fallback,
        pre_client="",
        skip_sig_resolution=False,
        disable_precise_fallback=False,
    )
    decompiler = DecompilerFactGenerator(run_args, ".*.hex")
    decompiler.analysis_executor = analysis_executor
    return decompiler


@pytest.mark.xfail(
    strict=True,
    raises=(TimeoutException, pytest.fail.Exception),
    reason="master: a decompiler crash gives a timeout, or starts the fallback",
)
@pytest.mark.parametrize(
    "disable_scalable_fallback", [True, False], ids=["no-fallback", "fallback"]
)
def test_crash_of_the_decompiler_is_an_error_not_a_timeout(
    make_script, analysis_executor, tmp_path, disable_scalable_fallback
):
    make_script("main.dl_compiled", SEGFAULT)
    # The fallback would complete, but a crash does not start it
    make_script("fallback_scalable.dl_compiled", WRITE_DECOMPILER_OUTPUT)
    decompiler = make_decompiler(analysis_executor, disable_scalable_fallback)

    with pytest.raises(
        DecompilationException,
        match=re.escape(f"main.dl failed, see the .err file in {tmp_path}"),
    ):
        decompiler.run_decomp("c.hex", str(tmp_path), str(tmp_path), time.time())


def test_decompiler_stopped_by_sigkill_uses_the_scalable_fallback(
    make_script, analysis_executor, tmp_path
):
    make_script("main.dl_compiled", "kill -KILL $$\n")
    make_script("fallback_scalable.dl_compiled", WRITE_DECOMPILER_OUTPUT)
    decompiler = make_decompiler(analysis_executor, disable_scalable_fallback=False)

    config = decompiler.run_decomp("c.hex", str(tmp_path), str(tmp_path), time.time())

    assert config == "ScalableDecomp"


class FailingFactGenerator(AbstractFactGenerator):
    def __init__(self, analysis_executor, error: Exception):
        self.analysis_executor = analysis_executor
        self.error = error

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        raise self.error

    def get_datalog_files(self) -> list[str]:
        return []

    def decomp_out_produced(self, out_dir: str) -> bool:
        return False

    def match_pattern(self, contract_filename: str) -> bool:
        return True


def analyze_failing_contract(tmp_path, monkeypatch, analysis_executor, error: Exception):
    """Runs gigahorse.analyze_contract on c.hex, with a fact generator that raises `error`."""
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=True,
        rerun_clients=False,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    results: queue.SimpleQueue = queue.SimpleQueue()
    gigahorse.analyze_contract(
        0, str(contract), results, FailingFactGenerator(analysis_executor, error), [], []
    )
    return results.get_nowait()


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="master: the log gives no cause of a failure"
)
@pytest.mark.parametrize(
    ("error", "flag", "message"),
    [
        (TimeoutException("too slow"), "TIMEOUT", "c.hex timed out: too slow"),
        (DecompilationException("main.dl failed"), "ERROR", "c.hex: decompilation failed: main.dl"),
        (KeyError("TAC_Def"), "ERROR", "c.hex: other error: KeyError: 'TAC_Def'"),
    ],
    ids=["timeout", "decompilation", "other"],
)
def test_the_log_names_the_contract_and_the_cause_of_a_failure(
    tmp_path, monkeypatch, analysis_executor, caplog, error, flag, message
):
    caplog.set_level(logging.INFO)

    result = analyze_failing_contract(tmp_path, monkeypatch, analysis_executor, error)

    assert result == ("c.hex", [], [flag], {})
    assert message in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="master: the debug log shows no traceback"
)
def test_debug_log_shows_the_traceback_of_an_other_error(
    tmp_path, monkeypatch, analysis_executor, caplog
):
    caplog.set_level(logging.DEBUG)

    analyze_failing_contract(tmp_path, monkeypatch, analysis_executor, KeyError("TAC_Def"))

    assert "Traceback" in caplog.text
    assert "raise self.error" in caplog.text
