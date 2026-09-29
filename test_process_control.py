"""
Tests that gigahorse stops its child processes at a timeout or a signal.
Stub scripts replace Souffle and the fact generation, thus Souffle does not run.
"""

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src.common import GIGAHORSE_DIR
from src.runners import run_process


def late_file_after_signal(
    command: list[str], started: Path, late_file: Path, sig: int
) -> tuple[bool, int]:
    """
    Runs `command` and sends `sig` to it when the file `started` exists. The processes that
    `command` starts write `late_file` 2 s after `started`. Returns whether `late_file` exists
    after that time, and the exit status of `command`.
    """
    process = subprocess.Popen(command, cwd=GIGAHORSE_DIR, start_new_session=True)
    try:
        deadline = time.time() + 10
        while not started.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert started.exists(), "the child process did not start"
        process.send_signal(sig)
        process.wait(10)
        time.sleep(2.5)
        return late_file.exists(), process.returncode
    finally:
        # Also stop the processes that are left when the test fails
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="master: at a timeout, only the direct child stops"
)
def test_timeout_also_stops_the_processes_that_the_process_started(make_script, tmp_path):
    late_file = tmp_path / "late_write"
    parent = make_script("parent", f'(sleep 2; touch "{late_file}") &\nsleep 30\n')

    assert run_process([parent], 0.5) == -1

    time.sleep(2.5)
    assert not late_file.exists()


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a SIGTERM to the main process does not stop the workers",
)
def test_sigterm_to_the_main_process_alone_also_stops_the_workers(make_script, tmp_path):
    started, late_file = tmp_path / "started", tmp_path / "late_write"
    # The fact generation script starts a process that writes a file after 2 s
    facts_script = make_script(
        "facts.sh", f'(sleep 2; touch "{late_file}") &\ntouch "{started}"\nwait\n'
    )
    handler = {
        "fileRegex": r".*\.custom",
        "tacGenScripts": {"factGen": "Custom", "customScripts": [facts_script]},
    }
    config = tmp_path / "tac_gen_config.json"
    config.write_text(json.dumps({"handlers": [handler]}))
    contract = tmp_path / "contract.custom"
    contract.write_text("input")
    command = [
        sys.executable,
        "gigahorse.py",
        str(contract),
        "--souffle_bin",
        make_script("souffle", "exit 0\n"),
        "--interpreted",
        "--disable_inline",
        "--tac_gen_config",
        str(config),
        "--working_dir",
        str(tmp_path / "work"),
        "--results_file",
        str(tmp_path / "results.json"),
    ]

    late, status = late_file_after_signal(command, started, late_file, signal.SIGTERM)
    assert not late
    assert status == 128 + signal.SIGTERM
