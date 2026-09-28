"""Unit tests for src/runners.py. Stub scripts replace the clients, so Souffle does not run."""

import time

from src.runners import run_process


def test_run_process_returns_the_runtime_of_a_process_that_exits(make_script):
    assert run_process([make_script("ok", "exit 0\n")], 10) >= 0


def test_run_process_returns_minus_one_when_the_timeout_stops_the_process(make_script):
    # exec replaces the shell, so the timeout also stops sleep
    assert run_process([make_script("slow", "exec sleep 30\n")], 0.5) == -1


def test_script_client_that_writes_to_stderr_is_an_error(make_script, analysis_executor, tmp_path):
    client = make_script("client.sh", 'echo "warning" >&2\n')

    errors, timeouts = analysis_executor.run_script_client(
        client, str(tmp_path), str(tmp_path), time.time()
    )

    assert errors == ["client.sh"]
    assert timeouts == []
