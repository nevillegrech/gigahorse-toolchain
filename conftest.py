import subprocess
import sys
from os.path import abspath, dirname, join
from pathlib import Path

import pytest
from filelock import FileLock

from src.runners import AnalysisExecutor

GIGAHORSE_TOOLCHAIN_ROOT = dirname(abspath(__file__))


@pytest.fixture(scope="session")
def gigahorse_prereqs(tmp_path_factory, worker_id):
    """Compiles core .dl files exactly once, shared across all workers."""

    def _run_prereq(working_dir: Path):
        common_clients = [
            "-C",
            join(GIGAHORSE_TOOLCHAIN_ROOT, "clients/analytics_client.dl"),
        ]
        result = subprocess.run(
            [
                sys.executable,
                join(GIGAHORSE_TOOLCHAIN_ROOT, "gigahorse.py"),
                join(GIGAHORSE_TOOLCHAIN_ROOT, "examples/long_running.hex"),
                "--restart",
                "--jobs",
                "1",
                "--working_dir",
                str(working_dir),
                "--results_file",
                str(working_dir / "results.json"),
                "--disable_scalable_fallback",
                *common_clients,
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.exit(
                f"Analysis binary compilation failed:\n{result.stderr.decode()}",
                returncode=1,
            )

    if worker_id == "master":
        _run_prereq(tmp_path_factory.mktemp("pretest"))
    else:
        root_tmp_dir = tmp_path_factory.getbasetemp().parent
        lock_path = root_tmp_dir / "gigahorse_prereq.lock"
        done_path = root_tmp_dir / "gigahorse_prereq.done"

        with FileLock(str(lock_path)):
            if not done_path.exists():
                _run_prereq(root_tmp_dir / "pretest_shared")
                done_path.write_text("done")

    yield


@pytest.fixture
def make_script(tmp_path):
    """Writes an executable /bin/sh script into tmp_path and returns its path."""

    def _make_script(name: str, body: str) -> str:
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return str(path)

    return _make_script


@pytest.fixture
def analysis_executor(tmp_path):
    """An AnalysisExecutor with a 1 s timeout. The stub clients need no Souffle."""
    return AnalysisExecutor(
        timeout=1,
        interpreted=False,
        minimum_client_time=1,
        debug=False,
        souffle_bin="souffle",
        cache_dir=str(tmp_path),
        souffle_macros="",
    )
