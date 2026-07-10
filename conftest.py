import subprocess
from pathlib import Path
from os.path import join, dirname, abspath

import pytest
from filelock import FileLock
import sys

GIGAHORSE_TOOLCHAIN_ROOT = dirname(abspath(__file__))

def pytest_sessionstart(session):
    print("\n[gigahorse] running prereq compilation before tests begin...\n", file=sys.stderr)

@pytest.fixture(scope="session", autouse=True)
def gigahorse_prereqs(tmp_path_factory, worker_id):
    """Compiles core .dl files exactly once, shared across all workers."""

    def _run_prereq(working_dir: Path):
        common_clients = ["-C", join(GIGAHORSE_TOOLCHAIN_ROOT, "clients/analytics_client.dl")]
        gigahorse_args = ["--disable_scalable_fallback"]
        result = subprocess.run(
            [
                "python3",
                join(GIGAHORSE_TOOLCHAIN_ROOT, "gigahorse.py"),
                join(GIGAHORSE_TOOLCHAIN_ROOT, "examples/long_running.hex"),
                "--restart",
                "--jobs", "1",
                "--working_dir", str(working_dir),
                *common_clients,
                *gigahorse_args,
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.exit(f"Prereq compilation failed:\n{result.stderr.decode()}", returncode=1)

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