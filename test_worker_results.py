"""Unit tests for the result collection of gigahorse.py. A stub fact generator replaces the decompiler."""

import argparse
import logging
import multiprocessing
import os
import signal
from pathlib import Path

import pytest

import gigahorse
from src.runners import FactGenUsedEnum


class StubFactGenerator:
    """Writes one TAC file. For dies.hex, it kills its own process."""

    def __init__(self, analysis_executor):
        self.analysis_executor = analysis_executor

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        if contract_filename.endswith("dies.hex"):
            os.kill(os.getpid(), signal.SIGKILL)
        (Path(out_dir) / "TAC_Def.csv").write_text("")
        return 0.0, 0.0, FactGenUsedEnum.Custom

    def decomp_out_produced(self, out_dir: str) -> bool:
        return (Path(out_dir) / "TAC_Def.csv").exists()


def set_args(monkeypatch, working_dir: Path):
    run_args = argparse.Namespace(
        working_dir=str(working_dir),
        restart=False,
        disable_inline=True,
        rerun_clients=False,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a worker that dies leaves no entry in the results",
)
# pytest-xdist starts these threads. gigahorse forks from a process with one thread.
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_batch_analysis_reports_a_worker_that_dies(
    tmp_path, monkeypatch, caplog, analysis_executor
):
    monkeypatch.setattr(gigahorse, "Process", multiprocessing.get_context("fork").Process)
    set_args(monkeypatch, tmp_path / "work")
    caplog.set_level(logging.INFO)
    contracts = []
    for name in ["a.hex", "dies.hex", "b.hex"]:
        (tmp_path / name).write_text("6001")
        contracts.append(str(tmp_path / name))

    results = gigahorse.batch_analysis(StubFactGenerator(analysis_executor), [], [], contracts, 2)

    assert [(name, flags) for name, _, flags, _ in results] == [
        ("a.hex", []),
        ("dies.hex", ["ERROR"]),
        ("b.hex", []),
    ]
    assert "dies.hex: the analysis process stopped with no result." in caplog.text
