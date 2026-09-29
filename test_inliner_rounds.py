"""Tests for the inliner rounds. Stub scripts replace the compiled inliner, so Souffle does not run."""

import argparse
import os
import queue
from pathlib import Path

import pytest

import gigahorse
from src.common import SOUFFLE_COMPILED_SUFFIX
from src.runners import AbstractFactGenerator, FactGenUsedEnum

INLINER = gigahorse.DEFAULT_INLINER_DL

# Writes one relation, then runs until the timeout stops it
STUB_INLINER_THAT_TIMES_OUT = 'echo new > "${2#--output=}/TAC_Op.csv"\nexec sleep 30\n'


@pytest.fixture
def make_inliner(make_script):
    """Writes a stub inliner binary to tmp_path, where analysis_executor looks for it."""

    def _make_inliner(body: str) -> None:
        make_script(os.path.basename(INLINER) + SOUFFLE_COMPILED_SUFFIX, body)

    return _make_inliner


def write_ir(out_dir: Path) -> None:
    (out_dir / "TAC_Op.csv").write_text("old\n")
    (out_dir / "TAC_Use.csv").write_text("old\n")


class StubFactGenerator(AbstractFactGenerator):
    def __init__(self, analysis_executor):
        self.analysis_executor = analysis_executor

    def generate_facts(self, contract_filename, work_dir, out_dir):
        write_ir(Path(out_dir))
        return 0.0, 0.0, FactGenUsedEnum.Custom

    def get_datalog_files(self):
        return []

    def decomp_out_produced(self, out_dir):
        return True

    def match_pattern(self, contract_filename):
        return True


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a timeout in an inliner round leaves a mix of two rounds",
)
def test_inliner_round_stopped_by_timeout_leaves_the_ir_unchanged(
    make_inliner, analysis_executor, tmp_path, monkeypatch
):
    make_inliner(STUB_INLINER_THAT_TIMES_OUT)
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=False,
        rerun_clients=False,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    results: queue.Queue = queue.Queue()

    gigahorse.analyze_contract(
        0, str(contract), results, StubFactGenerator(analysis_executor), [], []
    )

    _, _, flags, _ = results.get_nowait()
    assert flags == []
    out_dir = tmp_path / "work" / "c" / "out"
    assert (out_dir / "TAC_Op.csv").read_text() == "old\n"
    assert (out_dir / "TAC_Use.csv").read_text() == "old\n"
    assert (out_dir / "function_inliner.dl.err").exists()
