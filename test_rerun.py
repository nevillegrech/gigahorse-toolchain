"""
Unit tests for --rerun_clients and the decompilation status of a working directory. A stub
fact generator replaces the decompiler, so Souffle does not run.
"""

import argparse
import json
import queue
from pathlib import Path

import pytest

import gigahorse
from src.runners import (
    ContractStitchingGenerator,
    DecompilationException,
    FactGenUsedEnum,
    TimeoutException,
)
from src.tac_schema import ALL_RELATIONS

# The file name and its content are the same in each gigahorse version: a rerun reads the
# working directory of an earlier run.
STATUS_FILE = "decompilation_status"


class StubFactGenerator:
    """
    Writes TAC_Def.csv and then raises `error`, if it is set. A decompiler that stops late
    also leaves most of its output.
    """

    def __init__(self, analysis_executor, error: Exception | None = None):
        self.analysis_executor = analysis_executor
        self.error = error
        self.calls = 0

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        self.calls += 1
        (Path(out_dir) / "TAC_Def.csv").write_text("")
        if self.error:
            raise self.error
        return 0.0, 0.0, FactGenUsedEnum.Custom

    def decomp_out_produced(self, out_dir: str) -> bool:
        return (Path(out_dir) / "TAC_Def.csv").exists()


def analyze(tmp_path: Path, monkeypatch, generator, rerun_clients: bool = False) -> list[str]:
    """Runs gigahorse.analyze_contract on c.hex with no clients. Returns the flags of the result."""
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=True,
        rerun_clients=rerun_clients,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    # A new queue for each call: the result is the result of this call
    results: queue.SimpleQueue = queue.SimpleQueue()
    gigahorse.analyze_contract(0, str(contract), results, generator, [], [])
    _, _, flags, _ = results.get_nowait()
    return flags


def make_earlier_working_dir(tmp_path: Path, status: str | None, has_output: bool) -> None:
    out_dir = tmp_path / "work" / "c" / "out"
    out_dir.mkdir(parents=True)
    if has_output:
        (out_dir / "TAC_Def.csv").write_text("")
    if status is not None:
        (out_dir.parent / STATUS_FILE).write_text(f"{status}\n")


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a rerun uses the output of a decompilation that stopped late",
)
@pytest.mark.parametrize(
    ("error", "flag"),
    [(TimeoutException(), "TIMEOUT"), (DecompilationException(), "ERROR")],
    ids=["TIMEOUT", "ERROR"],
)
def test_rerun_keeps_the_flag_of_a_decompilation_that_stopped_late(
    tmp_path, monkeypatch, analysis_executor, error, flag
):
    generator = StubFactGenerator(analysis_executor, error)

    assert analyze(tmp_path, monkeypatch, generator) == [flag]
    assert analyze(tmp_path, monkeypatch, generator, rerun_clients=True) == [flag]
    assert generator.calls == 1


def test_rerun_uses_a_complete_decompilation(tmp_path, monkeypatch, analysis_executor):
    generator = StubFactGenerator(analysis_executor)

    assert analyze(tmp_path, monkeypatch, generator) == []
    assert analyze(tmp_path, monkeypatch, generator, rerun_clients=True) == []
    assert generator.calls == 1


def test_rerun_checks_the_output_of_a_complete_decompilation(
    tmp_path, monkeypatch, analysis_executor
):
    # A custom fact generator can complete with no TAC_Def.csv
    make_earlier_working_dir(tmp_path, "OK", has_output=False)
    generator = StubFactGenerator(analysis_executor)

    assert analyze(tmp_path, monkeypatch, generator, rerun_clients=True) == ["TIMEOUT"]
    assert generator.calls == 0


# A worker that stops during the decompilation leaves RUNNING
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a rerun uses the output of a decompilation that stopped or failed",
)
@pytest.mark.parametrize("status", ["RUNNING", "ERROR"])
def test_rerun_does_not_use_a_decompilation_that_stopped_or_failed(
    tmp_path, monkeypatch, analysis_executor, status
):
    make_earlier_working_dir(tmp_path, status, has_output=True)
    generator = StubFactGenerator(analysis_executor)

    assert analyze(tmp_path, monkeypatch, generator, rerun_clients=True) == ["ERROR"]
    assert generator.calls == 0


@pytest.mark.parametrize(
    ("has_output", "flags"), [(True, []), (False, ["TIMEOUT"])], ids=["output", "no_output"]
)
def test_rerun_checks_the_output_of_a_working_dir_with_no_status(
    tmp_path, monkeypatch, analysis_executor, has_output, flags
):
    make_earlier_working_dir(tmp_path, None, has_output)
    generator = StubFactGenerator(analysis_executor)

    assert analyze(tmp_path, monkeypatch, generator, rerun_clients=True) == flags
    assert generator.calls == 0


@pytest.mark.xfail(
    strict=True,
    raises=pytest.fail.Exception,
    reason="master: the stitcher uses a contract that timed out",
)
def test_contract_stitching_refuses_a_contract_that_timed_out(tmp_path):
    main = "0xaaaaaaaa11"
    member_out = tmp_path / "main_id" / "out"
    member_out.mkdir(parents=True)
    for relation in ALL_RELATIONS:
        (member_out / f"{relation.name}.csv").write_text("")
    (member_out / "bytecode.hex").write_text("6001")
    (member_out.parent / STATUS_FILE).write_text("TIMEOUT\n")
    manifest = tmp_path / "stitched_multi.json"
    manifest.write_text(json.dumps({"main": main, "contracts": {main: "main_id"}}))
    out_dir = tmp_path / "stitched_multi" / "out"
    out_dir.mkdir(parents=True)

    with pytest.raises(DecompilationException, match=r"main_id .*\(TIMEOUT\)"):
        ContractStitchingGenerator(None, ".*_multi.json").generate_facts(
            str(manifest), str(out_dir.parent), str(out_dir)
        )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a client cannot read MaxContextDepth.csv, because out/ has no copy of it",
)
def test_rerun_clients_can_read_the_context_depth_of_an_older_working_dir(
    tmp_path, monkeypatch, make_script, analysis_executor
):
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"), restart=False, rerun_clients=True
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    # An older version wrote MaxContextDepth.csv only to the fact directory
    make_earlier_working_dir(tmp_path, None, has_output=True)
    (tmp_path / "work" / "c" / "MaxContextDepth.csv").write_text("20\n")
    client = make_script("read_depth.sh", "cp MaxContextDepth.csv Verbatim_Depth.csv\n")
    generator = StubFactGenerator(analysis_executor)
    results: queue.SimpleQueue = queue.SimpleQueue()

    gigahorse.analyze_contract(0, str(contract), results, generator, [], [client])

    _, _, flags, analytics = results.get_nowait()
    assert flags == []
    assert analytics["Verbatim_Depth"] == "20\n"
    assert generator.calls == 0
