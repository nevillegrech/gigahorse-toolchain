"""Unit tests for the results.json entry of a contract. A stub replaces the decompiler."""

import argparse
import queue
from pathlib import Path

import pytest

import gigahorse
from src.runners import FactGenUsedEnum


class StubFactGenerator:
    """Replaces the decompiler. It writes the given files into out/."""

    def __init__(self, analysis_executor, out_files: dict[str, str]):
        self.analysis_executor = analysis_executor
        self.out_files = out_files

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        for name, text in self.out_files.items():
            (Path(out_dir) / name).write_text(text)
        return 0.0, 0.0, FactGenUsedEnum.Custom


def analyze(tmp_path, monkeypatch, generator):
    """Runs gigahorse.analyze_contract on a 2 byte contract with no clients."""
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=True,
        rerun_clients=False,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    result_queue: queue.SimpleQueue = queue.SimpleQueue()
    gigahorse.analyze_contract(0, str(contract), result_queue, generator, [], [])
    return result_queue.get_nowait()


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: results.json shortens relation names at the first dot",
)
def test_properties_keep_the_dots_in_relation_names(tmp_path, monkeypatch, analysis_executor):
    generator = StubFactGenerator(analysis_executor, {"global.sens.DropLast.csv": "row\n"})

    _, properties, flags, _ = analyze(tmp_path, monkeypatch, generator)

    assert flags == []
    assert "global.sens.DropLast" in properties


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: bytecode_size comes from the text of the input file",
)
@pytest.mark.parametrize(
    ("out_files", "size"),
    [
        ({"bytecode.hex": "0x600160"}, 3),
        ({"bytecode.hex": "600160"}, 3),
        ({}, None),
    ],
    ids=["0x-prefix", "no-prefix", "no-file"],
)
def test_bytecode_size_measures_out_bytecode_hex(
    tmp_path, monkeypatch, analysis_executor, out_files, size
):
    generator = StubFactGenerator(analysis_executor, out_files)

    _, _, flags, analytics = analyze(tmp_path, monkeypatch, generator)

    assert flags == []
    assert analytics["bytecode_size"] == size


@pytest.mark.xfail(
    strict=True,
    raises=ValueError,
    reason="master: a blank line in vulnerability.csv raises ValueError",
)
def test_analytics_skip_a_blank_vulnerability_line(tmp_path):
    (tmp_path / "Analytics_Jumps.csv").write_text("0x1\n0x2\n")
    (tmp_path / "Verbatim_a.b.csv").write_text("text\n")
    (tmp_path / "vulnerability.csv").write_text("Reentrancy\tHigh\tPUBLIC\n\n")
    analytics: dict = {}

    gigahorse.get_gigahorse_analytics(str(tmp_path), analytics)

    assert analytics == {"Analytics_Jumps": 2, "Verbatim_a.b": "text\n", "High: Reentrancy": 1}
