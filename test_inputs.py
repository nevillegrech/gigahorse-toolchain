"""Tests for the input files of gigahorse.py. A stub script generates the facts, so Souffle does not run."""

import json
import subprocess
import sys
from os.path import abspath, dirname, join

import pytest

GIGAHORSE = join(dirname(abspath(__file__)), "gigahorse.py")


def write_contracts(directory, *names):
    directory.mkdir()
    for name in names:
        (directory / name).write_text("0x00")


def run_gigahorse(tmp_path, make_script, *args):
    """Runs gigahorse.py. Returns the result and the input files, in the order of analysis."""
    analyzed = tmp_path / "analyzed.log"
    fact_gen = make_script("fact_gen.sh", f'echo "$2" >> {analyzed}\n')
    config = tmp_path / "tac_gen_config.json"
    handler = {
        "fileRegex": r".*\.hex",
        "tacGenScripts": {"factGen": "Custom", "customScripts": [fact_gen]},
    }
    config.write_text(json.dumps({"handlers": [handler]}))

    result = subprocess.run(
        [
            sys.executable,
            GIGAHORSE,
            *args,
            "--souffle_bin",
            make_script("souffle", "exit 0\n"),
            "--tac_gen_config",
            str(config),
            "--working_dir",
            str(tmp_path / "work"),
            "--results_file",
            str(tmp_path / "results.json"),
            "--disable_inline",
            "--jobs",
            "1",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result, analyzed.read_text().splitlines() if analyzed.exists() else []


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: files that share a working directory lose their results",
)
def test_input_files_that_share_a_working_dir_stop_the_run(tmp_path, make_script):
    in_dir, other_dir = tmp_path / "in", tmp_path / "other"
    write_contracts(in_dir, "a.b.hex", "a.c.hex", "x.hex")
    write_contracts(other_dir, "x.hex")

    # --skip 3 keeps only other/x.hex: the check must also see the skipped files
    result, analyzed = run_gigahorse(
        tmp_path, make_script, str(in_dir), str(other_dir), "--skip", "3"
    )

    assert result.returncode == 1
    assert (
        f"a: {in_dir}/a.b.hex, {in_dir}/a.c.hex; x: {in_dir}/x.hex, {other_dir}/x.hex"
        in result.stderr
    )
    assert analyzed == []


def test_a_repeated_input_file_is_analyzed_once(tmp_path, make_script):
    in_dir = tmp_path / "in"
    write_contracts(in_dir, "a.hex", "b.hex")

    result, analyzed = run_gigahorse(
        tmp_path, make_script, f"{in_dir}/a.hex", f"{in_dir}/./a.hex", str(in_dir)
    )

    assert result.returncode == 0, result.stderr
    assert analyzed == [f"{in_dir}/a.hex", f"{in_dir}/b.hex"]


@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="master: the files of an input directory come in the order of the file system",
)
def test_the_files_of_an_input_dir_are_analyzed_in_sorted_order(tmp_path, make_script):
    in_dir = tmp_path / "in"
    # Not in sorted order, because some file systems list files in the order of creation
    names = ["c.hex", "a.hex", "e.hex", "b.hex", "d.hex"]
    write_contracts(in_dir, *names)

    result, analyzed = run_gigahorse(tmp_path, make_script, str(in_dir))

    assert result.returncode == 0, result.stderr
    assert analyzed == [str(in_dir / name) for name in sorted(names)]
