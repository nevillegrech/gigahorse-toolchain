"""
Unit tests for the Python harness: fact generation, process runs, datalog compilation
and the multi-contract stitching. Stub programs stand in for souffle and its binaries,
thus these tests do not compile any datalog.
"""

import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from src import blockparse
from src.runners import (
    AnalysisExecutor,
    ContractStitchingGenerator,
    DatalogCompilationError,
    DecompilationException,
    compile_datalog,
    get_souffle_executable_path,
    run_process,
)
from src.tac_schema import ALL_RELATIONS, TACRelations


def make_executable(path: Path, script: str) -> str:
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(0o755)
    return str(path)


def make_executor(cache_dir: Path) -> AnalysisExecutor:
    return AnalysisExecutor(
        timeout=1,
        interpreted=False,
        minimum_client_time=1,
        debug=False,
        souffle_bin="souffle",
        cache_dir=str(cache_dir),
        souffle_macros="",
    )


# A stand-in for a compiled inliner: it reads TAC_Op.csv, adds a line and writes it back.
STUB_TRANSFORMER = """
for arg in "$@"; do
  case "$arg" in
    --facts=*) facts="${arg#--facts=}" ;;
    --output=*) out="${arg#--output=}" ;;
  esac
done
cat "$facts/TAC_Op.csv" > "$out/TAC_Op.csv"
echo round >> "$out/TAC_Op.csv"
"""


@pytest.mark.parametrize(
    ("bytecode", "expected_ops"),
    [
        ("60015b", [(0x0, "PUSH1"), (0x2, "JUMPDEST")]),
        ("5b", [(0x0, "JUMPDEST")]),
        ("600156", [(0x0, "PUSH1"), (0x2, "JUMP")]),
        ("60015b00", [(0x0, "PUSH1"), (0x2, "JUMPDEST"), (0x3, "STOP")]),
        ("", []),
    ],
)
def test_bytecode_parser_keeps_all_ops(bytecode, expected_ops):
    blocks = blockparse.EVMBytecodeParser(bytecode).parse()
    assert [(op.pc, op.opcode.name) for block in blocks for op in block.evm_ops] == expected_ops


def test_tac_relations_are_written_with_souffle_line_ends(tmp_path):
    TACRelations({"TAC_Op": [("0x1", "ADD"), ("0x2", "STOP")]}).write_dir(tmp_path)
    assert (tmp_path / "TAC_Op.csv").read_bytes() == b"0x1\tADD\n0x2\tSTOP\n"


def test_contract_stitching_copies_the_bytecode_of_the_main_contract(tmp_path):
    main, other = "0xaaaaaaaa11", "0xbbbbbbbb22"
    for contract_id, bytecode in [("main_id", "6001"), ("other_id", "6002")]:
        contract_out = tmp_path / contract_id / "out"
        contract_out.mkdir(parents=True)
        for relation in ALL_RELATIONS:
            (contract_out / f"{relation.name}.csv").write_text("")
        (contract_out / "TAC_Op.csv").write_text("0x1\tSTOP\n")
        (contract_out / "bytecode.hex").write_text(bytecode)

    manifest = tmp_path / "stitched_multi.json"
    manifest.write_text(
        json.dumps({"main": main, "contracts": {main: "main_id", other: "other_id"}})
    )
    work_dir = tmp_path / "stitched_multi"
    out_dir = work_dir / "out"
    out_dir.mkdir(parents=True)

    ContractStitchingGenerator(None, ".*_multi.json").generate_facts(
        str(manifest), str(work_dir), str(out_dir)
    )

    assert (out_dir / "bytecode.hex").read_text() == "6001"
    assert (out_dir / "TAC_Op.csv").read_text() == f"0x1\tSTOP\n{other[:8]}_0x1\tSTOP\n"


def test_run_process_reports_exit_status_and_timeout():
    ok = run_process([sys.executable, "-c", "pass"], 10)
    assert ok.returncode == 0
    assert not ok.timed_out

    failed = run_process([sys.executable, "-c", "raise SystemExit(3)"], 10)
    assert failed.returncode == 3
    assert not failed.timed_out

    crashed = run_process(
        [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"], 10
    )
    assert crashed.returncode == -signal.SIGSEGV
    assert not crashed.timed_out

    slow = run_process([sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
    assert slow.timed_out


def test_crash_of_a_souffle_client_is_an_error_without_stderr_output(tmp_path):
    executor = make_executor(tmp_path)
    executor.set_executable("client.dl", make_executable(tmp_path / "crash", "kill -SEGV $$\n"))

    errors, timeouts = executor.run_souffle_client(
        "client.dl", str(tmp_path), str(tmp_path), time.time(), False
    )

    assert errors == ["client.dl"]
    assert timeouts == []
    assert (tmp_path / "client.dl.err").read_text() == ""


def make_ir_dir(tmp_path: Path) -> Path:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "TAC_Op.csv").write_text("old\n")
    (out_dir / "TAC_Use.csv").write_text("old\n")
    return out_dir


def test_transformer_rounds_read_the_output_of_the_previous_round(tmp_path):
    out_dir = make_ir_dir(tmp_path)
    executor = make_executor(tmp_path)
    executor.set_executable("inliner.dl", make_executable(tmp_path / "inliner", STUB_TRANSFORMER))

    executor.run_transformer_rounds(
        "inliner.dl", 3, str(out_dir), str(tmp_path / "round"), time.time()
    )

    assert (out_dir / "TAC_Op.csv").read_text() == "old\nround\nround\nround\n"
    assert (out_dir / "TAC_Use.csv").read_text() == "old\n"
    assert not (tmp_path / "round").exists()


def test_transformer_round_stopped_by_timeout_leaves_the_ir_unchanged(tmp_path):
    out_dir = make_ir_dir(tmp_path)
    executor = make_executor(tmp_path)
    # Writes one relation, then runs until the timeout stops it
    inliner = make_executable(
        tmp_path / "inliner", 'echo new > "${2#--output=}/TAC_Op.csv"\nexec sleep 30\n'
    )
    executor.set_executable("inliner.dl", inliner)

    executor.run_transformer_rounds(
        "inliner.dl", 6, str(out_dir), str(tmp_path / "round"), time.time()
    )

    assert (out_dir / "TAC_Op.csv").read_text() == "old\n"
    assert (out_dir / "TAC_Use.csv").read_text() == "old\n"
    assert (out_dir / "inliner.dl.err").exists()


def test_transformer_round_that_fails_raises(tmp_path):
    out_dir = make_ir_dir(tmp_path)
    executor = make_executor(tmp_path)
    executor.set_executable(
        "inliner.dl",
        make_executable(tmp_path / "inliner", 'echo "Error: bad input" >&2\nexit 1\n'),
    )

    with pytest.raises(DecompilationException):
        executor.run_transformer_rounds(
            "inliner.dl", 6, str(out_dir), str(tmp_path / "round"), time.time()
        )

    assert (out_dir / "TAC_Op.csv").read_text() == "old\n"
    assert "bad input" in (out_dir / "inliner.dl.err").read_text()


# A stand-in for souffle: `souffle -M <macros> -o <binary> <spec> -L <dir>`
STUB_SOUFFLE = """
echo compiled >> "$(dirname "$0")/compilations"
printf '#!/bin/sh\\n' > "$4"
chmod +x "$4"
echo "// C++" > "$4.cpp"
"""


@pytest.fixture
def datalog_spec(tmp_path) -> str:
    spec = tmp_path / "prog.dl"
    spec.write_text(".decl A(x: number)\nA(1).\n#ifdef FEATURE\n.output A\n#endif\n")
    return str(spec)


def count_compilations(tmp_path: Path) -> int:
    log_file = tmp_path / "compilations"
    return len(log_file.read_text().splitlines()) if log_file.exists() else 0


def test_compiled_binaries_are_content_addressed_and_cached(tmp_path, datalog_spec):
    souffle = make_executable(tmp_path / "souffle", STUB_SOUFFLE)
    cache_dir = str(tmp_path / "cache")

    binary = compile_datalog(datalog_spec, souffle, cache_dir, False, "GIGAHORSE_DIR=/x")
    assert count_compilations(tmp_path) == 1
    assert os.access(binary, os.X_OK)
    assert os.path.exists(f"{binary}.cpp")
    link = get_souffle_executable_path(cache_dir, datalog_spec)
    assert os.path.realpath(link) == binary

    # Same program and macros: the cached binary is used
    assert compile_datalog(datalog_spec, souffle, cache_dir, False, "GIGAHORSE_DIR=/x") == binary
    assert count_compilations(tmp_path) == 1

    # Other macros: another binary. The first binary stays in place for runs that use it.
    other = compile_datalog(datalog_spec, souffle, cache_dir, False, "GIGAHORSE_DIR=/x FEATURE=")
    assert other != binary
    assert count_compilations(tmp_path) == 2
    assert os.path.exists(binary)
    assert os.path.realpath(link) == other

    # --reuse_datalog_bin: the most recent binary, with no preprocessing or compilation
    assert compile_datalog(datalog_spec, "/no/such/souffle", cache_dir, True, "") == other


def test_failed_compilation_raises_and_leaves_no_binary(tmp_path, datalog_spec):
    # Fails after it writes the C++ program and a part of the binary
    souffle = make_executable(
        tmp_path / "souffle", 'echo "// C++" > "$4.cpp"\necho x > "$4"\nexit 1\n'
    )
    cache_dir = tmp_path / "cache"

    with pytest.raises(DatalogCompilationError):
        compile_datalog(datalog_spec, souffle, str(cache_dir), False, "GIGAHORSE_DIR=/x")

    assert [p.name for p in cache_dir.iterdir() if not p.name.endswith(".lock")] == []
