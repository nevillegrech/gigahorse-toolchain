"""
Unit tests for the Python harness: fact generation, process runs, datalog compilation
and the multi-contract stitching. Stub programs stand in for souffle and its binaries,
thus these tests do not compile any datalog.
"""

import argparse
import json
import multiprocessing
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import gigahorse
from src import blockparse
from src.runners import (
    AnalysisExecutor,
    ContractStitchingGenerator,
    CustomFactGenerator,
    DatalogCompilationError,
    DecompilationException,
    DecompilationStatus,
    FactGenUsedEnum,
    TimeoutException,
    compile_datalog,
    get_souffle_executable_path,
    read_decompilation_status,
    run_process,
    write_decompilation_status,
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


def test_input_files_that_share_a_working_directory_stop_the_run():
    contracts = ["in/a.b.hex", "in/a.c.hex", "in/x.hex", "other/x.hex", "in/y.hex"]

    assert gigahorse.find_working_dir_collisions(contracts) == {
        "a": ["in/a.b.hex", "in/a.c.hex"],
        "x": ["in/x.hex", "other/x.hex"],
    }
    with pytest.raises(SystemExit, match=re.escape("in/a.b.hex, in/a.c.hex")):
        gigahorse.unique_contracts(contracts)


def test_a_repeated_input_file_is_analyzed_once():
    contracts = ["in/a.hex", "in/./a.hex", "in/b.hex"]
    assert gigahorse.unique_contracts(contracts) == ["in/a.hex", "in/b.hex"]


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


def test_timeout_also_stops_the_processes_that_the_process_started(tmp_path):
    late_file = tmp_path / "late_write"
    parent = make_executable(tmp_path / "parent", f'(sleep 2; touch "{late_file}") &\nsleep 30\n')

    assert run_process([parent], 0.5).timed_out

    time.sleep(2.5)
    assert not late_file.exists()


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

    with pytest.raises(
        DecompilationException,
        match=re.escape(f"inliner.dl failed, see the .err file in {out_dir}"),
    ):
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


class StubFactGenerator:
    """Stands in for a fact generator: writes one TAC file, or raises `error`."""

    def __init__(self, analysis_executor: AnalysisExecutor, error: Exception | None = None):
        self.analysis_executor = analysis_executor
        self.error = error
        self.calls = 0

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        self.calls += 1
        if self.error:
            raise self.error
        (Path(out_dir) / "TAC_Def.csv").write_text("")
        return 0.0, 0.0, FactGenUsedEnum.Custom

    def decomp_out_produced(self, out_dir: str) -> bool:
        return (Path(out_dir) / "TAC_Def.csv").exists()


def analyze(tmp_path: Path, monkeypatch, generator: StubFactGenerator, rerun_clients=False):
    """Runs gigahorse.analyze_contract on a small contract, with no inliner and no clients."""
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=True,
        rerun_clients=rerun_clients,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contract = tmp_path / "c.hex"
    contract.write_text("6001")
    results_dir = tmp_path / "results"
    results_dir.mkdir(exist_ok=True)
    gigahorse.analyze_contract(0, str(contract), str(results_dir), generator, [], [])
    return gigahorse.load_result(str(results_dir), 0, contract.name)


def test_rerun_does_not_use_a_decompilation_that_timed_out(tmp_path, monkeypatch):
    generator = StubFactGenerator(make_executor(tmp_path), TimeoutException("too slow"))

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator)
    assert flags == ["TIMEOUT"]
    assert read_decompilation_status(str(tmp_path / "work" / "c")) == DecompilationStatus.TIMEOUT

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator, rerun_clients=True)
    assert flags == ["TIMEOUT"]
    assert generator.calls == 1


def test_rerun_uses_a_complete_decompilation(tmp_path, monkeypatch):
    generator = StubFactGenerator(make_executor(tmp_path))

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator)
    assert flags == []
    assert read_decompilation_status(str(tmp_path / "work" / "c")) == DecompilationStatus.OK

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator, rerun_clients=True)
    assert flags == []
    assert generator.calls == 1


def test_rerun_does_not_use_a_decompilation_that_stopped_before_it_completed(tmp_path, monkeypatch):
    # A worker that was killed leaves the RUNNING status and can leave most of the output
    work_dir = tmp_path / "work" / "c"
    (work_dir / "out").mkdir(parents=True)
    (work_dir / "out" / "TAC_Def.csv").write_text("")
    write_decompilation_status(str(work_dir), DecompilationStatus.RUNNING)
    generator = StubFactGenerator(make_executor(tmp_path))

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator, rerun_clients=True)
    assert flags == ["ERROR"]
    assert generator.calls == 0


def test_rerun_checks_the_output_of_a_working_dir_with_no_status(tmp_path, monkeypatch):
    # A working directory from a gigahorse version with no status file
    (tmp_path / "work" / "c" / "out").mkdir(parents=True)
    generator = StubFactGenerator(make_executor(tmp_path))

    _, _, flags, _ = analyze(tmp_path, monkeypatch, generator, rerun_clients=True)
    assert flags == ["TIMEOUT"]


def test_contract_stitching_refuses_a_contract_with_no_complete_decompilation(tmp_path):
    main = "0xaaaaaaaa11"
    (tmp_path / "main_id" / "out").mkdir(parents=True)
    write_decompilation_status(str(tmp_path / "main_id"), DecompilationStatus.TIMEOUT)
    manifest = tmp_path / "stitched_multi.json"
    manifest.write_text(json.dumps({"main": main, "contracts": {main: "main_id"}}))
    out_dir = tmp_path / "stitched_multi" / "out"
    out_dir.mkdir(parents=True)

    with pytest.raises(DecompilationException, match=r"main_id .*\(TIMEOUT\)"):
        ContractStitchingGenerator(None, ".*_multi.json").generate_facts(
            str(manifest), str(out_dir.parent), str(out_dir)
        )


# A custom fact generation script is called as `<script> -i <input file> -o <out dir>`
def run_custom_fact_gen(tmp_path: Path, script: str, name: str = "factgen.sh"):
    work_dir = tmp_path / "contract"
    out_dir = work_dir / "out"
    out_dir.mkdir(parents=True)
    contract = tmp_path / "contract.custom"
    contract.write_text("input")
    generator = CustomFactGenerator(r".*\.custom", [make_executable(tmp_path / name, script)])
    generator.analysis_executor = make_executor(tmp_path)
    return generator.generate_facts(str(contract), str(work_dir), str(out_dir)), out_dir


WRITE_TAC = 'printf "0x1\\tv1\\t0\\n" > "$4/TAC_Def.csv"\n'


def test_custom_fact_gen_script_that_fails_raises(tmp_path):
    with pytest.raises(DecompilationException, match=r"factgen\.sh failed"):
        run_custom_fact_gen(tmp_path, WRITE_TAC + 'echo "fatal: bad input" >&2\nexit 1\n')

    assert "bad input" in (tmp_path / "contract" / "out" / "factgen.sh.err").read_text()


def test_custom_fact_gen_script_that_crashes_without_stderr_output_raises(tmp_path):
    with pytest.raises(DecompilationException):
        run_custom_fact_gen(tmp_path, WRITE_TAC + "kill -SEGV $$\n")


def test_custom_fact_gen_script_stopped_by_timeout_raises_timeout(tmp_path):
    with pytest.raises(TimeoutException):
        run_custom_fact_gen(tmp_path, WRITE_TAC + "exec sleep 30\n")


def test_custom_fact_gen_script_can_log_progress_on_stderr(tmp_path):
    (_, _, config), out_dir = run_custom_fact_gen(
        tmp_path, 'echo "50%" >&2\n' + WRITE_TAC + 'echo "100%" >&2\n'
    )

    assert config == FactGenUsedEnum.Custom
    assert (out_dir / "factgen.sh.err").read_text() == "50%\n100%\n"


def test_custom_fact_gen_time_is_decompilation_time(tmp_path):
    (disassemble_time, decomp_time, _), _ = run_custom_fact_gen(tmp_path, WRITE_TAC)

    assert disassemble_time == 0.0
    assert decomp_time > 0.0


def test_custom_fact_gen_that_writes_no_tac_raises(tmp_path):
    with pytest.raises(DecompilationException, match=r"TAC_Def\.csv"):
        run_custom_fact_gen(tmp_path, "exit 0\n")


def test_custom_fact_gen_stops_at_the_first_failed_script(tmp_path):
    work_dir = tmp_path / "contract"
    (work_dir / "out").mkdir(parents=True)
    (tmp_path / "contract.custom").write_text("input")
    first = make_executable(tmp_path / "first.sh", "exit 2\n")
    second = make_executable(tmp_path / "second.sh", f"touch {tmp_path}/second-ran\n" + WRITE_TAC)
    generator = CustomFactGenerator(r".*\.custom", [first, second])
    generator.analysis_executor = make_executor(tmp_path)

    with pytest.raises(DecompilationException, match=r"first\.sh"):
        generator.generate_facts(
            str(tmp_path / "contract.custom"), str(work_dir), str(work_dir / "out")
        )
    assert not (tmp_path / "second-ran").exists()


def test_stderr_output_of_a_script_client_stays_an_error(tmp_path):
    client = make_executable(tmp_path / "client.sh", 'echo "warning" >&2\n')

    errors, timeouts = make_executor(tmp_path).run_script_client(
        client, str(tmp_path), str(tmp_path), time.time()
    )

    assert errors == ["client.sh"]
    assert timeouts == []


def handler(file_regex: str, fact_gen: str) -> dict:
    return {"fileRegex": file_regex, "tacGenScripts": {"factGen": fact_gen, "customScripts": []}}


GENERATOR_ARGS = argparse.Namespace(
    context_depth=20,
    disable_scalable_fallback=False,
    pre_client="",
    skip_sig_resolution=False,
    disable_precise_fallback=False,
)


def test_default_tac_generation_config_selects_hex_and_manifest_files():
    with open(Path(gigahorse.GIGAHORSE_DIR) / "tac_gen_config.json") as f:
        generator = gigahorse.build_fact_generator(json.load(f), GENERATOR_ARGS)

    assert generator.match_pattern("in/a.hex")
    assert generator.match_pattern("in/b_multi.json")
    assert not generator.match_pattern("in/c.txt")


def test_tac_generation_config_with_only_a_multi_contract_handler_is_invalid():
    config = {"handlers": [handler(".*_multi.json", "MultiContract")]}

    with pytest.raises(ValueError, match="MultiContract"):
        gigahorse.build_fact_generator(config, GENERATOR_ARGS)


def test_tac_generation_handlers_with_the_same_file_regex_are_invalid():
    config = {"handlers": [handler(".*.hex", "Decomp"), handler(".*.hex", "Custom")]}

    with pytest.raises(ValueError, match="fileRegex"):
        gigahorse.build_fact_generator(config, GENERATOR_ARGS)


class DyingFactGenerator(StubFactGenerator):
    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        if contract_filename.endswith("dies.hex"):
            os.kill(os.getpid(), signal.SIGKILL)
        return super().generate_facts(contract_filename, work_dir, out_dir)


def test_batch_analysis_reports_a_worker_that_dies(tmp_path, monkeypatch):
    monkeypatch.setattr(gigahorse, "Process", multiprocessing.get_context("fork").Process)
    run_args = argparse.Namespace(
        working_dir=str(tmp_path / "work"),
        restart=False,
        disable_inline=True,
        rerun_clients=False,
    )
    monkeypatch.setattr(gigahorse, "args", run_args, raising=False)
    contracts = []
    for name in ["a.hex", "dies.hex", "b.hex"]:
        (tmp_path / name).write_text("6001")
        contracts.append(str(tmp_path / name))

    results = gigahorse.batch_analysis(
        DyingFactGenerator(make_executor(tmp_path)), [], [], contracts, 2
    )

    assert [(name, flags) for name, _, flags, _ in results] == [
        ("a.hex", []),
        ("dies.hex", ["ERROR"]),
        ("b.hex", []),
    ]


def make_decompiled_contract(contract_dir: Path, files: dict[str, str]) -> None:
    """The working dir of a decompiled contract: empty TAC relations plus `files`."""
    (contract_dir / "out").mkdir(parents=True)
    for relation in ALL_RELATIONS:
        (contract_dir / "out" / f"{relation.name}.csv").write_text("")
    for path, content in files.items():
        (contract_dir / path).write_text(content)


def stitch(tmp_path: Path, contracts: dict[str, str], main: str) -> Path:
    manifest = tmp_path / "stitched_multi.json"
    manifest.write_text(json.dumps({"main": main, "contracts": contracts}))
    out_dir = tmp_path / "stitched_multi" / "out"
    out_dir.mkdir(parents=True)
    ContractStitchingGenerator(None, ".*_multi.json").generate_facts(
        str(manifest), str(out_dir.parent), str(out_dir)
    )
    return out_dir


def test_contract_stitching_writes_the_client_inputs_of_the_main_contract(tmp_path):
    main, other = "0xaaaaaaaa11", "0xbbbbbbbb22"
    for contract_id, depth, storage in [("main_id", "20", "0x0\t0x1\n"), ("other_id", "10", "")]:
        make_decompiled_contract(
            tmp_path / contract_id,
            {
                "out/bytecode.hex": "6001",
                "out/StorageContents.csv": storage,
                "out/MaxContextDepth.csv": f"{depth}\n",
            },
        )

    out_dir = stitch(tmp_path, {main: "main_id", other: "other_id"}, main)

    assert (out_dir / "StorageContents.csv").read_text() == "0x0\t0x1\n"
    assert (out_dir / "SHA3Decompositions.csv").read_text() == ""
    assert (out_dir / "MaxContextDepth.csv").read_text() == "20\n"
    assert (out_dir / "vulnerability.csv").read_text() == ""
    assert (out_dir / "proto_vulnerability.csv").read_text() == ""


def test_contract_stitching_reads_the_context_depth_of_an_older_working_dir(tmp_path):
    main = "0xaaaaaaaa11"
    # An older version wrote MaxContextDepth.csv only to the fact dir
    make_decompiled_contract(
        tmp_path / "main_id", {"out/bytecode.hex": "6001", "MaxContextDepth.csv": "20\n"}
    )

    out_dir = stitch(tmp_path, {main: "main_id"}, main)

    assert (out_dir / "MaxContextDepth.csv").read_text() == "20\n"
    assert (out_dir / "StorageContents.csv").read_text() == ""


GENERATEFACTS = str(Path(gigahorse.GIGAHORSE_DIR) / "generatefacts")


def test_generatefacts_writes_the_facts_that_the_decompiler_reads(tmp_path):
    (tmp_path / "c.hex").write_text("6001")

    subprocess.run([sys.executable, GENERATEFACTS, "c.hex"], cwd=tmp_path, check=True)

    assert (tmp_path / "bytecode.hex").read_text() == "6001"
    assert (tmp_path / "MaxContextDepth.csv").read_text() == "20\n"


def test_generatefacts_reads_disassembly(tmp_path):
    (tmp_path / "c.dasm").write_text("0x0 PUSH1 => 0x1\n0x2 STOP\n")

    subprocess.run(
        [sys.executable, GENERATEFACTS, "-a", "c.dasm", "facts"], cwd=tmp_path, check=True
    )

    assert (tmp_path / "facts" / "Statement_Opcode.facts").read_text() == "0x0\tPUSH1\n0x2\tSTOP\n"
    assert (tmp_path / "facts" / "bytecode.hex").read_text() == ""


class OutputFactGenerator(StubFactGenerator):
    """Also writes bytecode.hex (with a 0x prefix) and a relation with dots in its name."""

    def generate_facts(self, contract_filename: str, work_dir: str, out_dir: str):
        (Path(out_dir) / "bytecode.hex").write_text("0x600160")
        (Path(out_dir) / "global.sens.DropLast.csv").write_text("row\n")
        return super().generate_facts(contract_filename, work_dir, out_dir)


def test_results_keep_relation_names_and_measure_the_bytecode(tmp_path, monkeypatch):
    name, properties, _, analytics = analyze(
        tmp_path, monkeypatch, OutputFactGenerator(make_executor(tmp_path))
    )

    assert name == "c.hex"
    assert "global.sens.DropLast" in properties
    assert analytics["bytecode_size"] == 3


def test_analytics_of_the_output_relations(tmp_path):
    (tmp_path / "Analytics_Jumps.csv").write_text("0x1\n0x2\n")
    (tmp_path / "Verbatim_a.b.csv").write_text("text\n")
    (tmp_path / "vulnerability.csv").write_text("Reentrancy\tHigh\tPUBLIC\n\n")
    analytics: dict = {}

    gigahorse.get_gigahorse_analytics(str(tmp_path), analytics)

    assert analytics == {"Analytics_Jumps": 2, "Verbatim_a.b": "text\n", "High: Reentrancy": 1}
