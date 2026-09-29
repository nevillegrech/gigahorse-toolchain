"""
Unit tests for the compilation of datalog programs. A stub stands in for souffle,
thus these tests compile no datalog.
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from src.runners import compile_datalog

# A stand-in for souffle: `souffle -M <macros> -o <binary> <spec> -L <dir>`
STUB_SOUFFLE = """
echo compiled >> "$(dirname "$0")/compilations"
printf '#!/bin/sh\\n' > "$4"
chmod +x "$4"
echo "// C++" > "$4.cpp"
"""

MACROS = "GIGAHORSE_DIR=/x"


@pytest.fixture
def datalog_spec(tmp_path) -> str:
    spec = tmp_path / "prog.dl"
    spec.write_text(".decl A(x: number)\nA(1).\n#ifdef FEATURE\n.output A\n#endif\n")
    return str(spec)


def count_compilations(tmp_path: Path) -> int:
    log_file = tmp_path / "compilations"
    return len(log_file.read_text().splitlines()) if log_file.exists() else 0


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: concurrent runs compile one program more than one time",
)
def test_concurrent_runs_compile_a_program_once(tmp_path, make_script, datalog_spec):
    souffle = make_script("souffle", "sleep 0.5\n" + STUB_SOUFFLE)
    cache_dir = str(tmp_path / "cache")

    def compile_once(_):
        return compile_datalog(datalog_spec, souffle, cache_dir, False, MACROS)

    with ThreadPoolExecutor(4) as pool:
        assert len(set(pool.map(compile_once, range(4)))) == 1
    assert count_compilations(tmp_path) == 1


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="master: a failed compilation leaves a partial binary",
)
def test_failed_compilation_raises_and_leaves_no_binary(tmp_path, make_script, datalog_spec):
    # Fails after it writes the C++ program and a part of the binary
    souffle = make_script("souffle", 'echo "// C++" > "$4.cpp"\necho x > "$4"\nexit 1\n')
    cache_dir = tmp_path / "cache"

    with pytest.raises(AssertionError):
        compile_datalog(datalog_spec, souffle, str(cache_dir), False, MACROS)

    assert [p.name for p in cache_dir.iterdir() if not p.name.endswith(".lock")] == []
