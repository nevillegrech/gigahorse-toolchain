"""Native cache readers must never execute a binary that is still being written."""

import errno
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from src.datalog_cache import build_cached_executable, publish_executable

ROOT = Path(__file__).resolve().parents[1]


def bash_binary():
    binary = shutil.which("bash")
    if binary is None:
        pytest.skip("Bash is needed for the running-native-binary regression")
    return Path(binary)


def test_publication_does_not_overwrite_an_executing_inode(tmp_path):
    source = bash_binary()
    active = tmp_path / "active"
    shutil.copy2(source, active)
    process = subprocess.Popen(
        [str(active), "-c", "printf ready; read -r line"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert process.stdout.read(5) == b"ready" and process.poll() is None
        previous_inode = active.stat().st_ino
        publish_executable(source, active)
        assert active.stat().st_ino != previous_inode
        assert process.poll() is None
        assert subprocess.run([str(active), "-c", "exit 17"]).returncode == 17
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_concurrent_publishers_and_executions_see_complete_binaries(tmp_path):
    source = bash_binary()
    active = tmp_path / "active"
    publish_executable(source, active)

    def writer():
        for _ in range(12):
            publish_executable(source, active)

    def reader():
        for _ in range(20):
            assert subprocess.run([str(active), "-c", "exit 17"]).returncode == 17

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(writer) for _ in range(4)] + [pool.submit(reader) for _ in range(2)]
        for future in futures:
            future.result(timeout=15)
    assert not list(tmp_path.glob(".publish-*"))


CACHE_WORKER = """
import shutil
import sys
import time
from pathlib import Path
from src.datalog_cache import build_cached_executable
root, source = Path(sys.argv[1]), Path(sys.argv[2])
def build(output):
    with (root / 'builds').open('a') as log:
        log.write('build\\n')
    data = source.read_bytes()
    with output.open('wb') as stream:
        stream.write(data[:len(data)//2])
        stream.flush()
        (root / 'started').touch()
        deadline = time.monotonic() + 10
        while not (root / 'release').exists():
            if time.monotonic() > deadline:
                raise RuntimeError('test did not release builder')
            time.sleep(0.01)
        stream.write(data[len(data)//2:])
    shutil.copymode(source, output)
print(int(build_cached_executable(root / 'cached', build)))
"""


def test_cold_cache_build_isolated_until_complete_and_shared_across_processes(tmp_path):
    source = bash_binary()
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", CACHE_WORKER, str(tmp_path), str(source)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(4)
    ]
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "started").exists():
            assert all(p.poll() is None for p in processes)
            if time.monotonic() > deadline:
                pytest.fail("Cache builder did not start")
            time.sleep(0.01)
        assert not (tmp_path / "cached").exists()
        (tmp_path / "release").touch()
        built = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr.decode()
            built.append(int(stdout))
        assert sum(built) == 1
        assert (tmp_path / "builds").read_text().splitlines() == ["build"]
        assert subprocess.run([str(tmp_path / "cached"), "-c", "exit 17"]).returncode == 17
        assert not list(tmp_path.glob(".build-*"))
    finally:
        (tmp_path / "release").touch()
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)


def test_failed_build_and_copy_preserve_published_files(tmp_path, monkeypatch):
    destination = tmp_path / "cached"

    def failed_build(output):
        output.write_bytes(b"partial")
        raise RuntimeError("compiler failed")

    with pytest.raises(RuntimeError, match="compiler failed"):
        build_cached_executable(destination, failed_build)
    assert not destination.exists() and not list(tmp_path.glob(".build-*"))
    active = tmp_path / "active"
    active.write_bytes(b"previous")

    def failed_copy(source, output):
        Path(output).write_bytes(b"partial")
        raise OSError(errno.ENOSPC, "test disk full")

    monkeypatch.setattr("src.datalog_cache.shutil.copy2", failed_copy)
    with pytest.raises(OSError) as caught:
        publish_executable(tmp_path / "source", active)
    assert caught.value.errno == errno.ENOSPC
    assert active.read_bytes() == b"previous" and not list(tmp_path.glob(".publish-*"))


@pytest.mark.skipif(
    os.environ.get("GIGAHORSE_INTEGRATION") != "1", reason="opt-in native driver test"
)
def test_compile_failure_stops_before_using_an_old_binary(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    marker = tmp_path / "stale-executed"
    for name in ("main.dl", "function_inliner.dl"):
        alias = cache / (name + "_compiled")
        alias.write_text(f"#!/bin/sh\nprintf stale >> '{marker}'\n")
        alias.chmod(0o755)
    compiler = tmp_path / "failing-compiler"
    compiler.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then exit 0; fi\nexit 1\n')
    compiler.chmod(0o755)
    result = subprocess.run(
        [
            sys.executable,
            "gigahorse.py",
            "fixtures/reconstruction/interaction-via-ir.hex",
            "--souffle_bin",
            str(compiler),
            "--cache_dir",
            str(cache),
            "--working_dir",
            str(tmp_path / "work"),
            "--results_file",
            str(tmp_path / "results.json"),
            "--jobs",
            "1",
            "--disable_scalable_fallback",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "Souffle binary compilation failed" in result.stderr
    assert not marker.exists()
