#!/usr/bin/env python3
"""Run Gigahorse and render an evidence-preserving reconstruction bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from reconstruction.bytecode import normalize_bytecode
from reconstruction.highlevel.view import render_decompiled
from reconstruction.model import load_program
from reconstruction.recovered import render_recovered
from reconstruction.render import render_program

ROOT = Path(__file__).resolve().parent


def scratch_root() -> Path:
    preferred = Path("/mnt/model-ssd/scratch/gigahorse-decompiler")
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=preferred):
            pass
        return preferred
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "gigahorse-decompiler"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def dependency_status(souffle_bin: str) -> dict[str, str]:
    status = {}
    if sys.version_info < (3, 13):  # noqa: UP036 -- doctor also explains unsupported system Python
        status["python"] = "ERROR: Python 3.13 or newer is required"
    else:
        status["python"] = sys.version.split()[0]
    binary = shutil.which(souffle_bin)
    if not binary:
        status["souffle"] = f"ERROR: {souffle_bin!r} not found; see README.fork.md"
    else:
        try:
            result = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=10
            )
            status["souffle"] = (
                result.stdout.strip()
                if result.returncode == 0
                else "ERROR: " + result.stderr.strip()
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            status["souffle"] = f"ERROR: {exc}"
    functors = ROOT / "souffle-addon/libfunctors.so"
    if not functors.is_file():
        status["functors"] = "ERROR: build souffle-addon first; see README.md"
    else:
        result = subprocess.run(
            [sys.executable, "-c", "import ctypes,sys; ctypes.CDLL(sys.argv[1])", str(functors)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        status["functors"] = (
            str(functors) if result.returncode == 0 else ("ERROR: " + result.stderr.strip())
        )
    return status


def check_dependencies(souffle_bin: str) -> None:
    failures = [
        f"{key}: {value}"
        for key, value in dependency_status(souffle_bin).items()
        if value.startswith("ERROR:")
    ]
    if failures:
        raise ValueError("\n".join(failures))


def semantic_implementation_hash() -> str:
    digest = hashlib.sha256()
    for folder in ("clientlib", "clients"):
        for path in sorted((ROOT / folder).rglob("*.dl")):
            digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def write_bundle(
    facts: Path,
    output: Path,
    metadata: dict,
    log: str | None = None,
    signature_file: Path | None = None,
    online_signatures: bool = False,
) -> None:
    if output.exists():
        raise ValueError(f"Output already exists: {output}; choose a new directory")
    program = load_program(facts)
    if signature_file is not None:
        from reconstruction.signatures import apply_signature_file

        apply_signature_file(program, signature_file)
    report = program.to_dict()
    provenance = dict(metadata)
    bytecode_path = facts / "bytecode.hex"
    if bytecode_path.is_file():
        bytecode = normalize_bytecode(bytecode_path.read_text())
        digest = hashlib.sha256(bytes.fromhex(bytecode)).hexdigest()
        if provenance.get("input_sha256", digest) != digest:
            raise ValueError("Analysis bytecode does not match the claimed provenance hash")
        provenance["input_sha256"] = digest
    report["provenance"] = provenance
    pseudocode = render_program(program)
    recovered, source_map = render_recovered(program)
    structured, structured_map = render_recovered(program, structure_flow=True)
    decompiled, decompiled_map = render_decompiled(
        program, facts, online_signatures=online_signatures
    )
    output.mkdir(parents=True)
    (output / "analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "pseudocode.sol.txt").write_text(pseudocode)
    (output / "recovered.sol.txt").write_text(recovered)
    (output / "recovered.map.json").write_text(json.dumps(source_map, indent=2) + "\n")
    (output / "structured.sol.txt").write_text(structured)
    (output / "structured.map.json").write_text(json.dumps(structured_map, indent=2) + "\n")
    (output / "decompiled.sol.txt").write_text(decompiled)
    (output / "decompiled.map.json").write_text(json.dumps(decompiled_map, indent=2) + "\n")
    shutil.copytree(facts, output / "relations")
    if log is not None:
        (output / "upstream.log").write_text(log)


def decompile(args: argparse.Namespace) -> None:
    bytecode = normalize_bytecode(args.bytecode.read_text())
    if args.output.exists():
        raise ValueError(f"Output already exists: {args.output}; choose a new directory")
    check_dependencies(args.souffle_bin)
    scratch = scratch_root()
    cache = scratch / "cache"
    cache.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=scratch) as temporary:
        run_dir = Path(temporary)
        source = run_dir / "contract.hex"
        source.write_text(bytecode + "\n")
        results_path = run_dir / "results.json"
        command = [
            sys.executable,
            str(ROOT / "gigahorse.py"),
            str(source),
            "--souffle_bin",
            args.souffle_bin,
            "--working_dir",
            str(run_dir / "analysis"),
            "--cache_dir",
            str(cache),
            "--results_file",
            str(results_path),
            "--jobs",
            "1",
            "--timeout_secs",
            str(args.timeout),
            "--skip_sig_resolution",
            "--client",
            str(ROOT / "clients/reconstruction.dl"),
            "--debug",
        ]
        if args.interpreted:
            command.append("--interpreted")
        env = os.environ.copy()
        env["TMPDIR"] = str(run_dir)
        env.setdefault("OMP_NUM_THREADS", "2")
        print("Running Gigahorse; initial compiled runs can take several minutes.", file=sys.stderr)
        with (run_dir / "upstream.log").open("w+") as stream:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=stream)
            stream.seek(0)
            log = stream.read()
        if result.returncode:
            raise ValueError(f"Gigahorse exited with status {result.returncode}:\n{log[-6000:]}")
        if not results_path.is_file():
            raise ValueError(f"Gigahorse did not produce a status report:\n{log[-6000:]}")
        results = json.loads(results_path.read_text())
        if len(results) != 1 or len(results[0]) < 3:
            raise ValueError(f"Unexpected Gigahorse status report: {results!r}")
        flags = results[0][2]
        if flags:
            raise ValueError(f"Gigahorse reported flags {flags!r}:\n{log[-6000:]}")
        write_bundle(
            run_dir / "analysis/contract/out",
            args.output,
            {
                "engine": "Gigahorse",
                "input_sha256": hashlib.sha256(bytes.fromhex(bytecode)).hexdigest(),
                "input_kind": "runtime-bytecode",
                "signature_resolution": False,
                "interpreted": args.interpreted,
                "upstream_results": results,
                "semantic_export_sha256": hashlib.sha256(
                    (ROOT / "clients/reconstruction.dl").read_bytes()
                ).hexdigest(),
                "semantic_implementation_sha256": semantic_implementation_hash(),
            },
            log,
            args.signatures,
            args.online_signatures,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Check the local native runtime")
    doctor.add_argument("--souffle-bin", default="souffle")
    render = commands.add_parser("render", help="Render an existing Gigahorse out directory")
    render.add_argument("relations", type=Path)
    render.add_argument("--output", type=Path, required=True, help="A new bundle directory")
    analyze = commands.add_parser("decompile", help="Analyze a runtime bytecode hex file")
    analyze.add_argument("bytecode", type=Path)
    analyze.add_argument("--output", type=Path, required=True, help="A new bundle directory")
    analyze.add_argument("--souffle-bin", default="souffle")
    analyze.add_argument(
        "--timeout", type=int, default=120, help="Upstream analysis timeout in seconds"
    )
    analyze.add_argument("--interpreted", action="store_true", help="Avoid initial C++ compilation")
    for command in (render, analyze):
        command.add_argument(
            "--signatures",
            type=Path,
            help="Optional local selector/signature TSV; requires the naming extra. Labels remain hints.",
        )
        command.add_argument(
            "--online-signatures",
            action="store_true",
            help="Opt-in: look up unresolved selectors/topics on openchain.xyz (discloses them), "
            "keep only hash-checked names, and cache them under cache/signatures/ for offline reuse.",
        )
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            status = dependency_status(args.souffle_bin)
            print(json.dumps(status, indent=2))
            return int(any(value.startswith("ERROR:") for value in status.values()))
        if args.command == "render":
            write_bundle(
                args.relations,
                args.output,
                {"engine": "Gigahorse", "input_kind": "existing-relations"},
                signature_file=args.signatures,
                online_signatures=args.online_signatures,
            )
        else:
            if args.timeout < 1:
                raise ValueError("--timeout must be positive")
            decompile(args)
        print(f"Wrote {args.output.resolve()}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
