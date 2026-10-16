#!/usr/bin/env python3
"""Rerun the semantic client on retained native IR, with explicit provenance."""

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT))
    from reconstruct import (
        check_dependencies,
        normalize_bytecode,
        scratch_root,
        semantic_implementation_hash,
        write_bundle,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("facts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--souffle-bin", default="souffle")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Output already exists; choose a new directory")
    check_dependencies(args.souffle_bin)
    bytecode = normalize_bytecode((args.facts / "bytecode.hex").read_text())
    client_hash = semantic_implementation_hash()
    with tempfile.TemporaryDirectory(prefix="semantic-refresh-", dir=scratch_root()) as temp:
        temporary = Path(temp)
        destination = temporary / "exports"
        destination.mkdir()
        merged = temporary / "relations"
        shutil.copytree(args.facts, merged)
        # Legacy exports remain usable; absent entry/edge evidence stays unknown.
        for optional in ("TAC_PhiInput.csv", "TAC_PhiEntryInput.csv"):
            (merged / optional).touch(exist_ok=True)
        command = [
            args.souffle_bin,
            "-j",
            "2",
            "-F",
            str(merged.resolve()),
            "-D",
            str(destination),
            "-L",
            str(ROOT / "souffle-addon"),
            str(ROOT / "clients/reconstruction.dl"),
        ]
        with (temporary / "native.log").open("w+") as stream:
            process = subprocess.Popen(
                command, cwd=ROOT, stdout=stream, stderr=stream, start_new_session=True
            )
            try:
                code = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise SystemExit("Semantic client timed out") from None
            stream.seek(0)
            log = stream.read()
        if client_hash != semantic_implementation_hash():
            raise SystemExit(
                "Semantic sources changed during native analysis; rerun on a stable source tree"
            )
        if code:
            raise SystemExit(f"Semantic client failed ({code}):\n{log[-6000:]}")
        for path in destination.glob("Semantic*.csv"):
            shutil.copy2(path, merged / path.name)
        write_bundle(
            merged,
            args.output,
            {
                "engine": "Gigahorse",
                "input_sha256": hashlib.sha256(bytes.fromhex(bytecode)).hexdigest(),
                "bytecode_lifting_reused": True,
                "semantic_analysis_refreshed": True,
                "semantic_implementation_sha256": client_hash,
                "source_relations": str(args.facts),
                "native_command": command,
            },
            log,
        )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "bytecode_sha256": hashlib.sha256(bytes.fromhex(bytecode)).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
