#!/usr/bin/env python3
"""Save real native relations for offline regression, bound to locked bytecode."""

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT))
    from reconstruct import normalize_bytecode
    from reconstruction.interactions import COPY_TABLES, EXTERNAL_TABLES
    from reconstruction.memory import MEMORY_TABLES
    from reconstruction.model import load_program
    from reconstruction.semantics import TABLES
    from src.tac_schema import TACRelations

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--fixture")
    selection.add_argument("--evaluation-fixture")
    parser.add_argument(
        "--evaluation-dir",
        type=Path,
        default=ROOT / "fixtures/evaluation",
        help="Directory of the selected evaluation corpus (ABI remains scoring ground truth)",
    )
    args = parser.parse_args()
    fixture = (
        args.evaluation_dir / args.evaluation_fixture
        if args.evaluation_fixture
        else ROOT / "fixtures/reconstruction" / args.fixture
    )
    manifest = json.loads(fixture.with_suffix(".json").read_text())
    relations = args.bundle / "relations"
    bytecode = normalize_bytecode((relations / "bytecode.hex").read_text())
    digest = hashlib.sha256(bytes.fromhex(bytecode)).hexdigest()
    if digest != manifest["bytecode_sha256"]:
        raise SystemExit("Bundle bytecode does not match the selected fixture")
    program = load_program(relations)
    if program.semantics is None:
        raise SystemExit("Bundle is missing the stable semantic export")
    tac = TACRelations.from_dir(relations)
    core = {name: sorted(tac[name]) for name in sorted(tac.relation_names)}
    semantic = {}
    version = program.semantics.schema_version
    for suffix in (
        TABLES
        | (EXTERNAL_TABLES if version >= 2 else {})
        | (COPY_TABLES if version >= 3 else {})
        | (MEMORY_TABLES if program.semantics.memory_model else {})
    ):
        with (relations / f"Semantic{suffix}.csv").open() as stream:
            semantic[f"Semantic{suffix}"] = sorted(csv.reader(stream, delimiter="\t"))
    for extension, data in (("relations", core), ("semantic", semantic)):
        path = fixture.with_suffix(f".{extension}.json")
        path.write_text(json.dumps(data, indent=2) + "\n")
    if args.evaluation_fixture:
        fixture.with_suffix(".snapshot.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "bytecode_sha256": digest,
                    "semantic_schema": version,
                    "tables": {
                        extension: hashlib.sha256(
                            fixture.with_suffix(f".{extension}.json").read_bytes()
                        ).hexdigest()
                        for extension in ("relations", "semantic")
                    },
                    "source_bundle": str(args.bundle),
                    "evaluation_scope": "Calibration regression snapshot, not a new unseen contract",
                },
                indent=2,
            )
            + "\n"
        )
    print(f"Captured {fixture.name}: {digest}")


if __name__ == "__main__":
    main()
