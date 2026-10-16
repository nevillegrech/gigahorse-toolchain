#!/usr/bin/env python3
"""Capture native memory writer->consumer links next to a frozen fixture snapshot.

The links come from a bundle produced by the same native run as the fixture.
The bundle's TAC statements and opcodes must equal the fixture's exactly, so
links cannot be attached to different IR. Existing fixture files are untouched.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path


def rows(path: Path) -> list[list[str]]:
    with path.open() as stream:
        return list(csv.reader(stream, delimiter="\t"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relations", type=Path, help="bundle relations directory")
    parser.add_argument(
        "fixture", type=Path, help="fixture prefix, e.g. fixtures/evaluation-next/weth9"
    )
    args = parser.parse_args()
    snapshot = json.loads(args.fixture.with_suffix(".relations.json").read_text())
    expected = sorted(tuple(r) for r in snapshot["TAC_Op"])
    actual = sorted(tuple(r) for r in rows(args.relations / "TAC_Op.csv"))
    if expected != actual:
        raise SystemExit("Bundle IR differs from the fixture snapshot; refusing to attach links")
    stable = args.relations / "SemanticMemoryConsumerWrite.csv"
    if stable.is_file():
        links, source = rows(stable), "SemanticMemoryConsumerWrite"
    else:
        debug = rows(args.relations / "MemWriteToMemConsStmtResolved.csv")
        links = [[r[1], r[0], r[2], r[3], r[4]] for r in debug]
        source = "MemWriteToMemConsStmtResolved (debug output of the same native run)"
    bytecode = (args.relations / "bytecode.hex").read_text().strip().removeprefix("0x")
    output = args.fixture.with_suffix(".memory-links.json")
    output.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_relation": source,
                "bytecode_sha256": hashlib.sha256(bytes.fromhex(bytecode)).hexdigest(),
                "tac_op_sha256": hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                "SemanticMemoryConsumerWrite": sorted(links),
            },
            indent=1,
        )
        + "\n"
    )
    print(f"Wrote {output} ({len(links)} links)")


if __name__ == "__main__":
    main()
