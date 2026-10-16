"""Write captured native memory links next to a materialized fixture."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


def write_links(directory: Path, prefix: Path) -> int:
    """Write SemanticMemoryConsumerWrite.csv from a fixture's captured sidecar.

    The sidecar records a hash of the IR it was captured from; a mismatch fails.
    """
    sidecar = prefix.with_suffix(".memory-links.json")
    if not sidecar.is_file():
        return 0
    links = json.loads(sidecar.read_text())
    with (Path(directory) / "TAC_Op.csv").open() as stream:
        operations = sorted(tuple(r) for r in csv.reader(stream, delimiter="\t"))
    digest = hashlib.sha256(json.dumps([list(r) for r in operations]).encode()).hexdigest()
    assert digest == links["tac_op_sha256"], f"memory links do not match the IR of {prefix.name}"
    with (Path(directory) / "SemanticMemoryConsumerWrite.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerows(links["SemanticMemoryConsumerWrite"])
    return len(links["SemanticMemoryConsumerWrite"])
