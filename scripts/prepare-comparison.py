#!/usr/bin/env python3
"""Prepare review links and optionally import hash-matched Dedaub exports.

This makes no network requests, creates no vendor jobs and computes no parity
score. Vendor exports use the normalized container documented in EVALUATION.md.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate_vendor_export(path, expected_hash):
    sys.path.insert(0, str(ROOT))
    from reconstruct import normalize_bytecode

    data = json.loads(path.read_text())
    required = ("bytecode", "vendor", "representation", "code", "source_url", "captured_at")
    if not isinstance(data, dict) or any(not isinstance(data.get(k), str) for k in required):
        raise ValueError(
            "Vendor export needs bytecode, code, representation and provenance strings"
        )
    code = bytes.fromhex(normalize_bytecode(data["bytecode"]))
    if hashlib.sha256(code).hexdigest() != expected_hash:
        raise ValueError("Vendor output is for different runtime bytecode")
    if data["vendor"] != "Dedaub" or data["representation"] not in {
        "decompiled",
        "decompiled-yul",
        "ai-reconstructed",
    }:
        raise ValueError("Unsupported vendor or representation")
    if (
        not data.get("code", "").strip()
        or not data.get("source_url")
        or not data.get("captured_at")
    ):
        raise ValueError("Vendor export lacks code or provenance")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=ROOT / "fixtures/evaluation/corpus.json")
    parser.add_argument("--baselines", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.evaluation / "report.json").read_text())
    corpus = json.loads(args.corpus.read_text())
    if (
        not report.get("finished_at")
        or report["corpus_sha256"] != hashlib.sha256(args.corpus.read_bytes()).hexdigest()
        or report["implementation_changed_during_run"]
    ):
        raise ValueError("Evaluation corpus or implementation provenance is inconsistent")
    args.output.mkdir(parents=True, exist_ok=False)
    results = {r["id"]: r for r in report["results"]}
    packet = {
        "schema_version": 1,
        "selection_id": corpus["selection_id"],
        "parity": "not-assessed",
        "contracts": [],
    }
    lines = [
        "# Decompiler comparison packet",
        "",
        "Local coverage is measured. Dedaub parity and behavioral equivalence remain unproven.",
        "",
        "| Contract | Local output | Dedaub output |",
        "| --- | --- | --- |",
    ]
    for case in corpus["contracts"]:
        result = results[case["id"]]
        bytecode = bytes.fromhex((args.corpus.parent / f"{case['id']}.hex").read_text().strip())
        digest = hashlib.sha256(bytecode).hexdigest()
        if digest != result["bytecode_sha256"]:
            raise ValueError("Evaluation references different bytecode")
        record = {
            "id": case["id"],
            "bytecode_sha256": digest,
            "vendor_bytecode_md5": hashlib.md5(bytecode, usedforsecurity=False).hexdigest(),
            "local_status": result["status"],
            "vendor_status": "not-provided",
            "documented_vendor_artifact_url": "https://api.dedaub.com/api/on_demand/decompilation/"
            + hashlib.md5(bytecode, usedforsecurity=False).hexdigest(),
            "vendor_docs": "https://docs.dedaub.com/docs/api/nested/",
            "inspection_tasks": case["inspection_tasks"],
        }
        local = (args.evaluation / case["id"] / "bundle/structured.sol.txt").resolve()
        record["local_output"] = str(local) if local.exists() else None
        vendor_link = "Pending export/access"
        baseline = args.baselines / f"{case['id']}.json" if args.baselines else None
        if baseline and baseline.exists():
            try:
                vendor = validate_vendor_export(baseline, digest)
                destination = args.output / f"{case['id']}.dedaub.txt"
                destination.write_text(vendor["code"])
                record.update(
                    {
                        "vendor_status": "available",
                        "vendor_representation": vendor["representation"],
                        "vendor_code_sha256": hashlib.sha256(vendor["code"].encode()).hexdigest(),
                        "vendor_source_url": vendor["source_url"],
                        "vendor_captured_at": vendor["captured_at"],
                    }
                )
                vendor_link = f"[{vendor['representation']}]({destination.resolve()})"
            except (ValueError, KeyError) as exc:
                record["vendor_status"] = "rejected"
                record["vendor_error"] = str(exc)
                vendor_link = "Rejected: input/provenance mismatch"
        local_link = f"[Structured view]({local})" if local.exists() else result["status"]
        lines.append(f"| {case['id']} | {local_link} | {vendor_link} |")
        packet["contracts"].append(record)
    for record in packet["contracts"]:
        lines.extend(
            [
                "",
                "## " + record["id"],
                "",
                "Runtime SHA-256: `" + record["bytecode_sha256"] + "`",
                "",
            ]
        )
        lines.extend("- [ ] " + task for task in record["inspection_tasks"])
    (args.output / "requests.json").write_text(json.dumps(packet, indent=2) + "\n")
    (args.output / "review.md").write_text("\n".join(lines) + "\n")
    print("Wrote " + str(args.output / "review.md"))
    if any(c["vendor_status"] == "rejected" for c in packet["contracts"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
