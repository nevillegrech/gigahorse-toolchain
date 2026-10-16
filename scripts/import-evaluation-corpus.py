#!/usr/bin/env python3
"""Import the locked, specifically selected Sourcify responses from a local cache.

No network requests are made. Runtime bytecode is the analysis input; ABI and
compiler information remain separate evaluation ground truth.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT))
    from reconstruct import normalize_bytecode

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=ROOT / "fixtures/evaluation/corpus.json")
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    existing = {}
    for path in (ROOT / "tests").rglob("*.hex"):
        try:
            data = bytes.fromhex(normalize_bytecode(path.read_text()))
        except (ValueError, UnicodeError):
            continue
        existing.setdefault(hashlib.sha256(data).hexdigest(), []).append(
            str(path.relative_to(ROOT))
        )
    for case in corpus["contracts"]:
        source = args.source_dir / f"{case['id']}-sourcify.json"
        response = json.loads(source.read_text())
        retrieval = json.loads((args.source_dir / f"{case['id']}-retrieval.json").read_text())
        if (
            str(response["chainId"]) != str(case["chain_id"])
            or response["address"].lower() != case["address"].lower()
        ):
            raise SystemExit(f"Wrong contract response for {case['id']}")
        if response["runtimeMatch"] not in {"match", "exact_match"}:
            raise SystemExit(f"Unverified runtime for {case['id']}")
        response_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        if response_hash != retrieval["response_sha256"]:
            raise SystemExit(f"Changed cached response for {case['id']}")
        code = normalize_bytecode(response["runtimeBytecode"]["onchainBytecode"])
        digest = hashlib.sha256(bytes.fromhex(code)).hexdigest()
        metadata = {
            "schema_version": 1,
            "selection_id": corpus["selection_id"],
            "id": case["id"],
            "chain_id": case["chain_id"],
            "address": case["address"],
            "bytecode_sha256": digest,
            "bytecode_size": len(code) // 2,
            "provenance": retrieval,
            "bytecode_origin": "Sourcify's archived onchain runtime, locked by hash; not a fresh or historical-block RPC verification",
            "runtime_match": response["runtimeMatch"],
            "verified_at": response["verifiedAt"],
            "match_id": response["matchId"],
            "deployment": response.get("deployment"),
            "compilation": response["compilation"],
            "abi": response["abi"],
            "functions": response["signatures"]["function"],
            "upstream_bytecode_duplicates": sorted(existing.get(digest, [])),
            "analysis_inputs": [f"{case['id']}.hex"],
            "ground_truth_supplied_to_reconstructor": False,
        }
        for path, text in (
            (args.corpus.parent / f"{case['id']}.hex", code + "\n"),
            (args.corpus.parent / f"{case['id']}.json", json.dumps(metadata, indent=2) + "\n"),
        ):
            if path.exists() and path.read_text() != text:
                raise SystemExit(f"Locked corpus file differs: {path}")
            path.write_text(text)
        print(
            f"Imported {case['id']}: {len(code) // 2} bytes, sha256={digest}, upstream duplicates={len(existing.get(digest, []))}"
        )


if __name__ == "__main__":
    main()
