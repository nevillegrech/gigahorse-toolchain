#!/usr/bin/env python3
"""Fetch runtime bytecode (and ABI as scoring ground truth) from Sourcify for a frozen corpus.

Responses are cached under --cache with their SHA-256 recorded. The ABI is
kept separately and is never given to the decompiler.
"""

import argparse
import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

API = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=runtimeBytecode,compilation,abi"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    out_dir = args.corpus.parent
    args.cache.mkdir(parents=True, exist_ok=True)
    for case in corpus["contracts"]:
        url = API.format(chain=case["chain_id"], address=case["address"])
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                raw = response.read()
        except Exception as exc:
            print(f"{case['id']}: unavailable ({exc})")
            continue
        (args.cache / f"{case['id']}-sourcify.json").write_bytes(raw)
        data = json.loads(raw)
        code = (data.get("runtimeBytecode") or {}).get("onchainBytecode") or ""
        code = code.removeprefix("0x")
        if not code:
            print(f"{case['id']}: no runtime bytecode in response")
            continue
        runtime = bytes.fromhex(code)
        (out_dir / f"{case['id']}.hex").write_text(runtime.hex() + "\n")
        (out_dir / f"{case['id']}.abi.json").write_text(
            json.dumps(data.get("abi"), indent=1) + "\n"
        )
        compilation = data.get("compilation") or {}
        (out_dir / f"{case['id']}.json").write_text(
            json.dumps(
                {
                    "id": case["id"],
                    "chain_id": case["chain_id"],
                    "address": case["address"],
                    "bytecode_sha256": hashlib.sha256(runtime).hexdigest(),
                    "bytecode_size": len(runtime),
                    "compiler": compilation.get("compilerVersion"),
                    "language": compilation.get("language"),
                    "runtime_match": data.get("runtimeMatch"),
                    "retrieved_at": datetime.now(UTC).isoformat(),
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                    "source": url,
                    "ground_truth_note": "ABI is scoring ground truth only; never supplied to analysis",
                },
                indent=2,
            )
            + "\n"
        )
        print(
            f"{case['id']}: {len(runtime)} bytes, {compilation.get('compilerVersion')}, {data.get('runtimeMatch')}"
        )


if __name__ == "__main__":
    main()
