#!/usr/bin/env python3
"""Compile the Vyper fixture with each pinned compiler (one per dispatcher form).

Compilers are given as VERSION=PATH pairs (e.g. 0.3.10=/path/to/vyper); each
must report that exact version. Writes vyper-<variant>.hex and .json next to
the source, like scripts/compile-reconstruction-fixtures.py does for solc.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/reconstruction"
SOURCE = FIXTURES / "VyperFixture.vy"
# variant -> (compiler version, optimization setting or None for the compiler default)
VARIANTS = {
    "v0216": ("0.2.16", None),
    "v039": ("0.3.9", None),
    "v0310": ("0.3.10", "gas"),
    "v0310-codesize": ("0.3.10", "codesize"),
}


def compile_variant(variant: str, compiler: str) -> None:
    version, optimize = VARIANTS[variant]
    reported = subprocess.check_output([compiler, "--version"], text=True).strip()
    if not reported.startswith(version + "+"):
        raise SystemExit(f"{compiler} is {reported}, not {version}")
    settings: dict = {"outputSelection": {"*": ["evm.bytecode", "evm.deployedBytecode", "abi"]}}
    if optimize is not None:
        settings["optimize"] = optimize
    request = {
        "language": "Vyper",
        "sources": {SOURCE.name: {"content": SOURCE.read_text()}},
        "settings": settings,
    }
    result = subprocess.run(
        [compiler + "-json"], input=json.dumps(request), capture_output=True, text=True, check=True
    )
    response = json.loads(result.stdout)
    errors = [e for e in response.get("errors", []) if e.get("severity") == "error"]
    if errors:
        raise SystemExit(json.dumps(errors, indent=2))
    compiled = next(iter(response["contracts"][SOURCE.name].values()))
    runtime = compiled["evm"]["deployedBytecode"]["object"].removeprefix("0x")
    creation = compiled["evm"]["bytecode"]["object"].removeprefix("0x")
    abi = compiled["abi"]
    identifiers = {}
    for item in abi:
        if item.get("type") == "function":
            signature = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
            identifiers[signature] = _selector(signature)
    stem = f"vyper-{variant}"
    (FIXTURES / f"{stem}.hex").write_text(runtime + "\n")
    manifest = {
        "compiler": reported,
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "bytecode_sha256": hashlib.sha256(bytes.fromhex(runtime)).hexdigest(),
        "settings": settings,
        "method_identifiers": identifiers,
        "abi": abi,
        "creation_bytecode": creation,
    }
    (FIXTURES / f"{stem}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Generated {stem}: {len(runtime) // 2} bytes ({reported}, optimize={optimize})")


def _selector(signature: str) -> str:
    from eth_utils import keccak

    return keccak(text=signature)[:4].hex()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compilers", nargs="+", help="VERSION=PATH")
    args = parser.parse_args()
    paths = dict(item.split("=", 1) for item in args.compilers)
    for variant, (version, _) in VARIANTS.items():
        if version in paths:
            compile_variant(variant, paths[version])


if __name__ == "__main__":
    main()
