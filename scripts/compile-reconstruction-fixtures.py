#!/usr/bin/env python3
"""Regenerate known-source fixtures using the pinned external solc binary."""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/reconstruction"


def main():
    version = subprocess.check_output(["solc", "--version"], text=True).strip()
    if "Version: 0.8.30+commit.73712a01." not in version:
        raise SystemExit("Use solc 0.8.30+commit.73712a01 to regenerate these fixtures")
    for contract, prefix in (
        ("StorageFixture", "storage"),
        ("LayoutFixture", "layout"),
        ("ControlFlowFixture", "control-flow"),
        ("InteractionFixture", "interaction"),
        ("CopyFixture", "copy"),
        ("ExpressionFixture", "expression"),
        ("AliasFixture", "alias"),
        ("FailureFixture", "failure"),
        ("ParameterFixture", "parameter"),
    ):
        compile_fixture(contract, prefix, version)


def compile_fixture(contract: str, prefix: str, version: str):
    source = FIXTURES / f"{contract}.sol"
    for via_ir in (False, True):
        settings = {
            "optimizer": {"enabled": True, "runs": 200},
            "viaIR": via_ir,
            "evmVersion": "cancun",
            "metadata": {"bytecodeHash": "none", "appendCBOR": False},
            "outputSelection": {
                "*": {
                    "*": [
                        "evm.deployedBytecode.object",
                        "evm.bytecode.object",
                        "evm.methodIdentifiers",
                        "storageLayout",
                        "abi",
                    ]
                }
            },
        }
        request = {
            "language": "Solidity",
            "sources": {source.name: {"content": source.read_text()}},
            "settings": settings,
        }
        result = subprocess.run(
            ["solc", "--standard-json"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            check=True,
        )
        response = json.loads(result.stdout)
        errors = [error for error in response.get("errors", []) if error["severity"] == "error"]
        if errors:
            raise SystemExit(json.dumps(errors, indent=2))
        compiled = response["contracts"][source.name][contract]
        evm = compiled["evm"]
        bytecode = evm["deployedBytecode"]["object"]
        stem = f"{prefix}-via-ir" if via_ir else f"{prefix}-optimized"
        (FIXTURES / f"{stem}.hex").write_text(bytecode + "\n")
        manifest = {
            "compiler": version,
            "source": source.name,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "bytecode_sha256": hashlib.sha256(bytes.fromhex(bytecode)).hexdigest(),
            "settings": settings,
            "method_identifiers": evm["methodIdentifiers"],
            "storage_layout": compiled["storageLayout"],
            "abi": compiled["abi"],
            "creation_bytecode": evm["bytecode"]["object"],
        }
        auxiliary = {
            name: {"creation_bytecode": data["evm"]["bytecode"]["object"]}
            for name, data in response["contracts"][source.name].items()
            if name != contract and data["evm"]["bytecode"]["object"]
        }
        if auxiliary:
            manifest["auxiliary_contracts"] = auxiliary
        (FIXTURES / f"{stem}.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Generated {stem}: {len(bytecode) // 2} bytes")


if __name__ == "__main__":
    main()
