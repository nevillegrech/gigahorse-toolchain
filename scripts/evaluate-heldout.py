#!/usr/bin/env python3
"""Analyze a frozen corpus and score decompiled.sol.txt against ABI ground truth.

The ABI is only read here, after analysis, to classify each printed claim as
correct, unresolved (left as a raw word / unnamed) or wrong. Wrong claims are
reported separately; unknowns are never counted as correct.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reconstruction.keccak import keccak256  # noqa: E402


def canonical(param: dict) -> str:
    kind = param["type"]
    if kind.startswith("tuple"):
        inner = ",".join(canonical(c) for c in param.get("components", []))
        return f"({inner}){kind[5:]}"
    return kind


def abi_functions(abi: list[dict]) -> dict[str, dict]:
    result = {}
    for item in abi or []:
        if item.get("type") != "function":
            continue
        signature = f"{item['name']}({','.join(canonical(p) for p in item.get('inputs', []))})"
        selector = "0x" + keccak256(signature.encode()).hex()[:8]
        result[selector] = {
            "name": item["name"],
            "signature": signature,
            "inputs": [canonical(p) for p in item.get("inputs", [])],
            "outputs": [canonical(p) for p in item.get("outputs", [])],
            "payable": item.get("stateMutability") == "payable" or item.get("payable") is True,
        }
    return result


def abi_events(abi: list[dict]) -> set[str]:
    return {item["name"] for item in abi or [] if item.get("type") == "event"}


SIGNATURE = re.compile(
    r"^    // (0x[0-9a-f]{8})(?: (\S+) \[dict\])?\n(?:    //   .*\n)*    function (\S+?)\((.*)\) public (payable|nonpayable|/\* payability unresolved \*/)(?: returns \((.*)\))? \{",
    re.M,
)


def parse_view(text: str) -> dict[str, dict]:
    functions = {}
    for match in SIGNATURE.finditer(text):
        selector, hint, name, params, mutability, returns = match.groups()
        types = [p.strip().rsplit(" ", 1)[0] for p in params.split(",") if p.strip()]
        functions[selector] = {
            "hint": hint,
            "name": name,
            "types": types,
            "payable": None if "unresolved" in mutability else mutability == "payable",
            "returns": [r.strip() for r in returns.split(",")] if returns else None,
        }
    return functions


def score(view: dict[str, dict], truth: dict[str, dict]) -> dict:
    counts = {
        "abi_functions": len(truth),
        "selectors_recovered": 0,
        "names": {"correct": 0, "unresolved": 0, "wrong": 0},
        "arity": {"correct": 0, "wrong": 0},
        "argument_types": {"correct": 0, "unresolved": 0, "wrong": 0, "dynamic_unresolved": 0},
        "payability": {"correct": 0, "wrong": 0},
        "returns": {"correct": 0, "unresolved": 0, "wrong": 0},
        "wrong_claims": [],
    }
    for selector, expected in truth.items():
        ours = view.get(selector)
        if ours is None:
            continue
        counts["selectors_recovered"] += 1
        if ours["hint"]:
            ok = ours["hint"] == expected["signature"]
            counts["names"]["correct" if ok else "wrong"] += 1
            if not ok:
                counts["wrong_claims"].append(
                    f"{selector}: name {ours['hint']} vs {expected['signature']}"
                )
        else:
            counts["names"]["unresolved"] += 1
        if len(ours["types"]) == len(expected["inputs"]):
            counts["arity"]["correct"] += 1
            for index, (mine, theirs) in enumerate(
                zip(ours["types"], expected["inputs"], strict=True)
            ):
                if mine == theirs:
                    counts["argument_types"]["correct"] += 1
                elif mine == "dynamic":
                    counts["argument_types"]["dynamic_unresolved"] += 1
                elif mine == "uint256":
                    # The raw-word default: unresolved unless the ABI also says uint256.
                    counts["argument_types"]["unresolved"] += 1
                elif (
                    theirs.startswith(("uint", "int", "bytes"))
                    and mine.startswith("uint")
                    and theirs != mine
                ):
                    # Width evidence that the source type does not show is a wrong claim.
                    counts["argument_types"]["wrong"] += 1
                    counts["wrong_claims"].append(f"{selector}: arg{index} {mine} vs {theirs}")
                else:
                    counts["argument_types"]["wrong"] += 1
                    counts["wrong_claims"].append(f"{selector}: arg{index} {mine} vs {theirs}")
        else:
            counts["arity"]["wrong"] += 1
            counts["wrong_claims"].append(
                f"{selector}: arity {len(ours['types'])} vs {len(expected['inputs'])}"
            )
        if ours["payable"] is None:
            counts["payability"]["unresolved"] = counts["payability"].get("unresolved", 0) + 1
        elif ours["payable"] == expected["payable"]:
            counts["payability"]["correct"] += 1
        else:
            counts["payability"]["wrong"] += 1
            counts["wrong_claims"].append(
                f"{selector}: {'payable' if ours['payable'] else 'nonpayable'} vs ABI "
                f"{'payable' if expected['payable'] else 'nonpayable'}"
            )
        if ours["returns"] is None:
            counts["returns"]["unresolved" if expected["outputs"] else "correct"] += 1
        elif len(ours["returns"]) == len(expected["outputs"]) and all(
            a == b or a == "uint256"
            for a, b in zip(ours["returns"], expected["outputs"], strict=True)
        ):
            exact = all(a == b for a, b in zip(ours["returns"], expected["outputs"], strict=True))
            counts["returns"]["correct" if exact else "unresolved"] += 1
        else:
            counts["returns"]["wrong"] += 1
            counts["wrong_claims"].append(
                f"{selector}: returns {ours['returns']} vs {expected['outputs']}"
            )
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--only", nargs="*")
    parser.add_argument(
        "--reuse", action="store_true", help="re-render existing bundles' relations"
    )
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"selection_id": corpus["selection_id"], "contracts": []}
    for case in corpus["contracts"]:
        ident = case["id"]
        if args.only and ident not in args.only:
            continue
        hex_path = args.corpus.parent / f"{ident}.hex"
        bundle = args.output / ident
        entry: dict = {"id": ident}
        started = time.monotonic()
        if args.reuse and (bundle / "relations").is_dir():
            rendered = args.output / f"{ident}.render"
            if rendered.exists():
                subprocess.run(["rm", "-rf", str(rendered)], check=True)
            command = [
                sys.executable,
                str(ROOT / "reconstruct.py"),
                "render",
                str(bundle / "relations"),
                "--output",
                str(rendered),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            subprocess.run(["rm", "-rf", str(bundle)], check=True)
            if result.returncode == 0:
                rendered.rename(bundle)
        else:
            if bundle.exists():
                subprocess.run(["rm", "-rf", str(bundle)], check=True)
            command = [
                sys.executable,
                str(ROOT / "reconstruct.py"),
                "decompile",
                str(hex_path),
                "--output",
                str(bundle),
                "--timeout",
                str(args.timeout),
            ]
            result = subprocess.run(command, capture_output=True, text=True)
        entry["seconds"] = round(time.monotonic() - started, 1)
        entry["status"] = "ok" if result.returncode == 0 else "failed"
        if result.returncode:
            entry["error"] = (result.stderr or result.stdout)[-1500:]
            report["contracts"].append(entry)
            print(f"{ident}: FAILED after {entry['seconds']}s")
            continue
        text = (bundle / "decompiled.sol.txt").read_text()
        mapping = json.loads((bundle / "decompiled.map.json").read_text())
        abi = json.loads((args.corpus.parent / f"{ident}.abi.json").read_text())
        truth = abi_functions(abi)
        view = parse_view(text)
        code_lines = [
            line for line in text.splitlines() if line.strip() and not line.strip().startswith("//")
        ]
        structured_text = (bundle / "structured.sol.txt").read_text()
        structured_lines = [
            line
            for line in structured_text.splitlines()
            if line.strip() and not line.strip().startswith("//")
        ]
        emitted = set(re.findall(r"emit (\w+)\(", text))
        entry.update(
            {
                "decompiled_code_lines": len(code_lines),
                "structured_code_lines": len(structured_lines),
                "unaccounted_ir_statements": len(mapping["unaccounted_ir_statements"]),
                "uncertain_lines": sum(1 for line in text.splitlines() if "UNCERTAIN" in line),
                "unstructured_functions": text.count("control flow not structured"),
                "recognized_idioms": len(mapping.get("recognized_idioms", [])),
                "events": {
                    "abi": sorted(abi_events(abi)),
                    "named_in_view": sorted(emitted & abi_events(abi)),
                    "unnamed_in_view": sorted(e for e in emitted if e.startswith("Event_")),
                },
                "score": score(view, truth),
            }
        )
        report["contracts"].append(entry)
        s = entry["score"]
        print(
            f"{ident}: {entry['seconds']}s, {entry['decompiled_code_lines']} lines "
            f"(structured {entry['structured_code_lines']}), selectors {s['selectors_recovered']}/{s['abi_functions']}, "
            f"names {s['names']}, args {s['argument_types']}, wrong claims {len(s['wrong_claims'])}, "
            f"uncertain {entry['uncertain_lines']}, unstructured {entry['unstructured_functions']}"
        )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
