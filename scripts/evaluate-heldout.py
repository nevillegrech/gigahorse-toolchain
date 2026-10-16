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
import shutil
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


STRUCT = re.compile(r"^    struct (S\d+) \{ (.*?) \}$", re.M)


def parse_view(text: str) -> dict[str, dict]:
    # Struct types the view declares (`struct S3 { address f0; uint256 f1; }`), as tuples.
    structs = {
        name: "(" + ",".join(f.split()[0] for f in body.split(";") if f.strip()) + ")"
        for name, body in STRUCT.findall(text)
    }
    functions = {}
    for match in SIGNATURE.finditer(text):
        selector, hint, name, params, mutability, returns = match.groups()
        types = (
            None  # the view failed for this function and claims no arguments
            if "arguments not recovered" in params
            else [
                structs.get(kind, kind)
                for kind in (p.strip().rsplit(" ", 1)[0] for p in params.split(",") if p.strip())
            ]
        )
        functions[selector] = {
            "hint": hint,
            "name": name,
            "types": types,
            "payable": None if "unresolved" in mutability else mutability == "payable",
            "returns": [r.strip() for r in returns.split(",")] if returns else None,
        }
    return functions


def flat_words(kind: str) -> list[str] | None:
    """Head words of a static ABI type (tuples flattened); None when dynamic."""
    if kind.startswith("(") and kind.endswith(")"):
        parts, depth, current = [], 0, ""
        for char in kind[1:-1]:
            depth += char == "("
            depth -= char == ")"
            if char == "," and depth == 0:
                parts.append(current)
                current = ""
            else:
                current += char
        if current:
            parts.append(current)
        words: list[str] = []
        for part in parts:
            inner = flat_words(part)
            if inner is None:
                return None
            words += inner
        return words
    if kind in {"bytes", "string"} or kind.endswith("[]"):
        return None
    if kind.endswith("]"):
        element, _, count = kind[:-1].rpartition("[")
        inner = flat_words(element)
        return inner * int(count) if inner is not None and count.isdigit() else None
    return [kind]


def compare_tuple(mine: str, theirs: str) -> str:
    """A printed struct parameter against the ABI type, word by word: a uint256
    word is the raw default (unresolved); a different word count is wrong."""
    ours, expected = flat_words(mine), flat_words(theirs)
    if ours is None or expected is None or len(ours) != len(expected):
        return "wrong"
    results = {
        "correct" if a == b else "unresolved" if a == "uint256" else "wrong"
        for a, b in zip(ours, expected, strict=True)
    }
    return "wrong" if "wrong" in results else "unresolved" if "unresolved" in results else "correct"


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
        if ours["types"] is None:
            # No signature printed for this selector (e.g. an inlined body): no claim.
            counts["arity"]["unresolved"] = counts["arity"].get("unresolved", 0) + 1
        elif len(ours["types"]) == len(expected["inputs"]):
            counts["arity"]["correct"] += 1
            for index, (mine, theirs) in enumerate(
                zip(ours["types"], expected["inputs"], strict=True)
            ):
                if mine == theirs:
                    counts["argument_types"]["correct"] += 1
                elif mine.startswith("("):
                    verdict = compare_tuple(mine, theirs)
                    counts["argument_types"][verdict] += 1
                    if verdict == "wrong":
                        counts["wrong_claims"].append(f"{selector}: arg{index} {mine} vs {theirs}")
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


def limited(command: list[str], memory_gb: float, seconds: int) -> tuple[list[str], str]:
    """Run under a memory cap (cgroup, swap off) and a wall-clock limit; report peak RSS.

    A runaway analysis is then killed on its own instead of exhausting the
    machine. GNU time reports the largest resident set in the process tree.
    """
    wrapped = ["timeout", "--signal=TERM", "--kill-after=30", str(seconds), *command]
    if Path("/usr/bin/time").is_file():
        wrapped = ["/usr/bin/time", "-f", "peak_rss_kb=%M", *wrapped]
    if shutil.which("systemd-run"):
        scope = ["systemd-run", "--user", "--scope", "--quiet"]
        scope += ["-p", f"MemoryMax={memory_gb}G", "-p", "MemorySwapMax=0"]
        return [*scope, *wrapped], f"systemd scope MemoryMax={memory_gb}G, swap off"
    return wrapped, "none (systemd-run unavailable): wall-clock limit only"


def failure_kind(returncode: int, seconds: float, limit: int, output: str) -> str:
    if returncode == 124 or seconds >= limit:
        return "timeout"
    if returncode in (137, -9) or "Killed" in output[-2000:]:
        return "killed (memory limit)"
    return "error"


def peak_rss_gb(output: str) -> float | None:
    found = re.findall(r"peak_rss_kb=(\d+)", output)
    return round(int(found[-1]) / 1024 / 1024, 2) if found else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300, help="native analysis timeout")
    parser.add_argument(
        "--memory-gb", type=float, default=16, help="memory cap per contract (whole process tree)"
    )
    parser.add_argument(
        "--wall-seconds", type=int, default=3600, help="wall-clock limit per contract, all steps"
    )
    parser.add_argument("--only", nargs="*")
    parser.add_argument(
        "--reuse", action="store_true", help="re-render existing bundles' relations"
    )
    parser.add_argument(
        "--resume", action="store_true", help="skip contracts already recorded in report.json"
    )
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    report_path = args.output / "report.json"
    report = {"selection_id": corpus["selection_id"], "contracts": []}
    _, mechanism = limited([], args.memory_gb, args.wall_seconds)
    report["limits"] = {
        "memory_gb": args.memory_gb,
        "wall_seconds": args.wall_seconds,
        "native_timeout_seconds": args.timeout,
        "mechanism": mechanism,
    }
    if args.resume and report_path.is_file():
        report = json.loads(report_path.read_text())
    done = {entry["id"] for entry in report["contracts"]}
    for case in corpus["contracts"]:
        ident = case["id"]
        if (args.only and ident not in args.only) or ident in done:
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
            command, _ = limited(command, args.memory_gb, args.wall_seconds)
            result = subprocess.run(command, capture_output=True, text=True)
            # Replace the bundle only after a successful render: its relations are the input.
            if result.returncode == 0:
                subprocess.run(["rm", "-rf", str(bundle)], check=True)
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
            command, _ = limited(command, args.memory_gb, args.wall_seconds)
            result = subprocess.run(command, capture_output=True, text=True)
        entry["seconds"] = round(time.monotonic() - started, 1)
        entry["peak_rss_gb"] = peak_rss_gb(result.stderr)
        entry["status"] = "ok" if result.returncode == 0 else "failed"
        if result.returncode:
            # Timeouts and kills are recorded as failures, never dropped.
            entry["failure"] = failure_kind(
                result.returncode, entry["seconds"], args.wall_seconds, result.stderr
            )
            entry["error"] = (result.stderr or result.stdout)[-1500:]
            report["contracts"].append(entry)
            report_path.write_text(json.dumps(report, indent=2) + "\n")
            print(f"{ident}: FAILED ({entry['failure']}) after {entry['seconds']}s", flush=True)
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
            f"{ident}: {entry['seconds']}s, peak {entry['peak_rss_gb']} GB, "
            f"{entry['decompiled_code_lines']} lines "
            f"(structured {entry['structured_code_lines']}), selectors {s['selectors_recovered']}/{s['abi_functions']}, "
            f"names {s['names']}, args {s['argument_types']}, wrong claims {len(s['wrong_claims'])}, "
            f"uncertain {entry['uncertain_lines']}, unstructured {entry['unstructured_functions']}",
            flush=True,
        )
        # Saved after every contract: an interrupted batch keeps its finished results.
        report_path.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
