#!/usr/bin/env python3
"""Compare decompiled.sol.txt with a same-bytecode Dedaub export, both scored against the ABI.

Both texts get the same measurements: whole-file code lines (non-blank,
non-comment), lines that touch raw memory or calldata, decoded revert reasons,
emitted events and loops. Both public interfaces are scored with the held-out
scorer (scripts/evaluate-heldout.py): Dedaub's selectors and signatures come
from its dispatcher, its argument types and payability from the function
headers. Dedaub prints no return types, so its returns count as unresolved.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("heldout", ROOT / "scripts/evaluate-heldout.py")
assert _spec is not None and _spec.loader is not None
heldout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(heldout)

# Selector tests in Dedaub's dispatcher: `0x.. == v0`, `v0 == 0x..`,
# `require(0x.. == v0)` (then the call `name(types);` on the next line), and
# Vyper-style `function_selector != 0x..` with the body inlined (no call line).
SELECTOR_TEST = re.compile(
    r"0x([0-9a-fA-F]{1,8}) == (?:v\d+|function_selector(?: >> 224)?)\b"
    r"|\b(?:v\d+|function_selector(?: >> 224)?) [!=]= 0x([0-9a-fA-F]{1,8})\b"
)
KEYWORDS = {"require", "revert", "assert", "return", "exit", "emit", "selfdestruct"}
CALL_LINE = re.compile(r"^\s*([A-Za-z_$][\w$]*|0x[0-9a-fA-F]+)\((.*)\);\s*$")
HEADER = re.compile(r"^    function (\S+?)\((.*?)\) (public|external)([^{]*)\{", re.M)
RAW = re.compile(r"MEM\[|msg\.data\[|\b(?:CALLDATA|RETURNDATA|CODE|EXTCODE|M)COPY\(")


def code_lines(text: str) -> list[str]:
    return [
        line.split("//")[0]
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("//")
    ]


def readability(text: str) -> dict:
    code = code_lines(text)
    body = "\n".join(code)
    return {
        "code_lines": len(code),
        "raw_lines": sum(1 for line in code if RAW.search(line)),
        "error_reasons": len(re.findall(r"Error\(['\"]", body)),
        "events": len(re.findall(r"\bemit \w+\(", body)),
        "loops": len(re.findall(r"\b(?:while|for) \(", body)),
    }


def _top_level(params: str) -> list[str]:
    """Split at commas outside parentheses (Dedaub prints tuple types inline)."""
    parts, depth, current = [], 0, ""
    for char in params:
        depth += char == "("
        depth -= char == ")"
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def _param_type(param: str) -> str:
    return param.rsplit(" ", 1)[0] if " " in param else param


def _arity(signature_types: str) -> int:
    return len(_top_level(signature_types))


def dedaub_interface(text: str) -> dict[str, dict]:
    headers: dict[str, list[dict]] = {}
    for name, params, _visibility, modifiers in HEADER.findall(text):
        types = [_param_type(param) for param in _top_level(params)]
        headers.setdefault(name, []).append({"types": types, "modifiers": modifiers.split()})
    start = text.find("function __function_selector__")
    lines = text[start:].splitlines() if start >= 0 else []
    result: dict[str, dict] = {}
    for index, line in enumerate(lines):
        for match in SELECTOR_TEST.finditer(line):
            selector = "0x" + (match.group(1) or match.group(2)).lower().rjust(8, "0")
            following = next((x for x in lines[index + 1 :] if x.strip()), "")
            call = CALL_LINE.match(following) if "==" in match.group(0) else None
            if call is not None and call.group(1) in KEYWORDS:
                call = None
            if call is None:
                result.setdefault(
                    selector,
                    {"hint": None, "name": None, "types": None, "payable": None, "returns": None},
                )
                continue
            name, signature_types = call.groups()
            candidates = headers.get(name, [])
            header = next(
                (h for h in candidates if len(h["types"]) == _arity(signature_types)),
                candidates[0] if len(candidates) == 1 else None,
            )
            result[selector] = {
                "hint": None if name.startswith("0x") else f"{name}({signature_types})",
                "name": name,
                "types": header["types"] if header else None,
                "payable": ("payable" in header["modifiers"]) if header else None,
                "returns": None,
            }
    return result


def wrong_by_kind(claims: list[str]) -> dict[str, int]:
    kinds = {"name": 0, "arity": 0, "argument type": 0, "payability": 0, "returns": 0}
    for claim in claims:
        detail = claim.split(": ", 1)[1]
        if detail.startswith("name"):
            kinds["name"] += 1
        elif detail.startswith("arity"):
            kinds["arity"] += 1
        elif detail.startswith("arg"):
            kinds["argument type"] += 1
        elif detail.startswith("returns"):
            kinds["returns"] += 1
        else:
            kinds["payability"] += 1
    return kinds


def compare(ours: str, dedaub: str, abi: list[dict]) -> dict:
    truth = heldout.abi_functions(abi)
    result = {}
    for label, text, view in (
        ("local", ours, heldout.parse_view(ours)),
        ("dedaub", dedaub, dedaub_interface(dedaub)),
    ):
        score = heldout.score(view, truth)
        result[label] = {
            **readability(text),
            "public_functions": len([s for s in view if s != "0x00000000"]),
            "score": score,
            "wrong_by_kind": wrong_by_kind(score["wrong_claims"]),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--bundles", type=Path, required=True, help="evaluate-heldout output")
    parser.add_argument("--dedaub", type=Path, required=True, help="<id>.sol.txt exports")
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    report = {"selection_id": corpus["selection_id"], "contracts": []}
    for case in corpus["contracts"]:
        ident = case["id"]
        ours_path = args.bundles / ident / "decompiled.sol.txt"
        dedaub_path = args.dedaub / f"{ident}.sol.txt"
        if (args.only and ident not in args.only) or not dedaub_path.is_file():
            continue
        if not ours_path.is_file():
            report["contracts"].append({"id": ident, "local": "no output (analysis failed)"})
            continue
        abi = json.loads((args.corpus.parent / f"{ident}.abi.json").read_text())
        entry = {"id": ident, "address": case["address"]}
        entry.update(compare(ours_path.read_text(), dedaub_path.read_text(), abi))
        report["contracts"].append(entry)
        for label in ("local", "dedaub"):
            side, score = entry[label], entry[label]["score"]
            print(
                f"{ident:30} {label:6} lines {side['code_lines']:5} raw {side['raw_lines']:4} "
                f"selectors {score['selectors_recovered']}/{score['abi_functions']} "
                f"names {score['names']} args {score['argument_types']} "
                f"wrong {side['wrong_by_kind']}"
            )
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
