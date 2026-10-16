#!/usr/bin/env python3
"""Run the frozen deployed-contract corpus with ABI ground truth withheld."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def implementation_hash():
    paths = {
        ROOT / "reconstruct.py",
        ROOT / "gigahorse.py",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
    }
    for folder in ("src", "logic", "clientlib", "reconstruction", "clients"):
        paths.update(p for p in (ROOT / folder).rglob("*") if p.suffix in {".py", ".dl"})
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def summarize(bundle, ground_truth):
    analysis = json.loads((bundle / "analysis.json").read_text())
    bytecode = bytes.fromhex((bundle / "relations/bytecode.hex").read_text().strip())
    if hashlib.sha256(bytecode).hexdigest() != ground_truth["bytecode_sha256"]:
        raise ValueError("Bundle bytecode differs from the selected evaluation input")
    if analysis["provenance"]["input_sha256"] != ground_truth["bytecode_sha256"]:
        raise ValueError("Bundle claims different bytecode provenance")
    source_map = json.loads((bundle / "structured.map.json").read_text())
    rendered_lines = (bundle / "structured.sol.txt").read_text().splitlines()
    selectors = {s for f in analysis["functions"] for s in f["selectors"]}
    expected = {f["signatureHash4"] for f in ground_truth["functions"]}
    semantics = analysis.get("semantics") or {}
    plans = source_map.get("control_flow", [])
    signature_candidates = (analysis.get("signature_info") or {}).get("candidates", {})
    return {
        "selectors_expected": len(expected),
        "selectors_recovered": len(expected & selectors),
        "missing_selectors": [
            f for f in ground_truth["functions"] if f["signatureHash4"] not in selectors
        ],
        "ir_functions": len(analysis["functions"]),
        "structured_functions": sum(p["status"] == "structured" for p in plans),
        "partially_structured_functions": sum(p["status"] == "structured-partial" for p in plans),
        "cfg_fallback_functions": sum(
            p["status"] not in {"structured", "structured-partial"} for p in plans
        ),
        "functions_with_unresolved_phis": sum(bool(p["unresolved_phis"]) for p in plans),
        "blocks": len(analysis["blocks"]),
        "ir_instructions": sum(len(b["instructions"]) for b in analysis["blocks"]),
        "unmapped_original_statements": len(analysis["unmapped_statements"]),
        "inferred_storage_fields": len(semantics.get("storage_fields", [])),
        "inferred_argument_records": len(semantics.get("arguments", [])),
        "observed_calldata_fields": len(analysis.get("calldata_fields", [])),
        "calldata_fields_with_check_constraints": sum(
            bool(f["constraints"]) for f in analysis.get("calldata_fields", [])
        ),
        "candidate_dynamic_return_layouts": sum(
            r["status"] == "candidate_dynamic_encoding" for r in analysis.get("return_layouts", [])
        ),
        "raw_word_return_layouts": sum(
            r["status"] == "raw_words" for r in analysis.get("return_layouts", [])
        ),
        "candidate_raw_word_return_layouts": sum(
            r["status"] == "candidate_raw_words" for r in analysis.get("return_layouts", [])
        ),
        "withheld_native_constant_hints": len(analysis.get("constant_hints", {})),
        "cfg_derived_numeric_constants": len(analysis.get("derived_constants", {})),
        "private_interfaces_with_control_argument_omitted": len(
            analysis.get("internal_interfaces", [])
        ),
        "private_call_sites_with_control_argument_omitted": sum(
            len(interface["call_sites"]) for interface in analysis.get("internal_interfaces", [])
        ),
        "unresolved_return_layouts": sum(
            r["status"] == "unresolved" for r in analysis.get("return_layouts", [])
        ),
        "static_revert_payloads": sum(
            r["status"] == "static" for r in analysis.get("revert_summaries", [])
        ),
        "decoded_error_string_payloads": sum(
            r["encoding"] == "Error(string)" for r in analysis.get("revert_summaries", [])
        ),
        "decoded_panic_payloads": sum(
            r["encoding"] == "Panic(uint256)" for r in analysis.get("revert_summaries", [])
        ),
        "partial_revert_payloads": sum(
            r["status"] == "partial" for r in analysis.get("revert_summaries", [])
        ),
        "unresolved_revert_payloads": sum(
            r["status"] == "unresolved" for r in analysis.get("revert_summaries", [])
        ),
        "guards_with_revert_payload": len(source_map.get("guard_revert_payloads", {})),
        "folded_revert_encoders": len(source_map.get("revert_folds", [])),
        "folded_revert_blocks": sum(len(f["blocks"]) for f in source_map.get("revert_folds", [])),
        "folded_revert_ir_instructions": sum(
            len(f["ir_statements"]) for f in source_map.get("revert_folds", [])
        ),
        "inferred_storage_roles": len((analysis.get("behavior") or {}).get("storage_roles", [])),
        "delegate_sites": len((analysis.get("behavior") or {}).get("delegate_sites", [])),
        "whole_calldata_delegate_sites": sum(
            s["whole_calldata"] is True
            for s in (analysis.get("behavior") or {}).get("delegate_sites", [])
        ),
        "returndata_forwarding_delegate_sites": sum(
            s["return_data_forwarding"] == "established_in_recovered_cfg"
            for s in (analysis.get("behavior") or {}).get("delegate_sites", [])
        ),
        "ignored_terminal_ir_edges": sum(
            len(t.get("ignored_terminal_targets", []))
            for f in plans
            for t in f["transfers"].values()
        ),
        "inferred_calldata_view_roots": sum(
            len(f["roots"]) for f in analysis.get("calldata_views", [])
        ),
        "calldata_path_bindings": sum(
            len(f["bindings"]) for f in analysis.get("calldata_views", [])
        ),
        "dynamic_calldata_byte_copies": sum(
            len(f["byte_copies"]) for f in analysis.get("calldata_views", [])
        ),
        "external_ir_calls": len(semantics.get("external_calls", [])),
        "external_selectors_inferred": sum(
            c["selector_resolved"] for c in semantics.get("external_calls", [])
        ),
        "warnings": len(analysis["warnings"]),
        "structured_output_lines": len(rendered_lines),
        "structured_output_characters": len((bundle / "structured.sol.txt").read_text()),
        "maximum_indentation_levels": max(
            ((len(line) - len(line.lstrip())) // 4 for line in rendered_lines), default=0
        ),
        "selectors_with_signature_hints": len(expected & signature_candidates.keys()),
        "selectors_with_unique_signature_hints": sum(
            len(signature_candidates.get(s, [])) == 1 for s in expected
        ),
    }


def analyze(case, corpus_dir, output, deadline, timeout, reuse_relations=None, signatures=None):
    case_dir = output / case["id"]
    case_dir.mkdir()
    ground_truth = json.loads((corpus_dir / f"{case['id']}.json").read_text())
    bytecode = corpus_dir / f"{case['id']}.hex"
    if (
        hashlib.sha256(bytes.fromhex(bytecode.read_text().strip())).hexdigest()
        != ground_truth["bytecode_sha256"]
    ):
        raise ValueError(f"Changed evaluation input: {case['id']}")
    bundle = case_dir / "bundle"
    command = [
        sys.executable,
        str(ROOT / "reconstruct.py"),
        "decompile",
        str(bytecode),
        "--interpreted",
        "--timeout",
        str(timeout),
        "--output",
        str(bundle),
    ]
    if reuse_relations:
        command = [
            sys.executable,
            str(ROOT / "reconstruct.py"),
            "render",
            str(reuse_relations / case["id"] / "bundle/relations"),
            "--output",
            str(bundle),
        ]
    if signatures:
        command.extend(["--signatures", str(signatures)])
    record = {
        "id": case["id"],
        "address": case["address"],
        "chain_id": case["chain_id"],
        "bytecode_sha256": ground_truth["bytecode_sha256"],
        "compiler": ground_truth["compilation"]["compilerVersion"],
        "command": command,
        "ground_truth_supplied_to_reconstructor": False,
        "native_analysis_reused": reuse_relations is not None,
        "dedaub_comparison": "unavailable-no-output",
        "behavioral_equivalence": "not-measured",
        "inspection_tasks": [
            {"task": task, "local": "not-reviewed", "dedaub": "not-reviewed"}
            for task in case["inspection_tasks"]
        ],
    }
    started = time.monotonic()
    print("Running " + case["id"], flush=True)
    with (case_dir / "run.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, stdout=log, stderr=log, start_new_session=True
        )
        try:
            code = process.wait(timeout=deadline)
            record["status"] = "completed" if code == 0 else "failed"
            record["exit_code"] = code
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            record["status"] = "wall-timeout"
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if record["status"] == "completed":
        try:
            record["measurements"] = summarize(bundle, ground_truth)
        except (ValueError, KeyError, OSError) as exc:
            record["status"] = "invalid-bundle"
            record["error"] = str(exc)
    if record["status"] != "completed":
        record["log_tail"] = (case_dir / "run.log").read_text()[-4000:]
    (case_dir / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(case["id"] + ": " + record["status"], flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=ROOT / "fixtures/evaluation/corpus.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--deadline", type=int, default=480)
    parser.add_argument("--analysis-timeout", type=int, default=180)
    parser.add_argument(
        "--reuse-relations",
        type=Path,
        help="Rerender an existing evaluation's raw relations; elapsed times then measure rendering only",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        help="Optional independent local signature dictionary; never use the evaluation ABI as this file",
    )
    args = parser.parse_args()
    if args.deadline <= 0 or args.analysis_timeout <= 0:
        parser.error("Timeouts must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    corpus = json.loads(args.corpus.read_text())
    before = implementation_hash()
    report = {
        "schema_version": 1,
        "selection_id": corpus["selection_id"],
        "corpus_sha256": hashlib.sha256(args.corpus.read_bytes()).hexdigest(),
        "started_at": datetime.now(UTC).isoformat(),
        "implementation_sha256": before,
        "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "evaluation_scope": "Deployed bytecode coverage and inspection tasks; no equivalence or Dedaub parity claim",
        "results": [],
    }
    report_path = args.output / "report.json"
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(
                analyze,
                case,
                args.corpus.parent,
                args.output,
                args.deadline,
                args.analysis_timeout,
                args.reuse_relations,
                args.signatures,
            )
            for case in corpus["contracts"]
        ]
        for future in as_completed(futures):
            report["results"].append(future.result())
            report["results"].sort(key=lambda r: r["id"])
            report_path.write_text(json.dumps(report, indent=2) + "\n")
    report["implementation_changed_during_run"] = implementation_hash() != before
    report["finished_at"] = datetime.now(UTC).isoformat()
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print("Wrote " + str(report_path))


if __name__ == "__main__":
    main()
