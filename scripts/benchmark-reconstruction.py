#!/usr/bin/env python3
"""Measure current reconstruction against compiler ground truth in native snapshots."""

import argparse
import hashlib
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def normalized_type(value):
    return "".join(value.split())


def main():
    sys.path.insert(0, str(ROOT))
    from reconstruct import scratch_root
    from reconstruction.model import load_program
    from reconstruction.recovered import render_recovered
    from src.tac_schema import TACRelations

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--behavior-report", type=Path, help="Successful JUnit report with EVM case properties"
    )
    args = parser.parse_args()
    fixtures = ROOT / "fixtures/reconstruction"
    results = []
    for manifest_path in sorted(fixtures.glob("*.json")):
        if manifest_path.name.endswith((".relations.json", ".semantic.json")):
            continue
        manifest = json.loads(manifest_path.read_text())
        stem = manifest_path.stem
        bytecode = bytes.fromhex(manifest_path.with_suffix(".hex").read_text())
        if hashlib.sha256(bytecode).hexdigest() != manifest["bytecode_sha256"]:
            raise SystemExit(f"Stale fixture: {stem}")
        if (
            hashlib.sha256((fixtures / manifest["source"]).read_bytes()).hexdigest()
            != manifest["source_sha256"]
        ):
            raise SystemExit(f"Stale source: {stem}")
        data = {}
        for suffix in ("relations", "semantic"):
            data.update(json.loads((fixtures / f"{stem}.{suffix}.json").read_text()))
        with tempfile.TemporaryDirectory(prefix="benchmark-", dir=scratch_root()) as temp:
            TACRelations(data).write_dir(temp)
            (Path(temp) / "bytecode.hex").write_text(bytecode.hex())
            program = load_program(Path(temp))
        semantics = program.semantics
        if semantics is None:
            raise SystemExit(f"Missing semantic facts: {stem}")
        functions = {selector: f for f in program.functions for selector in f.selectors}
        expected = {"0x" + selector for selector in manifest["method_identifiers"].values()}
        matched_ranges = 0
        matched_types = 0
        for field in manifest["storage_layout"]["storage"]:
            type_info = manifest["storage_layout"]["types"][field["type"]]
            low = int(field["offset"])
            high = low + int(type_info["numberOfBytes"]) - 1
            candidates = [
                f
                for f in semantics.storage_fields
                if int(f.slot, 16) == int(field["slot"])
                and f.byte_low == low
                and f.byte_high == high
            ]
            matched_ranges += bool(candidates)
            matched_types += any(
                normalized_type(type_info["label"]) == normalized_type(t)
                for f in candidates
                for t in f.type_candidates
            )
        arguments_expected = 0
        argument_candidates_match = 0
        argument_unambiguous_match = 0
        for function_abi in manifest["abi"]:
            if function_abi["type"] != "function":
                continue
            signature = (
                function_abi["name"]
                + "("
                + ",".join(a["type"] for a in function_abi["inputs"])
                + ")"
            )
            selector = "0x" + manifest["method_identifiers"][signature]
            function = functions.get(selector)
            for index, argument in enumerate(function_abi["inputs"]):
                arguments_expected += 1
                inferred = [
                    a
                    for a in semantics.arguments
                    if function and a.function == function.id and a.index == index
                ]
                candidates = {t for a in inferred for t in a.type_candidates}
                argument_candidates_match += argument["type"] in candidates
                argument_unambiguous_match += candidates == {argument["type"]}
        _, source_map = render_recovered(program)
        _, structured_map = render_recovered(program, structure_flow=True)
        plans = structured_map.get("control_flow", [])
        mapped = {s for line in source_map["lines"] for s in line["ir_statements"]}
        results.append(
            {
                "fixture": stem,
                "bytecode_sha256": manifest["bytecode_sha256"],
                "selectors_expected": len(expected),
                "selectors_recovered": len(expected & functions.keys()),
                "storage_fields_expected": len(manifest["storage_layout"]["storage"]),
                "storage_ranges_match": matched_ranges,
                "storage_type_candidates_contain_source_type": matched_types,
                "arguments_expected": arguments_expected,
                "argument_type_candidates_contain_source_type": argument_candidates_match,
                "argument_types_unambiguous_and_match": argument_unambiguous_match,
                "revert_guards": len(semantics.guards),
                "unmapped_bytecode_statements": len(program.unmapped_statements),
                "ir_instructions": sum(len(b.instructions) for b in program.blocks),
                "ir_instructions_referenced_in_view": len(mapped),
                "structured_functions": sum(plan["status"] == "structured" for plan in plans),
                "functions_with_unresolved_phi_inputs": sum(
                    bool(plan["unresolved_phis"]) for plan in plans
                ),
                "resolved_phi_nodes": sum(len(plan["resolved_phis"]) for plan in plans),
                "external_calls": len(semantics.external_calls),
                "external_call_selectors_inferred": sum(
                    c.selector_resolved for c in semantics.external_calls
                ),
                "external_calls_using_memory_fragments": sum(
                    "memory-fragments" in c.abi_sources for c in semantics.external_calls
                ),
                "external_abi_word_variables_inferred": sum(
                    len(a.variables) == 1 for c in semantics.external_calls for a in c.arguments
                ),
            }
        )
    report = {
        "schema_version": 1,
        "evaluation": "compiler-fixtures-only",
        "dedaub_comparison": "not-measured",
        "behavioral_equivalence": "not-proven",
        "results": results,
    }
    if args.behavior_report:
        xml = ET.parse(args.behavior_report).getroot()
        if any(
            int(suite.get("errors", "0")) or int(suite.get("failures", "0"))
            for suite in xml.iter("testsuite")
        ):
            raise SystemExit("Behavior report contains failures or errors")
        evidence = []
        for testcase in xml.iter("testcase"):
            properties = {
                p.get("name"): p.get("value") for p in testcase.findall("./properties/property")
            }
            if "evm_contract_cases" not in properties:
                continue
            stem = properties["fixture"]
            manifest = json.loads((fixtures / f"{stem}.json").read_text())
            current_facts = hashlib.sha256(
                (fixtures / f"{stem}.relations.json").read_bytes()
                + (fixtures / f"{stem}.semantic.json").read_bytes()
            ).hexdigest()
            if (
                properties["bytecode_sha256"] != manifest["bytecode_sha256"]
                or properties["facts_sha256"] != current_facts
            ):
                raise SystemExit(f"Stale behavior evidence: {stem}")
            evidence.append(
                {
                    "fixture": stem,
                    "cases": int(properties["evm_contract_cases"]),
                    "bytecode_sha256": properties["bytecode_sha256"],
                    "facts_sha256": current_facts,
                    "mode": properties.get("validation_mode", "standalone"),
                    "external_calls": int(properties.get("evm_external_calls", "0")),
                    "abi_words": int(properties.get("evm_abi_words", "0")),
                    "printed_expression_checks": int(
                        properties.get("printed_expression_checks", "0")
                    ),
                    "printed_storage_path_checks": int(
                        properties.get("printed_storage_path_checks", "0")
                    ),
                    "printed_storage_paths_unchecked": int(
                        properties.get("printed_storage_paths_unchecked", "0")
                    ),
                }
            )
        if not evidence:
            raise SystemExit("No independent EVM contract comparisons in the supplied report")
        report["behavioral_tests"] = {
            "cases": sum(item["cases"] for item in evidence),
            "standalone_cases": sum(
                item["cases"] for item in evidence if item["mode"] == "standalone"
            ),
            "external_replay_cases": sum(
                item["cases"] for item in evidence if item["mode"] == "external-results-replayed"
            ),
            "external_calls_compared": sum(item["external_calls"] for item in evidence),
            "abi_words_compared": sum(item["abi_words"] for item in evidence),
            "printed_expression_checks": sum(
                item["printed_expression_checks"] for item in evidence
            ),
            "printed_storage_path_checks": sum(
                item["printed_storage_path_checks"] for item in evidence
            ),
            "printed_storage_paths_unchecked": sum(
                item["printed_storage_paths_unchecked"] for item in evidence
            ),
            "fixtures": evidence,
            "scope": "Original bytecode compared with recovered CFG and structured region execution: return bytes, reverts, touched state slots, CFG/region block traces, and observed external-call arguments and inferred ABI words. Listed printed-expression checks evaluate rendered operands, conditions, simultaneous PHI copies and return-word annotations in a separate frame containing only emitted assignments; supported constant/mapping storage paths are compared with raw slots.",
            "limitations": "Bounded fixture inputs. Interaction cases replay EVM-observed external results and GAS values; called-contract behavior and external world-state transitions are not independently reimplemented. The expression checker follows the recovered trace and obtains non-pure results from the IR machine. Array storage stride/packing is explicitly unchecked. No gas equivalence, general equivalence proof, or standalone execution of the full emitted pseudocode.",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
