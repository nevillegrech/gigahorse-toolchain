import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from reconstruction.model import load_program
from reconstruction_tests.test_controlflow import fixture_program
from src.tac_schema import TACRelations

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fixtures/evaluation"


def evaluation_program(directory, ident="multicall3", *, corpus=CORPUS):
    provenance = json.loads((corpus / f"{ident}.snapshot.json").read_text())
    runtime = bytes.fromhex((corpus / f"{ident}.hex").read_text().strip())
    assert hashlib.sha256(runtime).hexdigest() == provenance["bytecode_sha256"]
    tables = {}
    for extension, digest in provenance["tables"].items():
        content = (corpus / f"{ident}.{extension}.json").read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest
        tables.update(json.loads(content))
    TACRelations(tables).write_dir(directory)
    (Path(directory) / "bytecode.hex").write_text(runtime.hex())
    return load_program(directory), runtime


@pytest.mark.parametrize(
    "ident", ["uniswap-v2-pair", "multicall3", "usdc-proxy", "safe-proxy-factory"]
)
def test_locked_deployed_bytecode_has_matching_provenance(ident):
    manifest = json.loads((CORPUS / f"{ident}.json").read_text())
    code = bytes.fromhex((CORPUS / f"{ident}.hex").read_text().strip())
    assert hashlib.sha256(code).hexdigest() == manifest["bytecode_sha256"]
    assert len(code) == manifest["bytecode_size"]
    assert not manifest["upstream_bytecode_duplicates"]
    assert manifest["ground_truth_supplied_to_reconstructor"] is False
    assert manifest["analysis_inputs"] == [ident + ".hex"]
    assert manifest["runtime_match"] in {"match", "exact_match"}


def test_evaluation_summary_rejects_wrong_runtime_hash(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "evaluate_corpus", ROOT / "scripts/evaluate-corpus.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "relations").mkdir()
    (tmp_path / "relations/bytecode.hex").write_text("00")
    (tmp_path / "analysis.json").write_text("{}")
    with pytest.raises(ValueError, match="differs"):
        module.summarize(tmp_path, {"bytecode_sha256": "bad"})


def test_structured_evidence_is_stable_across_hash_seeds(tmp_path):
    fixture_program("control-flow-via-ir", tmp_path)
    script = """
import hashlib,json,sys
from pathlib import Path
from reconstruction.model import load_program
from reconstruction.recovered import render_recovered
p=load_program(Path(sys.argv[1]))
text,mapping=render_recovered(p,structure_flow=True)
print(hashlib.sha256(text.encode()+json.dumps(mapping,sort_keys=True).encode()).hexdigest())
"""
    fingerprints = []
    for seed in ("1", "3", "17"):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path)],
            cwd=ROOT,
            env=dict(os.environ, PYTHONHASHSEED=seed),
            capture_output=True,
            text=True,
            check=True,
        )
        fingerprints.append(result.stdout.strip())
    assert len(set(fingerprints)) == 1


def test_comparison_rejects_a_different_vendor_bytecode(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "prepare_comparison", ROOT / "scripts/prepare-comparison.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = tmp_path / "vendor.json"
    data = {
        "vendor": "Dedaub",
        "representation": "decompiled",
        "bytecode": "0x00",
        "code": "function sample() {}",
        "source_url": "https://app.dedaub.com/example",
        "captured_at": "2026-10-15T00:00:00Z",
    }
    path.write_text(json.dumps(data))
    assert module.validate_vendor_export(path, hashlib.sha256(b"\0").hexdigest())["code"]
    with pytest.raises(ValueError, match="different runtime"):
        module.validate_vendor_export(path, hashlib.sha256(b"\1").hexdigest())
    data["code"] = ""
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="lacks code"):
        module.validate_vendor_export(path, hashlib.sha256(b"\0").hexdigest())
