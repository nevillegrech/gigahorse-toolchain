"""Materialize frozen fixtures, including captured memory links, for the decompiled view."""

from __future__ import annotations

from pathlib import Path

from reconstruction.highlevel.view import DecompiledProgram, build_decompiled
from reconstruction.model import Program
from reconstruction_tests.memory_links import write_links
from reconstruction_tests.test_controlflow import fixture_program
from reconstruction_tests.test_evaluation import evaluation_program

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / "fixtures/reconstruction"
DEPLOYED = ROOT / "fixtures/evaluation"
DEPLOYED_NEXT = ROOT / "fixtures/evaluation-next"
DEDAUB = ROOT / "fixtures/dedaub"

COMPILER_STEMS = sorted(
    p.name.removesuffix(".relations.json") for p in COMPILER.glob("*.relations.json")
)
DEPLOYED_IDS = [
    (DEPLOYED, "uniswap-v2-pair"),
    (DEPLOYED, "multicall3"),
    (DEPLOYED, "usdc-proxy"),
    (DEPLOYED, "safe-proxy-factory"),
    (DEPLOYED_NEXT, "weth9"),
    (DEPLOYED_NEXT, "ens-registry"),
    (DEPLOYED_NEXT, "erc721-collection"),
    (DEDAUB, "morpho-liquidator"),
]


def compiler_fixture(stem: str, directory: Path) -> tuple[Program, DecompiledProgram]:
    directory.mkdir(parents=True, exist_ok=True)
    program = fixture_program(stem, directory)
    write_links(directory, COMPILER / stem)
    return program, build_decompiled(program, directory)


def deployed_fixture(
    corpus: Path, ident: str, directory: Path
) -> tuple[Program, DecompiledProgram, bytes]:
    directory.mkdir(parents=True, exist_ok=True)
    program, runtime = evaluation_program(directory, ident, corpus=corpus)
    write_links(directory, corpus / ident)
    return program, build_decompiled(program, directory), runtime
