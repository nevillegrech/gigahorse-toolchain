"""Checks of the Datalog sources. The tests that run souffle skip when it is not installed."""

import os
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

from src import opcodes

ROOT = Path(__file__).parent

DIRECTIVE = re.compile(r"^\s*\.(input|output)\s+([^\n(]+?)\s*(\(([^)]*)\))?\s*$", re.M)
FILENAME = re.compile(r'filename\s*=\s*"([^"]+)"')


def directive_files(dl_file: str, kind: str) -> set[str]:
    """File names of the `.input` or `.output` (`kind`) directives in `dl_file`."""
    files = set()
    for match in DIRECTIVE.finditer((ROOT / dl_file).read_text()):
        if match.group(1) != kind:
            continue
        explicit = FILENAME.search(match.group(4) or "")
        default_suffix = "facts" if kind == "input" else "csv"
        for relation in match.group(2).split(","):
            files.add(explicit.group(1) if explicit else f"{relation.strip()}.{default_suffix}")
    return files


def facts(dl_file: str, relation: str) -> set[str]:
    """The symbol arguments of the one-column facts of `relation` in `dl_file`."""
    return set(re.findall(rf'^{relation}\("([^"]+)"\)\.', (ROOT / dl_file).read_text(), re.M))


def test_the_decompiler_writes_every_file_that_clients_read():
    client_inputs = directive_files("clientlib/decompiler_imports.dl", "input")
    decompiler_outputs = directive_files("logic/decompiler_output.dl", "output")

    assert client_inputs - decompiler_outputs == set()


def test_clients_know_every_opcode_that_can_halt():
    decompiler = facts("logic/decompiler_input_opcodes.dl", "OpcodePossiblyHalts")
    clients = facts("clientlib/decompiler_imports.dl", "OpcodePossiblyHalts")

    assert decompiler
    # THROW is the TAC opcode for INVALID
    assert clients == decompiler | {"THROW"}


# No type evidence. The size opcodes are here because RETURNDATASIZE also pushes zero.
UNTYPED_OPCODES = {"PC", "CALLDATALOAD", "MLOAD", "SLOAD", "TLOAD", "CALLDATASIZE", "CODESIZE"}
UNTYPED_OPCODES |= {"RETURNDATASIZE", "EXTCODESIZE", "MSIZE"}
# Addresses: clientlib/casts_shifts.dl handles them
ADDRESS_OPCODES = {"ADDRESS", "ORIGIN", "CALLER", "COINBASE"}


def environment_opcodes() -> set[str]:
    """Opcodes (not aliases) that push one value from the environment or from at most one input."""
    return {
        name
        for name, op in opcodes.OPCODES.items()
        if name == op.name
        and op.push == 1
        and op.pop <= 1
        and not op.is_push()
        and op is not opcodes.PUSH0
        and not op.is_arithmetic()
    }


def test_storage_type_inference_knows_every_environment_opcode():
    text = (ROOT / "clientlib/storage_modeling/type_inference.dl").read_text()
    classified = set(
        re.findall(r'^TypeInference_(?:Uint|Bytes)ValuedOpcode\("(\w+)"\)\.', text, re.M)
    )

    assert classified <= set(opcodes.OPCODES)
    assert environment_opcodes() - classified - UNTYPED_OPCODES - ADDRESS_OPCODES == set()


FOLD_DRIVER = """
.type Opcode <: symbol
.type Value <: symbol
#include "souffle-addon/functor_includes.dl"
#include "clientlib/constants.dl"
.init folding = ConstantFolding
.decl Request1(op: Opcode, a: Value)
.decl Request2(op: Opcode, a: Value, b: Value)
.input Request1, Request2
folding.RequestConstantFold1(op, a) :- Request1(op, a).
folding.RequestConstantFold2(op, a, b) :- Request2(op, a, b).
.decl Result1(op: Opcode, a: Value, result: Value)
.decl Result2(op: Opcode, a: Value, b: Value, result: Value)
.output Result1, Result2
Result1(op, a, result) :- folding.ConstantFoldResult1(op, a, result).
Result2(op, a, b, result) :- folding.ConstantFoldResult2(op, a, b, result).
"""

WORD = 2**256
INDEXES = [*range(34), 2**64, 2**255, WORD - 1]
VALUES = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 2**255, WORD - 1, 0xAB << 248, 0xF0F0F0 << 100]


def evm_byte(i: int, x: int) -> int:
    return (x >> (248 - 8 * i)) & 0xFF if i < 32 else 0


def evm_signextend(b: int, x: int) -> int:
    if b >= 31:
        return x
    low = (1 << (8 * b + 8)) - 1
    return x | (WORD - 1 - low) if (x >> (8 * b + 7)) & 1 else x & low


@pytest.mark.skipif(shutil.which("souffle") is None, reason="souffle is not installed")
def test_constant_folding_of_byte_signextend_and_clz(tmp_path):
    # (opcode, arguments as hex) -> EVM result. The padded forms check that inputs are normalized.
    expected: dict[tuple[str, ...], int] = {}
    for x in VALUES:
        for x_hex in (hex(x), f"0x{x:064x}"):
            for i in INDEXES:
                expected["BYTE", hex(i), x_hex] = evm_byte(i, x)
                expected["SIGNEXTEND", hex(i), x_hex] = evm_signextend(i, x)
    for x in VALUES + [2**k for k in range(256)] + [2**k - 1 for k in range(257)]:
        for x_hex in (hex(x), f"0x{x:064x}"):
            expected["CLZ", x_hex] = 256 - x.bit_length()

    for arity in (1, 2):
        requests = [key for key in expected if len(key) == arity + 1]
        (tmp_path / f"Request{arity}.facts").write_text(
            "".join("\t".join(k) + "\n" for k in requests)
        )
    (tmp_path / "driver.dl").write_text(FOLD_DRIVER)
    addon = str(ROOT / "souffle-addon")
    subprocess.run(
        ["souffle", "-I", str(ROOT), "-L", addon, "-F", tmp_path, "-D", tmp_path, "driver.dl"],
        cwd=tmp_path,
        env={**os.environ, "LD_LIBRARY_PATH": addon},
        check=True,
    )

    results = defaultdict(list)
    for arity in (1, 2):
        for line in (tmp_path / f"Result{arity}.csv").read_text().splitlines():
            *key, result = line.split("\t")
            results[tuple(key)].append(int(result, 16))
    assert results.keys() == expected.keys()
    assert {key: found for key, found in results.items() if found != [expected[key]]} == {}
