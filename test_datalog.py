"""Static checks of the Datalog sources. These tests do not run souffle."""

import re
from pathlib import Path

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
