"""Typed optional memory exports; keep alias and layout ambiguities explicit."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Program

MEMORY_TABLES = {
    "MemorySchema": 1,
    "MemoryArrayAlias": 2,
    "MemoryArray": 3,
    "MemoryStruct": 2,
    "MemoryStructAccess": 5,
    "MemoryArrayAccess": 5,
    "MemoryReturnArray": 3,
    "MemoryReturnWrite": 5,
}


@dataclass(frozen=True)
class Array:
    identity: str
    element_bytes: str
    length: str


@dataclass(frozen=True)
class Access:
    statement: str
    aggregate: str
    index: str
    value: str
    operation: str


@dataclass(frozen=True)
class ReturnArray:
    statement: str
    index: int
    variable: str


@dataclass(frozen=True)
class ReturnWrite:
    statement: str
    writer: str
    offset: int
    low: int
    high: int


@dataclass
class MemoryInfo:
    schema_version: int
    aliases: list[tuple[str, str]]
    arrays: list[Array]
    structs: list[tuple[str, int]]
    struct_accesses: list[Access]
    array_accesses: list[Access]
    return_arrays: list[ReturnArray]
    return_writes: list[ReturnWrite]
    unresolved_variables: list[str]


def load_memory(directory: Path, program: Program) -> MemoryInfo | None:
    if not (directory / "SemanticMemorySchema.csv").exists():
        return None
    tables = {}
    for name, column_count in MEMORY_TABLES.items():
        with (directory / f"Semantic{name}.csv").open() as stream:
            rows = sorted({tuple(r) for r in csv.reader(stream, delimiter="\t")})
        if any(len(r) != column_count for r in rows):
            raise ValueError(f"Semantic{name}: wrong column count")
        tables[name] = rows
    if tables["MemorySchema"] != [("1",)]:
        raise ValueError("Unsupported memory extension schema")
    statements = {s.id: s for b in program.blocks for s in b.instructions}
    variables = {v for s in statements.values() for v in s.definitions + s.operands}
    variables.update(v for f in program.functions for v in f.formal_variables)
    variables.update(program.constants)
    referenced: set[str] = set()
    aliases = [(v, a) for v, a in tables["MemoryArrayAlias"]]
    referenced.update(v for row in aliases for v in row)
    arrays = []
    for identity, width, length in tables["MemoryArray"]:
        if width != "??" and (
            not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", width) or int(width, 16) == 0
        ):
            raise ValueError("Invalid memory array element width")
        arrays.append(Array(identity, width, length))
        referenced.update((identity, length))
    structs = []
    for variable, width in tables["MemoryStruct"]:
        if not width.isdecimal() or not 1 <= int(width) < 1 << 63:
            raise ValueError("Invalid memory struct width")
        structs.append((variable, int(width)))
        referenced.add(variable)

    def accesses(name: str, *, indexed: bool) -> list[Access]:
        results = []
        for stmt, base, index, value, operation in tables[name]:
            if stmt not in statements or operation not in {"load", "store"}:
                raise ValueError("Invalid memory aggregate access")
            if indexed and (not index.isdecimal() or int(index) >= 1 << 63):
                raise ValueError("Invalid memory struct field index")
            if statements[stmt].opcode != ("MLOAD" if operation == "load" else "MSTORE"):
                raise ValueError("Memory aggregate access has the wrong opcode")
            referenced.update((base, value))
            if not indexed:
                referenced.add(index)
            results.append(Access(stmt, base, index, value, operation))
        return results

    struct_accesses = accesses("MemoryStructAccess", indexed=True)
    array_accesses = accesses("MemoryArrayAccess", indexed=False)
    return_arrays = []
    for stmt, index, variable in tables["MemoryReturnArray"]:
        if (
            stmt not in statements
            or statements[stmt].opcode != "RETURN"
            or not index.isdecimal()
            or int(index) >= 1 << 63
        ):
            raise ValueError("Invalid returned memory array")
        return_arrays.append(ReturnArray(stmt, int(index), variable))
        referenced.add(variable)
    writes = []
    for stmt, writer, offset, low, high in tables["MemoryReturnWrite"]:
        if (
            stmt not in statements
            or statements[stmt].opcode != "RETURN"
            or writer not in statements
        ):
            raise ValueError("Invalid return memory writer")
        if (
            not re.fullmatch(r"-?[0-9]+", offset)
            or not low.isdecimal()
            or not high.isdecimal()
            or int(high) <= int(low)
        ):
            raise ValueError("Invalid return memory fragment range")
        if statements[writer].opcode == "MSTORE" and int(high) > 32:
            raise ValueError("Invalid return MSTORE fragment range")
        writes.append(ReturnWrite(stmt, writer, int(offset), int(low), int(high)))
    return MemoryInfo(
        1,
        aliases,
        arrays,
        structs,
        struct_accesses,
        array_accesses,
        return_arrays,
        writes,
        sorted(referenced - variables),
    )
