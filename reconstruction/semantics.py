"""Typed, explicitly inferred facts exported by clients/reconstruction.dl."""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import resolve_constants
from .interactions import COPY_TABLES, EXTERNAL_TABLES, ExternalCall, load_external_calls
from .memory import MemoryInfo, load_memory

if TYPE_CHECKING:
    from .model import Program


@dataclass(frozen=True)
class Term:
    constructor: str
    arguments: tuple[Term | str, ...] = ()


ARITIES = {
    "Storage": 0,
    "TransientStorage": 0,
    "Constant": 1,
    "Mapping": 1,
    "Array": 1,
    "StaticArray": 2,
    "Offset": 2,
    "Variable": 1,
    "TightlyPackedVariable": 3,
    "ConstantIndex": 1,
    "MappingAccessIndex": 2,
    "ArrayAccessIndex": 2,
    "StaticArrayAccessIndex": 3,
    "ArrayDataStartIndex": 1,
    "OffsetIndex": 2,
    "VariableWrite": 1,
    "ConstantWrite": 1,
}
TOKEN = re.compile(r'\s*(\$[A-Za-z_]\w*|[(),]|"(?:[^"\\]|\\.)*"|[^$(),\s]+)')


def parse_term(text: str) -> Term:
    """Parse Souffle's printed ADTs without evaluating source text."""
    if len(text) > 16384:
        raise ValueError("Semantic term exceeds the supported size")
    tokens = []
    position = 0
    while position < len(text.rstrip()):
        match = TOKEN.match(text, position)
        if match is None:
            raise ValueError(f"Invalid semantic term: {text!r}")
        tokens.append(match[1])
        position = match.end()
    cursor = 0

    def parse(depth: int) -> Term | str:
        nonlocal cursor
        if depth > 64 or cursor >= len(tokens):
            raise ValueError(f"Truncated or excessively nested semantic term: {text!r}")
        token = tokens[cursor]
        cursor += 1
        if not token.startswith("$"):
            if token in {"(", ")", ","}:
                raise ValueError(f"Invalid semantic atom: {token!r}")
            return json.loads(token) if token.startswith('"') else token
        constructor = token[1:]
        args: list[Term | str] = []
        if cursor < len(tokens) and tokens[cursor] == "(":
            cursor += 1
            if cursor < len(tokens) and tokens[cursor] != ")":
                args.append(parse(depth + 1))
                while cursor < len(tokens) and tokens[cursor] == ",":
                    cursor += 1
                    args.append(parse(depth + 1))
            if cursor >= len(tokens) or tokens[cursor] != ")":
                raise ValueError(f"Unclosed semantic term: {text!r}")
            cursor += 1
        if constructor in ARITIES and len(args) != ARITIES[constructor]:
            raise ValueError(f"Wrong arity for {constructor}: {text!r}")
        return Term(constructor, tuple(args))

    root = parse(0)
    if cursor != len(tokens) or not isinstance(root, Term):
        raise ValueError(f"Expected one semantic term: {text!r}")
    return root


def atom(term: Term, index: int) -> str:
    value = term.arguments[index]
    if not isinstance(value, str):
        raise ValueError(f"Expected an atom in {term.constructor}")
    return value


def child(term: Term, index: int = 0) -> Term:
    value = term.arguments[index]
    if not isinstance(value, Term):
        raise ValueError(f"Expected a nested term in {term.constructor}")
    return value


def location(text: str) -> str:
    term = parse_term(text)
    if term.constructor not in {"Storage", "TransientStorage"} or term.arguments:
        raise ValueError(f"Unknown storage location: {text!r}")
    return "storage" if term.constructor == "Storage" else "transient"


@dataclass
class StorageField:
    name: str
    location: str
    slot: str
    kind: str
    byte_low: int
    byte_high: int
    type_candidates: list[str]
    evidence: list[str]
    native_type_hints: list[str] = dataclass_field(default_factory=list)
    type_limitations: list[str] = dataclass_field(default_factory=list)


@dataclass
class StorageAccess:
    statement: str
    kind: str
    location: str
    index: Term
    construct: Term
    loaded_variables: list[str]
    written_values: list[Term]


@dataclass
class Argument:
    function: str
    index: int
    variables: list[str]
    kind: str
    type_candidates: list[str]
    validation_statements: list[str]


@dataclass
class Guard:
    block: str
    statement: str
    predicate: str
    success: str
    failure: str
    success_when_nonzero: bool


@dataclass
class SemanticInfo:
    schema_version: int
    storage_fields: list[StorageField]
    storage_accesses: list[StorageAccess]
    arguments: list[Argument]
    memory_values: dict[str, dict[int, list[str]]]
    constants: dict[str, str]
    guards: list[Guard]
    calls: list[tuple[str, str]]
    call_returns: list[tuple[str, str, str]]
    warnings: list[str]
    external_calls: list[ExternalCall] = dataclass_field(default_factory=list)
    memory_model: MemoryInfo | None = None
    cast_facts: list[tuple[str, ...]] = dataclass_field(default_factory=list)


TABLES = {
    "Schema": 1,
    "StoragePath": 5,
    "StorageRead": 4,
    "StorageWrite": 4,
    "StorageType": 3,
    "StorageInfo": 5,
    "StorageName": 3,
    "Argument": 4,
    "Memory": 4,
    "Constant": 2,
    "Cast": 4,
    "VariableUse": 2,
    "MustRevert": 1,
    "SenderGuard": 2,
    "Call": 2,
    "CallReturn": 3,
}


def _root(term: Term) -> tuple[str, str, int, int] | None:
    """Identify only top-level declarations, without flattening nested fields."""
    kind = term.constructor
    if kind in {"Variable", "TightlyPackedVariable", "Mapping", "Array", "StaticArray"}:
        parent = child(term)
        if parent.constructor != "Constant":
            return None
        slot = atom(parent, 0)
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", slot):
            raise ValueError(f"Invalid storage slot: {slot!r}")
        low, high = (
            (int(atom(term, 1)), int(atom(term, 2))) if kind == "TightlyPackedVariable" else (0, 31)
        )
        if not 0 <= low <= high <= 31:
            raise ValueError("Invalid packed storage byte range")
        return hex(int(slot, 16)), kind, low, high
    return None


def field_name(loc: str, slot: str, kind: str, low: int = 0, high: int = 31) -> str:
    base = (
        "mapping" if kind == "Mapping" else "array" if kind in {"Array", "StaticArray"} else "slot"
    )
    name = ("transient_" if loc == "transient" else "") + f"{base}_{int(slot, 16)}"
    if (low, high) != (0, 31):
        name += f"_bytes_{low}_{high}"
    return name


def find_guards(program: Program, must_revert: set[str]) -> list[Guard]:
    guards = []
    for block in program.blocks:
        if not block.instructions or len(block.successors) != 2 or len(block.fallthrough) != 1:
            continue
        tail = block.instructions[-1]
        if tail.opcode != "JUMPI" or len(tail.operands) != 2:
            continue
        destination = program.block_targets.get(
            tail.operands[0], program.constants.get(tail.operands[0])
        )
        fallthrough = block.fallthrough[0]
        if destination not in block.successors or destination == fallthrough:
            continue
        if (destination in must_revert) == (fallthrough in must_revert):
            continue
        failure = destination if destination in must_revert else fallthrough
        success = fallthrough if destination in must_revert else destination
        guards.append(
            Guard(block.id, tail.id, tail.operands[1], success, failure, destination == success)
        )
    return guards


def _argument_types(
    variables: set[str],
    casts: list[tuple[str, ...]],
    program: Program,
    guards: list[Guard],
    constants: dict[str, str],
) -> tuple[list[str], list[str]]:
    definitions = {
        v: stmt for b in program.blocks for stmt in b.instructions for v in stmt.definitions
    }
    candidates: set[str] = set()
    validations: set[str] = set()
    for source, target, kind, raw_width in casts:
        if source not in variables:
            continue
        width = int(raw_width)
        if not 1 <= width <= 32:
            continue
        cast = definitions.get(target)
        if cast is None:
            continue
        if kind == "bool":
            inner = definitions.get(cast.operands[0]) if cast.operands else None
            if (
                cast.opcode != "ISZERO"
                or inner is None
                or inner.opcode != "ISZERO"
                or inner.operands != [source]
            ):
                continue
            types = {"bool"}
        elif kind == "uint":
            if cast.opcode != "AND" or len(cast.operands) != 2:
                continue
            mask = next(
                (constants.get(v) for v in cast.operands if v != source and v in constants), None
            )
            if mask is None or int(mask, 16) != (1 << (8 * width)) - 1:
                continue
            types = {"address", "uint160"} if width == 20 else {f"uint{width * 8}"}
        elif kind == "int" and cast.opcode == "SIGNEXTEND":
            types = {f"int{width * 8}"}
        else:
            continue
        for guard in guards:
            variable = guard.predicate
            succeeds_nonzero = guard.success_when_nonzero
            condition = definitions.get(variable)
            seen = set()
            while (
                condition
                and condition.opcode == "ISZERO"
                and len(condition.operands) == 1
                and variable not in seen
            ):
                seen.add(variable)
                variable = condition.operands[0]
                succeeds_nonzero = not succeeds_nonzero
                condition = definitions.get(variable)
            if condition is None or set(condition.operands) != {source, target}:
                continue
            equality_success = (condition.opcode == "EQ" and succeeds_nonzero) or (
                condition.opcode == "SUB" and not succeeds_nonzero
            )
            if equality_success:
                candidates.update(types)
                validations.add(guard.statement)
    return sorted(candidates or {"word"}), sorted(validations)


def load_semantics(directory: Path, program: Program) -> SemanticInfo | None:
    marker = directory / "SemanticSchema.csv"
    if not marker.exists():
        return None
    with marker.open() as schema_stream:
        schema_rows = list(csv.reader(schema_stream, delimiter="\t"))
    if schema_rows not in ([["1"]], [["2"]], [["3"]]):
        raise ValueError(f"Unsupported semantic schema: {schema_rows!r}")
    version = int(schema_rows[0][0])
    tables = {}
    export_tables = (
        TABLES | (EXTERNAL_TABLES if version >= 2 else {}) | (COPY_TABLES if version >= 3 else {})
    )
    for suffix, width in export_tables.items():
        path = directory / f"Semantic{suffix}.csv"
        with path.open() as stream:
            rows = [tuple(row) for row in csv.reader(stream, delimiter="\t")]
        if any(len(row) != width for row in rows):
            raise ValueError(f"Semantic{suffix}: wrong column count")
        tables[suffix] = sorted(set(rows))
    warnings = [
        "Storage layouts and types are inferences from observed behavior; original declarations may differ."
    ]
    constants_by_var: defaultdict[str, set[str]] = defaultdict(set)
    for variable, value in tables["Constant"]:
        if re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
            constants_by_var[variable].add(value)
    constants = dict(program.constants)
    for variable, values in constants_by_var.items():
        values |= {constants[variable]} if variable in constants else set()
        if len(values) == 1:
            constants[variable] = next(iter(values))
        else:
            constants.pop(variable, None)
            warnings.append(f"Ambiguous semantic constant for {variable}.")

    constants = resolve_constants(
        program, constants, tables["Call"], [(a, b, c) for a, b, c in tables["CallReturn"]]
    )

    fields: dict[tuple[str, str, str, int, int], StorageField] = {}
    for raw_loc, raw_construct, type_name in tables["StorageType"]:
        loc, construct = location(raw_loc), parse_term(raw_construct)
        root = _root(construct)
        if root is None:
            continue
        slot, kind, low, high = root
        key = (loc, slot, kind, low, high)
        if key not in fields:
            fields[key] = StorageField(field_name(*key), loc, slot, kind, low, high, [], [])
        fields[key].native_type_hints.append(type_name)
        fields[key].type_candidates.append(type_name)
        if re.search(r"\bbool\b", type_name):
            # Native storage inference defaults every single byte to bool.
            # Reading/masking a byte does not establish a 0/1 range. Preserve
            # the hint, but keep an integer alternative and a raw-word view.
            width = 8 * (high - low + 1) if type_name == "bool" else 8
            fields[key].type_candidates.append(re.sub(r"\bbool\b", f"uint{width}", type_name))
            fields[key].type_limitations.append(
                "Native bool hints do not establish 0/1 storage values or original declarations; "
                "integer alternatives are retained and are not exhaustive."
            )
    for name, raw_loc, raw_slot, raw_low, raw_high in tables["StorageInfo"]:
        loc, slot, low, high = (
            location(raw_loc),
            hex(int(raw_slot, 16)),
            int(raw_low),
            int(raw_high),
        )
        if not 0 <= low <= high <= 31:
            raise ValueError("Invalid semantic storage byte range")
        kind = "Variable" if (low, high) == (0, 31) else "TightlyPackedVariable"
        key = (loc, slot, kind, low, high)
        if key not in fields:
            fields[key] = StorageField(field_name(*key), loc, slot, kind, low, high, [], [])
        fields[key].evidence.append(name)
    # Evidence links each declaration to actual recovered access instructions.
    accesses = []
    reads: defaultdict[tuple[str, str, str], list[str]] = defaultdict(list)
    writes: defaultdict[tuple[str, str, str], list[Term]] = defaultdict(list)
    for stmt, raw_loc, raw_construct, variable in tables["StorageRead"]:
        reads[(stmt, raw_loc, raw_construct)].append(variable)
    for stmt, raw_loc, raw_construct, raw_value in tables["StorageWrite"]:
        writes[(stmt, raw_loc, raw_construct)].append(parse_term(raw_value))
    instruction_ids = {s.id for b in program.blocks for s in b.instructions}
    for stmt, kind, raw_loc, raw_index, raw_construct in tables["StoragePath"]:
        if stmt not in instruction_ids:
            raise ValueError(f"Semantic storage access references an unknown instruction: {stmt}")
        loc, index, construct = location(raw_loc), parse_term(raw_index), parse_term(raw_construct)
        accesses.append(
            StorageAccess(
                stmt,
                kind,
                loc,
                index,
                construct,
                reads[(stmt, raw_loc, raw_construct)],
                writes[(stmt, raw_loc, raw_construct)],
            )
        )
        root = _root(construct)
        if root is not None:
            key = (loc, *root)
            if key in fields:
                fields[key].evidence.append(stmt)
        # For nested data, attach access evidence to its top-level allocation.
        ancestor = construct
        while ancestor.arguments and isinstance(ancestor.arguments[0], Term):
            root = _root(ancestor)
            if root is not None and (loc, *root) in fields:
                fields[(loc, *root)].evidence.append(stmt)
            ancestor = child(ancestor)
    for field in fields.values():
        field.type_candidates = sorted(set(field.type_candidates))
        field.native_type_hints = sorted(set(field.native_type_hints))
        field.type_limitations = sorted(set(field.type_limitations))
        field.evidence = sorted(set(field.evidence))

    guards = find_guards(program, {block for (block,) in tables["MustRevert"]})
    argument_rows: defaultdict[tuple[str, int, str], set[str]] = defaultdict(set)
    functions = {f.id for f in program.functions}
    for function, variable, raw_index, kind in tables["Argument"]:
        if (
            function not in functions
            or not raw_index.isdecimal()
            or kind not in {"word", "array", "struct"}
        ):
            raise ValueError("Invalid semantic function argument")
        argument_rows[(function, int(raw_index), kind)].add(variable)
    arguments = []
    for (function, arg_index, kind), variables in sorted(argument_rows.items()):
        candidates, validations = _argument_types(
            variables, tables["Cast"], program, guards, constants
        )
        arguments.append(
            Argument(function, arg_index, sorted(variables), kind, candidates, validations)
        )
    memory: defaultdict[str, dict[int, list[str]]] = defaultdict(dict)
    for stmt, _kind, raw_index, variable in tables["Memory"]:
        if not raw_index.isdecimal():
            raise ValueError("Invalid semantic memory argument index")
        memory[stmt].setdefault(int(raw_index), []).append(variable)
    return SemanticInfo(
        version,
        list(fields.values()),
        accesses,
        arguments,
        dict(memory),
        constants,
        guards,
        [(a, b) for a, b in tables["Call"]],
        [(a, b, c) for a, b, c in tables["CallReturn"]],
        warnings,
        load_external_calls(program, tables, dict(memory), constants),
        load_memory(directory, program),
        tables["Cast"],
    )
