"""
tac_schema.py — Schema definition and low-level relational access to Gigahorse TAC output.

Each relation is defined once as a module-level `RelationDef` constant that
bundles the file name with its column schema.  Use these constants everywhere
instead of raw strings:

    from tac_schema import TACRelations, tac_op, tac_def, local_block_edge

    tac = TACRelations.from_dir(".temp/my_contract/out")
    for stmt_id, opcode in tac[tac_op]:
        ...

`ALL_RELATIONS` is the frozenset of every defined RelationDef.

Schema derived from:
  https://github.com/nevillegrech/gigahorse-toolchain/blob/master/logic/decompiler_output.dl
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional, Union


# ---------------------------------------------------------------------------
# Column kinds — what role a column plays in the schema
# ---------------------------------------------------------------------------

class ColKind(Enum):
    """The semantic role of a column in a TAC relation."""
    STMT_ID = auto()    # Statement identifier
    BLOCK_ID = auto()   # Basic block identifier (also used for function entry IDs)
    VAR_ID = auto()     # Variable identifier
    OPCODE = auto()     # EVM/TAC opcode string
    VALUE = auto()      # Hex constant, hash, gas value, selector, etc.
    INDEX = auto()      # Numeric positional index (e.g. TAC_Def index, FormalArgs n)
    SYMBOL = auto()     # Free-form string (function names, config names, signatures)

    @property
    def is_identifier(self) -> bool:
        """True if this column kind is an entity identifier that should be
        affected by prefix/remap operations."""
        return self in (ColKind.STMT_ID, ColKind.BLOCK_ID, ColKind.VAR_ID)


# ---------------------------------------------------------------------------
# Column descriptor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Column:
    """A named, typed column in a TAC relation."""
    name: str
    kind: ColKind

    def __repr__(self) -> str:
        return f"Column({self.name!r}, {self.kind.name})"


# ---------------------------------------------------------------------------
# Relation definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RelationDef:
    """A relation's name and column schema, defined once and used as a key."""
    name: str
    columns: tuple[Column, ...]

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)

    @property
    def column_kinds(self) -> tuple[ColKind, ...]:
        return tuple(c.kind for c in self.columns)

    @property
    def id_column_indices(self) -> list[int]:
        """Indices of columns that are identifiers (affected by prefix/remap)."""
        return [i for i, c in enumerate(self.columns) if c.kind.is_identifier]

    def __repr__(self) -> str:
        return f"RelationDef({self.name!r})"


# ---------------------------------------------------------------------------
# The full TAC schema — one constant per relation
#
# Python names are snake_case; the .name field preserves the original
# Souffle filename for disk I/O.
# ---------------------------------------------------------------------------

# Config / metadata
decompiler_config = RelationDef("DecompilerConfig", (
    Column("config", ColKind.SYMBOL),
))
global_entry_block = RelationDef("GlobalEntryBlock", (
    Column("block", ColKind.BLOCK_ID),
))

# Variables
tac_variable_value = RelationDef("TAC_Variable_Value", (
    Column("var", ColKind.VAR_ID),
    Column("value", ColKind.VALUE),
))
tac_variable_block_value = RelationDef("TAC_Variable_BlockValue", (
    Column("var", ColKind.VAR_ID),
    Column("value", ColKind.VALUE),
))

# Statements
tac_stmt = RelationDef("TAC_Stmt", (
    Column("stmt", ColKind.STMT_ID),
))
tac_op = RelationDef("TAC_Op", (
    Column("stmt", ColKind.STMT_ID),
    Column("opcode", ColKind.OPCODE),
))
tac_def = RelationDef("TAC_Def", (
    Column("stmt", ColKind.STMT_ID),
    Column("var", ColKind.VAR_ID),
    Column("index", ColKind.INDEX),
))
tac_use = RelationDef("TAC_Use", (
    Column("stmt", ColKind.STMT_ID),
    Column("var", ColKind.VAR_ID),
    Column("index", ColKind.INDEX),
))
tac_statement_next = RelationDef("TAC_Statement_Next", (
    Column("stmt", ColKind.STMT_ID),
    Column("next", ColKind.STMT_ID),
))
tac_statement_original_statement = RelationDef("TAC_Statement_OriginalStatement", (
    Column("tac_stmt", ColKind.STMT_ID),
    Column("orig_stmt", ColKind.STMT_ID),
))
tac_statement_original_statement_list = RelationDef("TAC_Statement_OriginalStatementList", (
    Column("tac_stmt", ColKind.STMT_ID),
    Column("stmt_list", ColKind.SYMBOL),
))
tac_statement_inline_info = RelationDef("TAC_Statement_InlineInfo", (
    Column("tac_stmt", ColKind.STMT_ID),
    Column("function_list", ColKind.SYMBOL),
))
original_statement_block = RelationDef("TAC_OriginalStatement_Block", (
    Column("stmt", ColKind.SYMBOL),
    Column("block", ColKind.BLOCK_ID),
))

# Blocks
tac_block = RelationDef("TAC_Block", (
    Column("stmt", ColKind.STMT_ID),
    Column("block", ColKind.BLOCK_ID),
))
tac_block_head = RelationDef("TAC_Block_Head", (
    Column("block", ColKind.BLOCK_ID),
    Column("stmt", ColKind.STMT_ID),
))
tac_block_gas = RelationDef("TAC_Block_Gas", (
    Column("block", ColKind.BLOCK_ID),
    Column("gas", ColKind.VALUE),
))
tac_block_code_chunk_accessed = RelationDef("TAC_Block_CodeChunkAccessed", (
    Column("block", ColKind.BLOCK_ID),
    Column("chunk", ColKind.VALUE),
))

# CFG edges
local_block_edge = RelationDef("LocalBlockEdge", (
    Column("from", ColKind.BLOCK_ID),
    Column("to", ColKind.BLOCK_ID),
))
ir_fallthrough_edge = RelationDef("IRFallthroughEdge", (
    Column("from", ColKind.BLOCK_ID),
    Column("to", ColKind.BLOCK_ID),
))

# Functions
ir_function_entry = RelationDef("IRFunctionEntry", (
    Column("func", ColKind.BLOCK_ID),
))
function = RelationDef("Function", (
    Column("func", ColKind.BLOCK_ID),
))
high_level_function_name = RelationDef("HighLevelFunctionName", (
    Column("func", ColKind.BLOCK_ID),
    Column("name", ColKind.SYMBOL),
))
public_function = RelationDef("PublicFunction", (
    Column("func", ColKind.BLOCK_ID),
    Column("selector", ColKind.VALUE),
))
in_function = RelationDef("InFunction", (
    Column("block", ColKind.BLOCK_ID),
    Column("func", ColKind.BLOCK_ID),
))
function_is_inner = RelationDef("FunctionIsInner", (
    Column("func", ColKind.BLOCK_ID),
))
formal_args = RelationDef("FormalArgs", (
    Column("func", ColKind.BLOCK_ID),
    Column("var", ColKind.VAR_ID),
    Column("index", ColKind.INDEX),
))
ir_function_return = RelationDef("IRFunction_Return", (
    Column("func", ColKind.BLOCK_ID),
    Column("block", ColKind.BLOCK_ID),
))
function_contract = RelationDef("Function_Contract", (
    Column("func", ColKind.BLOCK_ID),
    Column("contract", ColKind.SYMBOL),
))

# Function calls
ir_function_call = RelationDef("IRFunctionCall", (
    Column("caller_block", ColKind.BLOCK_ID),
    Column("callee_func", ColKind.BLOCK_ID),
))
ir_function_call_return = RelationDef("IRFunctionCallReturn", (
    Column("caller_block", ColKind.BLOCK_ID),
    Column("callee_func", ColKind.BLOCK_ID),
    Column("return_block", ColKind.BLOCK_ID),
))
actual_return_args = RelationDef("ActualReturnArgs", (
    Column("caller_block", ColKind.BLOCK_ID),
    Column("var", ColKind.VAR_ID),
    Column("index", ColKind.INDEX),
))
ir_dynamic_private_call = RelationDef("IRDynamicPrivateCall", (
    Column("caller_block", ColKind.BLOCK_ID),
    Column("target_var", ColKind.VAR_ID),
))

# Events
event_signature_in_contract = RelationDef("EventSignatureInContract", (
    Column("sig_hash", ColKind.VALUE),
    Column("text_sig", ColKind.SYMBOL),
))

# Misc
constant_possible_sig_hash = RelationDef("ConstantPossibleSigHash", (
    Column("const", ColKind.VALUE),
    Column("canonical", ColKind.SYMBOL),
    Column("name", ColKind.SYMBOL),
))
unmapped_statements = RelationDef("UnmappedStatements", (
    Column("stmt", ColKind.STMT_ID),
))


# ---------------------------------------------------------------------------
# Collected set of all relations
# ---------------------------------------------------------------------------

ALL_RELATIONS: frozenset[RelationDef] = frozenset(
    v for v in globals().values() if isinstance(v, RelationDef)
)

# Name -> RelationDef lookup
_RELATION_BY_NAME: dict[str, RelationDef] = {r.name: r for r in ALL_RELATIONS}

# Convenience: set of all identifier ColKinds
_ID_KINDS = frozenset(k for k in ColKind if k.is_identifier)


# ---------------------------------------------------------------------------
# Key type for TACRelations access
# ---------------------------------------------------------------------------

RelKey = Union[RelationDef, str]


def _resolve_key(key: RelKey) -> str:
    """Resolve a RelationDef or string to a relation name string."""
    if isinstance(key, RelationDef):
        return key.name
    return key


def _resolve_def(key: RelKey) -> Optional[RelationDef]:
    """Resolve a key to a RelationDef, if known."""
    if isinstance(key, RelationDef):
        return key
    return _RELATION_BY_NAME.get(key)


# ---------------------------------------------------------------------------
# TACRelations — low-level relational TAC container
# ---------------------------------------------------------------------------

class TACRelations:
    """Low-level container for Gigahorse TAC output as raw tuples.

    Each relation is stored as a list of string tuples.  Access using
    RelationDef constants:

        from tac_schema import tac_op, tac_def
        rows = tac[tac_op]

    Supports loading from disk, transformations (prefix/remap identifiers),
    merging multiple instances, and writing back to disk.
    """

    def __init__(
        self,
        data: Optional[dict[str, list[tuple[str, ...]]]] = None,
    ):
        self._data: dict[str, list[tuple[str, ...]]] = data or {}

    # -------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------

    @classmethod
    def from_dir(cls, out_dir: str | Path) -> TACRelations:
        """Load all known relations from a Souffle output directory.

        Raises FileNotFoundError if any relation file is missing.
        """
        out_dir = Path(out_dir)
        if not out_dir.is_dir():
            raise FileNotFoundError(f"Output directory not found: {out_dir}")

        data: dict[str, list[tuple[str, ...]]] = {}
        missing: list[str] = []

        for rel in ALL_RELATIONS:
            rows = cls._read_csv(out_dir, rel.name)
            if rows is not None:
                data[rel.name] = rows
            else:
                missing.append(rel.name)

        if missing:
            names = ", ".join(sorted(missing))
            raise FileNotFoundError(
                f"Missing relation files in {out_dir}: {names}"
            )

        return cls(data=data)

    @staticmethod
    def _read_csv(out_dir: Path, name: str) -> Optional[list[tuple[str, ...]]]:
        """Read a single Souffle relation file (tab-separated, no header)."""
        path = out_dir / f"{name}.csv"
        if not path.exists():
            path = out_dir / name
            if not path.exists():
                return None
        with open(path, "r") as f:
            return [tuple(row) for row in csv.reader(f, delimiter="\t")]

    # -------------------------------------------------------------------
    # Access
    # -------------------------------------------------------------------

    def __getitem__(self, key: RelKey) -> list[tuple[str, ...]]:
        """Get tuples for a relation.  Returns empty list if not loaded."""
        return self._data.get(_resolve_key(key), [])

    def __setitem__(self, key: RelKey, rows: list[tuple[str, ...]]):
        self._data[_resolve_key(key)] = rows

    def __contains__(self, key: RelKey) -> bool:
        name = _resolve_key(key)
        return name in self._data and len(self._data[name]) > 0

    def __len__(self) -> int:
        return sum(len(rows) for rows in self._data.values())

    @property
    def relation_names(self) -> list[str]:
        """Names of all loaded (non-empty) relations."""
        return [k for k in self._data.keys()]

    @property
    def loaded_relations(self) -> list[RelationDef]:
        """RelationDefs of all loaded (non-empty) known relations."""
        return [r for r in ALL_RELATIONS if r.name in self._data and self._data[r.name]]

    # -------------------------------------------------------------------
    # Transformations
    # -------------------------------------------------------------------

    def prefix_identifiers(self, prefix: str) -> None:
        """Prefix all identifier columns (STMT_ID, BLOCK_ID, VAR_ID) in-place."""
        self.map_identifiers(lambda id_str: prefix + id_str)

    def map_identifiers(
        self,
        fn: Callable[[str], str],
        kinds: Optional[frozenset[ColKind]] = None,
    ) -> None:
        """Apply a function to all identifier columns in-place.

        Args:
            fn: Transformation function applied to each identifier string.
            kinds: Which ColKind(s) to affect. Defaults to all identifier kinds.
        """
        target_kinds = kinds or _ID_KINDS

        for rel_name, rows in self._data.items():
            rel_def = _RELATION_BY_NAME.get(rel_name)
            if rel_def is None:
                continue

            id_indices = [
                i for i, c in enumerate(rel_def.columns)
                if c.kind in target_kinds
            ]
            if not id_indices:
                continue

            new_rows = []
            for row in rows:
                row_list = list(row)
                for i in id_indices:
                    if i < len(row_list):
                        row_list[i] = fn(row_list[i])
                new_rows.append(tuple(row_list))
            self._data[rel_name] = new_rows

    def filter_relation(
        self,
        key: RelKey,
        predicate: Callable[[tuple[str, ...]], bool],
    ) -> None:
        """Filter rows of a relation in-place."""
        name = _resolve_key(key)
        if name in self._data:
            self._data[name] = [r for r in self._data[name] if predicate(r)]

    def drop_relation(self, key: RelKey) -> None:
        """Remove a relation entirely."""
        self._data.pop(_resolve_key(key), None)

    def set_contract(self, contract: str) -> None:
        """Set the contract name for all functions in Function_Contract."""
        rows = self[function_contract]
        self[function_contract] = [(func_id, contract) for func_id, _ in rows]


    # -------------------------------------------------------------------
    # Merging
    # -------------------------------------------------------------------

    @classmethod
    def merge(cls, *instances: TACRelations) -> TACRelations:
        """Merge multiple TACRelations by concatenating all rows per relation.

        Caller is responsible for ensuring identifiers don't collide
        (e.g. by calling prefix_identifiers() first).
        """
        if not instances:
            return cls()

        merged_data: dict[str, list[tuple[str, ...]]] = {}

        all_rel_names: set[str] = set()
        for inst in instances:
            all_rel_names.update(inst.relation_names)

        for rel_name in all_rel_names:
            combined: list[tuple[str, ...]] = []
            for inst in instances:
                combined.extend(inst[rel_name])
            merged_data[rel_name] = combined

        return cls(data=merged_data)

    # -------------------------------------------------------------------
    # Writing
    # -------------------------------------------------------------------

    def write_dir(self, out_dir: str | Path) -> None:
        """Write all loaded relations to a directory as tab-separated .csv files."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for rel_name, rows in self._data.items():
            path = out_dir / f"{rel_name}.csv"
            with open(path, "w", newline="") as f:
                writer = csv.writer(f, delimiter="\t")
                for row in rows:
                    writer.writerow(row)

    # -------------------------------------------------------------------
    # Introspection / summary
    # -------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        """Row counts per loaded relation."""
        return {k: len(v) for k, v in self._data.items() if v}

    def __repr__(self) -> str:
        loaded = len(self.relation_names)
        total = sum(len(v) for v in self._data.values())
        return f"TACRelations({loaded} relations, {total} rows)"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    tac = TACRelations.from_dir(out_dir)
    print(tac)
    print()
    for name, count in sorted(tac.summary().items(), key=lambda x: -x[1]):
        print(f"  {name}: {count} rows")