"""Load Gigahorse relations without depending on its native runner."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from src import tac_schema as schema

if TYPE_CHECKING:
    from .behavior import BehaviorInfo
    from .interfaces import CalldataField
    from .returns import ReturnLayout
    from .semantics import SemanticInfo
    from .signatures import SignatureInfo


def sort_key(identifier: str) -> tuple[int, str]:
    match = re.search(r"0x([0-9a-fA-F]+)", identifier)
    return (int(match[1], 16) if match else -1, identifier)


@dataclass
class Instruction:
    id: str
    opcode: str
    definitions: list[str]
    operands: list[str]
    original_statements: list[str]


@dataclass
class Block:
    id: str
    instructions: list[Instruction]
    successors: list[str]
    fallthrough: list[str]


@dataclass
class Function:
    id: str
    entries: list[str]
    selectors: list[str]
    name_hint: str | None
    formal_variables: list[str]
    blocks: list[str]


@dataclass
class Program:
    constants: dict[str, str]
    block_targets: dict[str, str]
    functions: list[Function]
    blocks: list[Block]
    warnings: list[str]
    unmapped_statements: list[str]
    semantics: SemanticInfo | None = None
    phi_inputs: list[tuple[str, str, str]] = field(default_factory=list)
    signature_info: SignatureInfo | None = None
    calldata_views: list[dict] = field(default_factory=list)
    behavior: BehaviorInfo | None = None
    return_layouts: list[ReturnLayout] = field(default_factory=list)
    calldata_fields: list[CalldataField] = field(default_factory=list)
    constant_hints: dict[str, str] = field(default_factory=dict)
    derived_constants: dict[str, str] = field(default_factory=dict)
    constant_verification: dict = field(default_factory=dict)
    revert_memory: dict[str, dict] = field(default_factory=dict)
    runtime_bytecode: str | None = None
    phi_entry_inputs: list[tuple[str, str]] = field(default_factory=list)
    # Relations directory the program was loaded from (not serialized).
    source_directory: Path | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        result = asdict(self)
        from .bytecode import code_context
        from .presentation import InternalInterfaces
        from .reverts import analyze_reverts

        result.pop("runtime_bytecode")
        result.pop("source_directory")
        result["bytecode_context"] = code_context(self)
        result["internal_interfaces"] = InternalInterfaces(self).metadata()
        result["revert_summaries"] = analyze_reverts(self)
        result["schema_version"] = 2
        result["representation"] = "gigahorse-ir-presentation"
        result["compilable_solidity"] = False
        accesses = []
        for block in self.blocks:
            for stmt in block.instructions:
                if stmt.opcode in {"SLOAD", "SSTORE", "TLOAD", "TSTORE"} and stmt.operands:
                    accesses.append(
                        {
                            "statement": stmt.id,
                            "block": block.id,
                            "operation": stmt.opcode,
                            "slot_variable": stmt.operands[0],
                            "constant_slot": self.constants.get(stmt.operands[0]),
                        }
                    )
        result["storage_accesses"] = accesses
        return result


def _unique_values(
    rows: list[tuple[str, ...]], description: str, warnings: list[str], *, strict: bool = False
) -> dict[str, str]:
    values: defaultdict[str, set[str]] = defaultdict(set)
    for key, value in rows:
        values[key].add(value)
    result = {}
    for key in sorted(values, key=sort_key):
        if len(values[key]) == 1:
            result[key] = next(iter(values[key]))
        else:
            if strict:
                raise ValueError(f"Conflicting {description} for {key}")
            warnings.append(f"Ambiguous {description} for {key}; kept as an unresolved variable.")
    return result


def load_program(directory: Path) -> Program:
    tac = schema.TACRelations.from_dir(directory)
    for relation in sorted(schema.ALL_RELATIONS, key=lambda rel: rel.name):
        for row_number, row in enumerate(tac[relation], 1):
            if len(row) != len(relation.columns):
                raise ValueError(f"{relation.name}: row {row_number} has wrong column count")
            for col, value in zip(relation.columns, row, strict=True):
                if col.kind == schema.ColKind.INDEX and not re.fullmatch(r"-?[0-9]+", value):
                    raise ValueError(
                        f"{relation.name}: row {row_number} has invalid index {value!r}"
                    )

    warnings = [
        "This is low-level pseudocode, not compilable Solidity or an equivalence proof.",
        "Function names are upstream hints; formal variables are not recovered ABI parameters.",
    ]
    constants = _unique_values(tac[schema.tac_variable_value], "constant", warnings)
    for variable, value in list(constants.items()):
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
            warnings.append(f"Invalid EVM constant for {variable}; kept unresolved.")
            del constants[variable]
    targets = _unique_values(tac[schema.tac_variable_block_value], "block target", warnings)
    opcodes = _unique_values(tac[schema.tac_op], "opcode", warnings, strict=True)

    def indexed(relation: schema.RelationDef) -> dict[str, list[str]]:
        grouped: defaultdict[str, dict[int, str]] = defaultdict(dict)
        phi_inputs: defaultdict[str, set[str]] = defaultdict(set)
        for key, variable, index in tac[relation]:
            position = int(index)
            if relation == schema.tac_use and opcodes.get(key) == "PHI":
                if position != -1:
                    raise ValueError(f"{relation.name}: expected unordered PHI index -1 at {key}")
                phi_inputs[key].add(variable)
                continue
            if position in grouped[key] and grouped[key][position] != variable:
                raise ValueError(f"{relation.name}: conflicting operand at {key}, index {position}")
            grouped[key][position] = variable
        for key, positions in grouped.items():
            if sorted(positions) != list(range(len(positions))):
                raise ValueError(f"{relation.name}: non-contiguous operand indices at {key}")
        result = {
            key: [positions[i] for i in sorted(positions)] for key, positions in grouped.items()
        }
        result.update({key: sorted(values, key=sort_key) for key, values in phi_inputs.items()})
        return result

    definitions = indexed(schema.tac_def)
    operands = indexed(schema.tac_use)
    formals = indexed(schema.formal_args)
    origins: defaultdict[str, set[str]] = defaultdict(set)
    for statement, original in tac[schema.tac_statement_original_statement]:
        origins[statement].add(original)
    instruction_blocks = _unique_values(
        tac[schema.tac_block], "statement block", warnings, strict=True
    )
    if set(opcodes) - set(instruction_blocks):
        raise ValueError("Some TAC instructions have no unambiguous block membership")
    block_statements: defaultdict[str, set[str]] = defaultdict(set)
    for statement, block in instruction_blocks.items():
        if statement in opcodes:
            block_statements[block].add(statement)

    next_predecessors: defaultdict[str, set[str]] = defaultdict(set)
    for source, target in tac[schema.tac_statement_next]:
        next_predecessors[target].add(source)

    successors: defaultdict[str, set[str]] = defaultdict(set)
    fallthrough: defaultdict[str, set[str]] = defaultdict(set)
    for source, target in tac[schema.local_block_edge]:
        successors[source].add(target)
    for source, target in tac[schema.ir_fallthrough_edge]:
        fallthrough[source].add(target)

    def order(block_id: str) -> list[str]:
        """Respect relation ordering; expose incomplete order instead of inventing it."""
        remaining = set(block_statements[block_id])
        ordered = []
        partial = False
        while remaining:
            ready = sorted(
                (s for s in remaining if not next_predecessors[s].intersection(remaining)),
                key=sort_key,
            )
            if not ready:
                warnings.append(
                    f"Cyclic statement order in {block_id}; remaining order is uncertain."
                )
                ordered.extend(sorted(remaining, key=sort_key))
                break
            # PHI nodes are parallel block-entry merges, not ordinary sequential operations.
            phi = [s for s in ready if opcodes[s] == "PHI"]
            partial |= len([s for s in ready if opcodes[s] != "PHI"]) > 1
            chosen = phi[0] if phi else ready[0]
            ordered.append(chosen)
            remaining.remove(chosen)
        if partial:
            warnings.append(
                f"Partial statement order in {block_id}; ties use bytecode identifiers."
            )
        return ordered

    memberships: defaultdict[str, set[str]] = defaultdict(set)
    owners: defaultdict[str, set[str]] = defaultdict(set)
    for block, function in tac[schema.in_function]:
        memberships[function].add(block)
        owners[block].add(function)
    block_ids = set(block_statements) | set(owners)
    for source, target in tac[schema.local_block_edge] + tac[schema.ir_fallthrough_edge]:
        if source not in block_ids or target not in block_ids:
            raise ValueError(f"CFG edge references a missing block: {source} -> {target}")

    blocks = [
        Block(
            id=block_id,
            instructions=[
                Instruction(
                    id=s,
                    opcode=opcodes[s],
                    definitions=definitions.get(s, []),
                    operands=operands.get(s, []),
                    original_statements=sorted(origins[s], key=sort_key),
                )
                for s in order(block_id)
            ],
            successors=sorted(successors[block_id], key=sort_key),
            fallthrough=sorted(fallthrough[block_id], key=sort_key),
        )
        for block_id in sorted(block_ids, key=sort_key)
    ]
    entries: defaultdict[str, set[str]] = defaultdict(set)
    for (entry,) in tac[schema.ir_function_entry]:
        for owner in owners[entry]:
            entries[owner].add(entry)
    selectors: defaultdict[str, set[str]] = defaultdict(set)
    for function, selector in tac[schema.public_function]:
        if not re.fullmatch(r"0x[0-9a-fA-F]+", selector) or int(selector, 16) >= 1 << 32:
            raise ValueError(f"Invalid function selector: {selector!r}")
        selectors[function].add(f"0x{int(selector, 16):08x}")
    hints = _unique_values(tac[schema.high_level_function_name], "function name", warnings)
    functions = [
        Function(
            id=function,
            entries=sorted(entries[function], key=sort_key),
            selectors=sorted(selectors[function]),
            name_hint=hints.get(function),
            formal_variables=formals.get(function, []),
            blocks=sorted(memberships[function], key=sort_key),
        )
        for function in sorted(memberships, key=sort_key)
    ]
    if not blocks:
        raise ValueError("No recovered blocks; the analysis may have failed or timed out")
    if any(s.opcode == "PHI" for b in blocks for s in b.instructions):
        warnings.append(
            "Raw PHI operands are unordered; predecessor associations, when available, are reported separately."
        )
    if block_ids - set(owners):
        warnings.append("Some recovered blocks have no function membership; retained in output.")
    unmapped = sorted((s for (s,) in tac[schema.unmapped_statements]), key=sort_key)
    if unmapped:
        warnings.append(f"Gigahorse reports {len(unmapped)} unmapped original statements.")
    program = Program(constants, targets, functions, blocks, warnings, unmapped)
    program.source_directory = Path(directory)
    bytecode_file = Path(directory) / "bytecode.hex"
    if bytecode_file.is_file():
        from .bytecode import normalize_bytecode

        program.runtime_bytecode = normalize_bytecode(bytecode_file.read_text())
    program.phi_inputs = [
        (phi, predecessor, value) for phi, predecessor, value in tac[schema.tac_phi_input]
    ]
    program.phi_entry_inputs = [(phi, value) for phi, value in tac[schema.tac_phi_entry_input]]
    from .constants import resolve_constants
    from .semantics import load_semantics

    program.semantics = load_semantics(directory, program)
    if program.semantics is None:
        program.constants = resolve_constants(program, program.constants)
        program.warnings.append(
            "Semantic exports are unavailable; only the recovered IR is presented."
        )
    else:
        program.warnings.extend(program.semantics.warnings)
    program.constants = {
        variable: value
        for variable, value in program.constants.items()
        if variable not in program.constant_hints
    }
    program.constants.update(program.derived_constants)
    if program.constant_hints:
        program.warnings.append(
            f"{len(program.constant_hints)} native constant hints depend on reads, calls or "
            "function inputs; native hints are substituted only when established in the recovered CFG."
        )
    from .calldata import analyze_calldata

    program.calldata_views = analyze_calldata(program)
    from .behavior import analyze_behavior

    program.behavior = analyze_behavior(program)
    from .returns import analyze_returns

    program.return_layouts = analyze_returns(program)
    from .interfaces import analyze_calldata_fields

    program.calldata_fields = analyze_calldata_fields(program)
    return program
