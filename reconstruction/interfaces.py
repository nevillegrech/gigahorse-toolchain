"""Observed calldata fields, checked value constraints and direct use roles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .calldata import CalldataViews, View
from .semantics import _argument_types

if TYPE_CHECKING:
    from .model import Program


@dataclass
class CalldataField:
    function: str
    argument: int
    path: list[str]
    field_index: int | None
    encoding: str
    variables: list[str] = field(default_factory=list)
    checked_type_candidates: list[str] = field(default_factory=list)
    constraints: list[dict] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(
        default_factory=lambda: [
            "Fields and roles are inferred from raw accesses, not original declarations or parameter names.",
            "Constraints describe listed checks of loaded values, not a type guarantee on every path or element.",
        ]
    )

    def label(self) -> str:
        base = f"arg{self.argument}"
        if self.path:
            base += "." + ".".join(self.path)
        return base + (f".field[{self.field_index}]" if self.field_index is not None else "")


def analyze_calldata_fields(program: Program) -> list[CalldataField]:
    if program.semantics is None:
        return []
    semantics = program.semantics
    results = []
    for function in program.functions:
        views = CalldataViews(program, function)
        fields: dict[tuple[int, tuple[str, ...], int | None], CalldataField] = {}
        bound = {}

        def key(view: View, index: int | None):
            path = tuple(
                "element(*)" if s.kind == "element" else f"dynamic_field({s.index.constant})"
                for s in view.steps
            )
            return view.argument, path, index

        def obtain(identity, fields=fields, function_id=function.id):
            if identity not in fields:
                argument, path, index = identity
                fields[identity] = CalldataField(
                    function_id, argument, list(path), index, "head_word"
                )
            return fields[identity]

        for variable, (access, evidence) in views.bindings.items():
            if access.kind != "word" or access.index.terms:
                continue
            # Relative-element and dynamic-struct heads have observable fields.
            # A root array's length/head table is a different wire representation.
            if (
                not access.view.steps
                and views.root_info[access.view.argument]["kind_hint"] != "struct"
            ):
                continue
            identity = key(access.view, access.index.constant)
            descriptor = obtain(identity)
            descriptor.variables.append(variable)
            descriptor.evidence.extend(evidence)
            bound[variable] = identity
        for copy in views.byte_copies:
            path = copy["view"]
            steps = list(path["steps"])
            index = None
            if steps and steps[-1]["kind"] == "field" and not steps[-1]["index"]["terms"]:
                index = int(steps.pop()["index"]["constant"], 16)
            canonical = tuple(
                "element(*)"
                if s["kind"] == "element"
                else f"dynamic_field({int(s['index']['constant'], 16)})"
                for s in steps
            )
            descriptor = obtain((path["argument"], canonical, index))
            descriptor.encoding = "byte_sequence"
            descriptor.roles.append("copied_from_calldata")
            descriptor.evidence.extend(copy["evidence"])
            descriptor.limitations.append(
                "Byte copying does not distinguish bytes/string or establish an original ABI type."
            )

        def origin(variable: str, seen: frozenset[str] = frozenset(), *, bound=bound, views=views):
            if variable in bound:
                return bound[variable]
            definition = views.offsets.definitions.get(variable)
            if definition is None or variable in seen or len(seen) >= 16:
                return None
            if definition.opcode == "MOV" and len(definition.operands) == 1:
                return origin(definition.operands[0], seen | {variable})
            if definition.opcode == "AND" and len(definition.operands) == 2:
                sources = [v for v in definition.operands if v not in views.offsets.constants]
                if len(sources) == 1:
                    return origin(sources[0], seen | {variable})
            return None

        def condition_inputs(
            variable: str, seen: frozenset[str] = frozenset(), *, bound=bound, views=views
        ) -> set:
            if variable in bound:
                return {bound[variable]}
            definition = views.offsets.definitions.get(variable)
            if (
                definition is None
                or variable in seen
                or len(seen) >= 16
                or definition.opcode
                not in {"ISZERO", "EQ", "LT", "GT", "SLT", "SGT", "AND", "OR", "XOR", "MOV"}
            ):
                return set()
            return set().union(
                *(condition_inputs(v, seen | {variable}) for v in definition.operands)
            )

        for block in program.blocks:
            if block.id not in function.blocks:
                continue
            for stmt in block.instructions:
                uses = []
                if (
                    stmt.opcode in {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}
                    and len(stmt.operands) >= 2
                ):
                    uses.append((origin(stmt.operands[1]), stmt.opcode.lower() + "_target"))
                    if stmt.opcode in {"CALL", "CALLCODE"} and len(stmt.operands) >= 3:
                        uses.append((origin(stmt.operands[2]), "call_value"))
                if stmt.opcode == "JUMPI" and len(stmt.operands) == 2:
                    uses.extend(
                        (identity, "condition_input")
                        for identity in condition_inputs(stmt.operands[1])
                    )
                for identity, role in uses:
                    if identity is not None:
                        fields[identity].roles.append(role)
                        fields[identity].evidence.append(stmt.id)
        for descriptor in fields.values():
            for variable in sorted(set(descriptor.variables)):
                types, validations = _argument_types(
                    {variable}, semantics.cast_facts, program, semantics.guards, semantics.constants
                )
                if validations:
                    descriptor.checked_type_candidates.extend(types)
                    descriptor.constraints.append(
                        {"variable": variable, "type_candidates": types, "statements": validations}
                    )
                    descriptor.evidence.extend(validations)
            descriptor.variables = sorted(set(descriptor.variables))
            descriptor.roles = sorted(set(descriptor.roles))
            descriptor.evidence = sorted(set(descriptor.evidence))
            descriptor.checked_type_candidates = sorted(set(descriptor.checked_type_candidates))
            descriptor.limitations = sorted(set(descriptor.limitations))
            results.append(descriptor)
    return sorted(
        results,
        key=lambda f: (
            f.function,
            f.argument,
            f.path,
            -1 if f.field_index is None else f.field_index,
        ),
    )
