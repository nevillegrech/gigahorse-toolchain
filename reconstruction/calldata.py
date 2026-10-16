"""Evidence-backed raw ABI views, inferred from calldata address arithmetic.

These are accessors, not Solidity values: words are zero padded, every address
operation wraps at 256 bits, and indexing introduces no bounds checks. A relative
element/field means the bytecode actually added the corresponding head word to
the ABI base. It does not establish the original tuple, array or bytes type.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Function, Program

MASK = (1 << 256) - 1
ACCESSORS = {
    "offset": "base byte offset",
    "word_offset(k)": "u256(offset + 32*k)",
    "word(k)": "evm.calldataload(word_offset(k))",
    "length": "word(0), an inferred length word",
    "data_offset": "u256(offset + 32)",
    "head_offset(i)": "u256(data_offset + 32*i)",
    "head_word(i)": "evm.calldataload(head_offset(i))",
    "element(i)": "raw_calldata_view(u256(data_offset + head_word(i)))",
    "dynamic_field(k)": "raw_calldata_view(u256(offset + word(k)))",
}


@dataclass(frozen=True)
class Atom:
    kind: str
    variable: str = ""
    address: Offset | None = None


@dataclass(frozen=True)
class Offset:
    """An affine expression over SSA values and recursively addressed loads."""

    constant: int = 0
    terms: tuple[tuple[Atom, int], ...] = ()

    def add(self, other: Offset, factor: int = 1) -> Offset:
        coefficients: defaultdict[Atom, int] = defaultdict(int, self.terms)
        for atom, coefficient in other.terms:
            coefficients[atom] += coefficient * factor
        terms = [(atom, value & MASK) for atom, value in coefficients.items() if value & MASK]
        return Offset(
            (self.constant + factor * other.constant) & MASK,
            tuple(sorted(terms, key=lambda pair: repr(pair[0]))),
        )

    def scale(self, factor: int) -> Offset:
        return Offset().add(self, factor)

    def word_index(self) -> Offset | None:
        if self.constant % 32 or any(coefficient % 32 for _, coefficient in self.terms):
            return None
        return Offset(self.constant // 32, tuple((a, c // 32) for a, c in self.terms))

    def evaluate(self, data: bytes, variables: Mapping[str, int]) -> int:
        value = self.constant
        for atom, coefficient in self.terms:
            if atom.kind == "load" and atom.address is not None:
                number = load_word(data, atom.address.evaluate(data, variables))
            else:
                number = variables[atom.variable]
            value += coefficient * number
        return value & MASK

    def render(
        self, variable: Callable[[str], str], load: Callable[[Offset], str] | None = None
    ) -> str:
        parts = [hex(self.constant)] if self.constant or not self.terms else []
        for atom, coefficient in self.terms:
            text = (
                load(atom.address)
                if atom.kind == "load" and atom.address is not None and load is not None
                else f"evm.calldataload({atom.address.render(variable, load)})"
                if atom.kind == "load" and atom.address is not None
                else variable(atom.variable)
            )
            parts.append(text if coefficient == 1 else f"u256({hex(coefficient)} * {text})")
        return parts[0] if len(parts) == 1 else "u256(" + " + ".join(parts) + ")"

    def to_dict(self) -> dict:
        return {
            "constant": hex(self.constant),
            "terms": [
                {
                    "coefficient": hex(coefficient),
                    "kind": atom.kind,
                    **(
                        {"address": atom.address.to_dict()}
                        if atom.address is not None
                        else {"variable": atom.variable}
                    ),
                }
                for atom, coefficient in self.terms
            ],
        }


def load_word(data: bytes, address: int) -> int:
    return int.from_bytes(data[address : address + 32].ljust(32, b"\0"))


class Offsets:
    def __init__(self, program: Program):
        grouped = defaultdict(list)
        for block in program.blocks:
            for statement in block.instructions:
                for variable in statement.definitions:
                    grouped[variable].append(statement)
        self.definitions = {v: ss[0] for v, ss in grouped.items() if len(ss) == 1}
        self.constants = program.semantics.constants if program.semantics else program.constants
        self.cache: dict[str, tuple[Offset, frozenset[str]]] = {}

    def value(
        self, variable: str, seen: frozenset[str] = frozenset()
    ) -> tuple[Offset, frozenset[str]]:
        if variable in self.cache:
            return self.cache[variable]
        stmt = self.definitions.get(variable)
        evidence = frozenset({stmt.id}) if stmt else frozenset()
        fallback = Offset(0, ((Atom("variable", variable), 1),)), evidence
        if variable in seen or len(seen) >= 48:
            return fallback
        result = fallback[0]
        if variable in self.constants:
            result = Offset(int(self.constants[variable], 16))
        elif (
            stmt
            and len(stmt.definitions) == 1
            and stmt.opcode in {"ADD", "SUB", "MUL", "SHL", "MOV", "CALLDATALOAD"}
        ):
            operands = [self.value(v, seen | {variable}) for v in stmt.operands]
            args = [item[0] for item in operands]
            evidence |= frozenset().union(*(item[1] for item in operands))
            if stmt.opcode in {"ADD", "SUB"} and len(args) == 2:
                result = args[0].add(args[1], -1 if stmt.opcode == "SUB" else 1)
            elif stmt.opcode == "MUL" and len(args) == 2:
                if not args[0].terms:
                    result = args[1].scale(args[0].constant)
                elif not args[1].terms:
                    result = args[0].scale(args[1].constant)
            elif stmt.opcode == "SHL" and len(args) == 2 and not args[0].terms:
                result = args[1].scale(1 << args[0].constant if args[0].constant < 256 else 0)
            elif stmt.opcode == "MOV" and len(args) == 1:
                result = args[0]
            elif stmt.opcode == "CALLDATALOAD" and len(args) == 1:
                result = Offset(0, ((Atom("load", address=args[0]), 1),))
        self.cache[variable] = result, evidence
        return result, evidence


@dataclass(frozen=True)
class Step:
    kind: str
    index: Offset


@dataclass(frozen=True)
class View:
    argument: int
    steps: tuple[Step, ...] = ()

    def render(
        self, variable: Callable[[str], str], load: Callable[[Offset], str] | None = None
    ) -> str:
        text = f"cd_arg{self.argument}"
        for step in self.steps:
            method = "element" if step.kind == "element" else "dynamic_field"
            text += f".{method}({step.index.render(variable, load)})"
        return text

    def offset(self, data: bytes, variables: Mapping[str, int]) -> int:
        base = (4 + load_word(data, 4 + self.argument * 32)) & MASK
        for step in self.steps:
            index = step.index.evaluate(data, variables)
            if step.kind == "element":
                base = (base + 32) & MASK
            base = (base + load_word(data, (base + 32 * index) & MASK)) & MASK
        return base

    def to_dict(self) -> dict:
        return {
            "argument": self.argument,
            "steps": [{"kind": s.kind, "index": s.index.to_dict()} for s in self.steps],
        }


@dataclass(frozen=True)
class Access:
    view: View
    kind: str
    index: Offset = Offset()

    def render(
        self, variable: Callable[[str], str], load: Callable[[Offset], str] | None = None
    ) -> str:
        base = self.view.render(variable, load)
        if self.kind in {"offset", "data_offset", "length"}:
            return base + "." + self.kind
        return f"{base}.{self.kind}({self.index.render(variable, load)})"

    def evaluate(self, data: bytes, variables: Mapping[str, int]) -> int:
        base = self.view.offset(data, variables)
        if self.kind == "offset":
            return base
        if self.kind == "data_offset":
            return (base + 32) & MASK
        if self.kind == "length":
            return load_word(data, base)
        if self.kind in {"head_offset", "head_word"}:
            base = (base + 32) & MASK
        index = self.index.evaluate(data, variables)
        address = (base + 32 * index) & MASK
        return load_word(data, address) if self.kind in {"length", "word", "head_word"} else address


class CalldataViews:
    def __init__(self, program: Program, function: Function):
        self.offsets = Offsets(program)
        self.roots: dict[Offset, View] = {}
        self.root_info: dict[int, dict] = {}
        self.views: dict[Offset, View] = {}
        self.bindings: dict[str, tuple[Access, frozenset[str]]] = {}
        self.byte_copies: list[dict] = []
        self.length_views: set[View] = set()
        self.cache: dict[Offset, View | None] = {}
        if program.semantics is None or not function.selectors:
            return
        ambiguous: set[Offset] = set()
        kinds: defaultdict[int, set[str]] = defaultdict(set)
        for argument in program.semantics.arguments:
            if argument.function == function.id:
                kinds[argument.index].add(argument.kind)
        for argument in program.semantics.arguments:
            if (
                argument.function != function.id
                or argument.kind not in {"array", "struct"}
                or len(kinds[argument.index]) != 1
                or argument.index >= 1024
            ):
                continue
            head = Offset(4 + 32 * argument.index)
            expected = Offset(4, ((Atom("load", address=head), 1),))
            verified = []
            root_evidence: set[str] = set()
            for variable in argument.variables:
                expression, sources = self.offsets.value(variable)
                if expression == expected:
                    verified.append(variable)
                    root_evidence.update(sources)
            if not verified:
                continue
            root = View(argument.index)
            if expected in self.roots and self.roots[expected] != root:
                ambiguous.add(expected)
            self.roots[expected] = root
            self.root_info[argument.index] = {
                "argument": argument.index,
                "kind_hint": argument.kind,
                "variables": sorted(verified),
                "evidence": sorted(root_evidence),
            }
            if argument.kind == "array":
                self.length_views.add(root)
        for expression in ambiguous:
            self.root_info.pop(self.roots.pop(expression).argument, None)
        blocks = [b for b in program.blocks if b.id in function.blocks]
        variables = sorted(
            {v for b in blocks for s in b.instructions for v in s.definitions + s.operands}
        )
        for variable in variables:
            expression, _ = self.offsets.value(variable)
            self._view(expression)
        # A copy of load(base) bytes beginning at base+32 supports a byte-sequence
        # view. This does not distinguish bytes/string or establish valid bounds.
        for block in blocks:
            for stmt in block.instructions:
                if stmt.opcode != "CALLDATACOPY" or len(stmt.operands) != 3:
                    continue
                start, start_evidence = self.offsets.value(stmt.operands[1])
                size, size_evidence = self.offsets.value(stmt.operands[2])
                base = start.add(Offset(32), -1)
                view = self._view(base)
                if view and size == Offset(0, ((Atom("load", address=base), 1),)):
                    self.length_views.add(view)
                    self.byte_copies.append(
                        {
                            "statement": stmt.id,
                            "destination_variable": stmt.operands[0],
                            "view": view.to_dict(),
                            "evidence": sorted(start_evidence | size_evidence | {stmt.id}),
                        }
                    )
        for variable in variables:
            expression, evidence = self.offsets.value(variable)
            definition = self.offsets.definitions.get(variable)
            if variable in self.offsets.constants:
                continue
            if definition and definition.opcode == "CALLDATALOAD" and len(definition.operands) == 1:
                address, _ = self.offsets.value(definition.operands[0])
                access = self._access(address, read=True)
            else:
                access = self._access(expression, read=False)
            if access:
                root_sources = self.root_info[access.view.argument]["evidence"]
                self.bindings[variable] = access, evidence | frozenset(root_sources)

    def _view(self, expression: Offset, depth: int = 0) -> View | None:
        if expression in self.roots:
            self.views[expression] = self.roots[expression]
            return self.roots[expression]
        if expression in self.cache:
            return self.cache[expression]
        if depth >= 16:
            return None
        candidates = set()
        for atom, coefficient in expression.terms:
            if coefficient != 1 or atom.kind != "load" or atom.address is None:
                continue
            remainder = expression.add(Offset(0, ((atom, 1),)), -1)
            parent = self._view(remainder, depth + 1)
            difference = atom.address.add(remainder, -1)
            if parent and not difference.terms and difference.constant < 32 * 1024:
                index = difference.word_index()
                if index is not None:
                    candidates.add(View(parent.argument, (*parent.steps, Step("field", index))))
            parent = self._view(remainder.add(Offset(32), -1), depth + 1)
            if parent:
                index = difference.word_index()
                if index is not None and (
                    index.terms
                    or (
                        not parent.steps and self.root_info[parent.argument]["kind_hint"] == "array"
                    )
                ):
                    candidates.add(View(parent.argument, (*parent.steps, Step("element", index))))
        result = next(iter(candidates)) if len(candidates) == 1 else None
        self.cache[expression] = result
        if result:
            self.views[expression] = result
        return result

    def _access(self, address: Offset, *, read: bool) -> Access | None:
        exact = self._view(address)
        if exact and not read:
            return Access(exact, "offset")
        candidates: list[tuple[int, Access]] = []
        for base, view in self.views.items():
            difference = address.add(base, -1)
            if not difference.terms and difference.constant < 32 * 1024:
                index = difference.word_index()
                if index is not None:
                    kind = "word" if read else "word_offset"
                    if difference.constant == 0:
                        kind = "length" if read and view in self.length_views else kind
                    elif difference.constant == 32 and not read:
                        kind = "data_offset"
                    if kind in {"length", "data_offset"}:
                        index = Offset()
                    candidates.append((len(view.steps) * 2 + 1, Access(view, kind, index)))
            # head_word is a raw load from base+32+32*i, with no index check.
            index = difference.add(Offset(32), -1).word_index()
            if index is not None and index.terms:
                candidates.append(
                    (
                        len(view.steps) * 2,
                        Access(view, "head_word" if read else "head_offset", index),
                    )
                )
        if not candidates:
            return None
        best = max(rank for rank, _ in candidates)
        results = {access for rank, access in candidates if rank == best}
        return next(iter(results)) if len(results) == 1 else None

    def render(self, access: Access, variable: Callable[[str], str]) -> str:
        active: set[Offset] = set()

        def load(address: Offset) -> str:
            linked = self._access(address, read=True) if address not in active else None
            if linked:
                active.add(address)
                text = linked.render(variable, load)
                active.remove(address)
                return text
            return f"evm.calldataload({address.render(variable)})"

        return access.render(variable, load)

    def metadata(self, function: str) -> dict:
        return {
            "function": function,
            "semantics": "raw-calldata-accessors-modulo-2**256-zero-padded-no-added-checks",
            "limits": {"expression_depth": 48, "view_depth": 16, "field_words": 1024},
            "roots": [self.root_info[i] for i in sorted(self.root_info)],
            "byte_copies": self.byte_copies,
            "bindings": [
                {
                    "variable": variable,
                    "view": access.view.to_dict(),
                    "kind": access.kind,
                    "index": access.index.to_dict(),
                    "evidence": sorted(evidence),
                }
                for variable, (access, evidence) in sorted(self.bindings.items())
            ],
        }


def analyze_calldata(program: Program) -> list[dict]:
    results = []
    for function in program.functions:
        views = CalldataViews(program, function)
        if views.bindings:
            results.append(views.metadata(function.id))
    return results
