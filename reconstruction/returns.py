"""Return words and candidate dynamic encodings, with encoder witnesses.

Layouts describe observed wire encodings, not original Solidity declarations.
Dynamic candidates annotate the raw RETURN; they never replace its byte range.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .calldata import Atom, Offset, Offsets
from .controlflow import FlowPlan, Region, dominators, structure_function
from .render import PURE

if TYPE_CHECKING:
    from .memory import MemoryInfo
    from .model import Function, Program

MASK = (1 << 256) - 1


@dataclass
class ReturnLayout:
    function: str
    statement: str
    status: str
    shape: dict | None
    words: list[str]
    evidence: list[str]
    limitations: list[str]


@dataclass
class Loop:
    header: str
    nodes: set[str]


def variable_offset(variable: str) -> Offset:
    return Offset(0, ((Atom("variable", variable), 1),))


def loops(region: Region | None) -> list[Loop]:
    if region is None:
        return []

    def nodes(node: Region) -> set[str]:
        return ({node.block} if node.kind == "block" and node.block else set()).union(
            *(nodes(c) for c in node.children)
        )

    result = [Loop(region.block, nodes(region))] if region.kind == "loop" and region.block else []
    return result + [loop for child in region.children for loop in loops(child)]


class ReturnAnalysis:
    def __init__(self, program: Program):
        self.program = program
        self.offsets = Offsets(program)
        self.definitions = self.offsets.definitions
        self.blocks = {b.id: b for b in program.blocks}
        self.statements = {s.id: s for b in program.blocks for s in b.instructions}
        self.statement_blocks = {s.id: b.id for b in program.blocks for s in b.instructions}

    def word_write_is_current(
        self, function: Function, writer: str, reader: str, offset: int
    ) -> bool:
        """Prove the full word's address and absence of intervening aliasing writes."""
        plan = structure_function(self.program, function)
        if not plan.region or plan.unresolved_phis:
            return False
        positions = {
            s.id: (b, i) for b in function.blocks for i, s in enumerate(self.blocks[b].instructions)
        }
        if writer not in positions or reader not in positions:
            return False
        start, finish = positions[writer], positions[reader]
        write, read = self.statements[writer], self.statements[reader]
        address = self.value(write.operands[0])
        if address != self.value(read.operands[0]).add(Offset(offset)):
            return False
        if not self.saved_value_is_current(function, writer, reader, write.operands[0]):
            return False
        edges = {b: t.targets for b, t in plan.transfers.items() if b in plan.reachable_blocks}
        dom = dominators(function.entries[0], edges)
        if start[0] not in dom.get(finish[0], set()) or (
            start[0] == finish[0] and start[1] >= finish[1]
        ):
            return False

        def interferes(stmt) -> bool:
            op = stmt.opcode
            destination: str
            length: Offset
            if op in {"MSTORE", "MSTORE8"}:
                destination, length = stmt.operands[0], Offset(32 if op == "MSTORE" else 1)
            elif op in {"MCOPY", "CALLDATACOPY", "RETURNDATACOPY", "CODECOPY", "EXTCODECOPY"}:
                index = 1 if op == "EXTCODECOPY" else 0
                destination, length = stmt.operands[index], self.value(stmt.operands[index + 2])
            elif op in {"CALL", "CALLCODE", "STATICCALL", "DELEGATECALL"}:
                index = 5 if op in {"CALL", "CALLCODE"} else 4
                destination, length = stmt.operands[index], self.value(stmt.operands[index + 1])
            elif op in PURE | {
                "MLOAD",
                "PHI",
                "MOV2",
                "SLOAD",
                "SSTORE",
                "TLOAD",
                "TSTORE",
                "SHA3",
                "GAS",
                "MSIZE",
                "RETURNDATASIZE",
                "CODESIZE",
                "COINBASE",
                "BASEFEE",
                "BLOBHASH",
                "BLOBBASEFEE",
                "PREVRANDAO",
                "DIFFICULTY",
                "BALANCE",
                "SELFBALANCE",
                "EXTCODEHASH",
                "EXTCODESIZE",
                "BLOCKHASH",
                "GASPRICE",
                "GASLIMIT",
                "CLZ",
                "PC",
                "JUMP",
                "JUMPI",
                "JUMPDEST",
                "RETURNPRIVATE",
                "RETURN",
                "REVERT",
                "STOP",
                "INVALID",
                "THROW",
                "SELFDESTRUCT",
                "CREATE",
                "CREATE2",
                "LOG0",
                "LOG1",
                "LOG2",
                "LOG3",
                "LOG4",
            }:
                return False
            else:
                return True  # Private/unknown effects have no disjointness proof.
            if length == Offset():
                return False
            distance = self.value(destination).add(address, -1)
            return bool(
                length.terms
                or distance.terms
                or not (distance.constant >= 32 and distance.constant + length.constant <= 1 << 256)
            )

        pending = [(start[0], start[1] + 1, False)]
        visited = set()
        while pending:
            block, index, changed = pending.pop()
            if (block, index, changed) in visited or (block, index) == start:
                continue
            visited.add((block, index, changed))
            if (block, index) == finish:
                if changed:
                    return False
                continue
            instructions = self.blocks[block].instructions
            if index < len(instructions):
                pending.append((block, index + 1, changed or interferes(instructions[index])))
            else:
                pending.extend((target, 0, changed) for target in plan.transfers[block].targets)
        return True

    def saved_value_is_current(
        self, function: Function, writer: str, reader: str, variable: str
    ) -> bool:
        """A memory snapshot is not necessarily the latest execution of an SSA label.

        Follow instruction positions after the store. A second execution of the
        value's definition followed by RETURN without another execution of this
        store invalidates the raw-word substitution. PHIs count as definitions.
        Cross-function snapshots and unresolved transfers stay raw as well.
        """
        if variable in self.offsets.constants:
            return True
        definition = self.definitions.get(variable)
        if definition is None:
            return variable in function.formal_variables
        # The printed word can expand a pure definition. A captured result may
        # itself stay current while its expanded PHI/read operands have changed.
        dependencies = {variable}
        pending_variables = [variable]
        while pending_variables:
            current = pending_variables.pop()
            source = self.definitions.get(current)
            if source and source.opcode in PURE and len(source.definitions) == 1:
                for operand in source.operands:
                    if operand not in dependencies and operand not in self.offsets.constants:
                        dependencies.add(operand)
                        pending_variables.append(operand)
        plan = structure_function(self.program, function)
        if plan.unresolved_phis or plan.region is None:
            return False
        positions = {
            s.id: (b, i) for b in function.blocks for i, s in enumerate(self.blocks[b].instructions)
        }
        if writer not in positions or reader not in positions or definition.id not in positions:
            return False
        start = positions[writer]
        finish = positions[reader]
        pending = [(start[0], start[1] + 1, False)]
        visited = set()
        while pending:
            block, index, changed = pending.pop()
            point = (block, index)
            state = (block, index, changed)
            if state in visited or point == start:
                continue
            visited.add(state)
            if point == finish:
                if changed:
                    return False
                continue
            instructions = self.blocks[block].instructions
            if index < len(instructions):
                changed |= bool(dependencies.intersection(instructions[index].definitions))
                pending.append((block, index + 1, changed))
            else:
                pending.extend((target, 0, changed) for target in plan.transfers[block].targets)
        return True

    def required_writes(self, writers: list[str], loop: Loop, plan: FlowPlan) -> bool:
        edges = {b: t.targets for b, t in plan.transfers.items()}
        # A successful early exit could leave gaps in the purported array.
        if any(b != loop.header and any(t not in loop.nodes for t in edges[b]) for b in loop.nodes):
            return False
        if any(
            b != loop.header
            and not edges[b]
            and (
                not self.blocks[b].instructions
                or self.blocks[b].instructions[-1].opcode not in {"REVERT", "INVALID", "THROW"}
            )
            for b in loop.nodes
        ):
            return False
        dom = dominators(
            loop.header, {b: tuple(t for t in edges[b] if t in loop.nodes) for b in loop.nodes}
        )
        back = [b for b in loop.nodes if loop.header in edges[b]]
        return bool(back) and all(self.statement_blocks[w] in dom[b] for w in writers for b in back)

    def value(self, variable: str) -> Offset:
        return self.offsets.value(variable)[0]

    def phi(
        self, variable: str, loop: Loop, plan: FlowPlan
    ) -> tuple[Offset, Offset, set[str]] | None:
        initial: set[Offset] = set()
        updated: set[Offset] = set()
        evidence: set[str] = set()
        for (source, target), copies in plan.copies.items():
            if target != loop.header:
                continue
            for copy in copies:
                if copy.destination == variable:
                    expression, sources = self.offsets.value(copy.source)
                    (updated if source in loop.nodes else initial).add(expression)
                    evidence.update(sources | {copy.phi})
        if len(initial) == len(updated) == 1:
            return next(iter(initial)), next(iter(updated)), evidence
        return None

    def count_loop(
        self, loop: Loop, length: Offset, plan: FlowPlan, *, stride: int
    ) -> tuple[str, set[str]] | None:
        transfer = plan.transfers[loop.header]
        if transfer.kind != "if":
            return None
        predicate, inverted, evidence = transfer.predicate, False, set()
        seen = set()
        while predicate and predicate not in seen:
            seen.add(predicate)
            stmt = self.definitions.get(predicate)
            if stmt is None:
                return None
            evidence.add(stmt.id)
            if stmt.opcode in {"ISZERO", "MOV"} and len(stmt.operands) == 1:
                inverted ^= stmt.opcode == "ISZERO"
                predicate = stmt.operands[0]
                continue
            if stmt.opcode not in {"LT", "GT"} or len(stmt.operands) != 2:
                return None
            index, bound = stmt.operands if stmt.opcode == "LT" else stmt.operands[::-1]
            update = self.phi(index, loop, plan)
            if (
                self.value(bound) != length
                or update is None
                or update[0] != Offset()
                or update[1] != variable_offset(index).add(Offset(stride))
            ):
                return None
            inside = transfer.targets[1 if inverted else 0]
            outside = transfer.targets[0 if inverted else 1]
            if inside not in loop.nodes or outside in loop.nodes:
                return None
            return index, evidence | update[2] | (
                {transfer.statement} if transfer.statement else set()
            )
        return None

    def aligned(self, expression: Offset, length: Offset) -> bool:
        if expression.constant or len(expression.terms) != 1:
            return False
        atom, coefficient = expression.terms[0]
        stmt = self.definitions.get(atom.variable) if atom.kind == "variable" else None
        if coefficient != 1 or stmt is None or stmt.opcode != "AND" or len(stmt.operands) != 2:
            return False
        args = [self.value(v) for v in stmt.operands]
        return Offset(MASK ^ 31) in args and length.add(Offset(31)) in args

    def boolean_word(self, variable: str) -> bool:
        stmt = self.definitions.get(variable)
        return bool(stmt and stmt.opcode in {"ISZERO", "EQ", "LT", "GT", "SLT", "SGT"})

    def byte_payload(
        self,
        cursor: str,
        tail_words: int,
        length_variable: str,
        outer: Loop,
        all_loops: list[Loop],
        plan: FlowPlan,
    ) -> tuple[dict, set[str]] | None:
        length = self.value(length_variable)
        length_read = self.definitions.get(length_variable)
        if length_read is None or length_read.opcode != "MLOAD" or len(length_read.operands) != 1:
            return None
        source = self.value(length_read.operands[0]).add(Offset(32))
        data = variable_offset(cursor).add(Offset(32 * (tail_words + 1)))
        for inner in all_loops:
            if inner.header == outer.header or not inner.nodes < outer.nodes:
                continue
            counted = self.count_loop(inner, length, plan, stride=32)
            if counted is None:
                continue
            index, evidence = counted
            copies = []
            for block in sorted(inner.nodes):
                for stmt in self.blocks[block].instructions:
                    if stmt.opcode != "MSTORE" or len(stmt.operands) != 2:
                        continue
                    if self.value(stmt.operands[0]) != data.add(variable_offset(index)):
                        continue
                    loaded = self.definitions.get(stmt.operands[1])
                    if (
                        loaded
                        and loaded.opcode == "MLOAD"
                        and self.value(loaded.operands[0]) == source.add(variable_offset(index))
                    ):
                        copies.append(stmt.id)
                        evidence.update({stmt.id, loaded.id, length_read.id})
            if len(copies) == 1 and self.required_writes(copies, inner, plan):
                return {
                    "kind": "byte_sequence",
                    "length_variable": length_variable,
                    "source_variable": length_read.operands[0],
                    "copy_statement": copies[0],
                }, evidence
        return None

    def element(
        self, cursor: str, loop: Loop, all_loops: list[Loop], plan: FlowPlan
    ) -> tuple[dict, set[str]] | None:
        update = self.phi(cursor, loop, plan)
        if update is None:
            return None
        stores: defaultdict[int, list] = defaultdict(list)
        all_stores = []
        for block in sorted(loop.nodes):
            for stmt in self.blocks[block].instructions:
                if stmt.opcode == "MSTORE" and len(stmt.operands) == 2:
                    all_stores.append(stmt)
                    difference = self.value(stmt.operands[0]).add(variable_offset(cursor), -1)
                    if (
                        not difference.terms
                        and difference.constant % 32 == 0
                        and difference.constant < 32 * 64
                    ):
                        stores[difference.constant // 32].append(stmt)
                elif stmt.opcode not in {
                    "CONST",
                    "PHI",
                    "MLOAD",
                    "JUMP",
                    "JUMPI",
                    "ADD",
                    "SUB",
                    "MUL",
                    "SHL",
                    "AND",
                    "EQ",
                    "LT",
                    "GT",
                    "ISZERO",
                    "DIV",
                    "MOD",
                    "MOV",
                    "OR",
                    "NOT",
                }:
                    return None  # An unmodeled memory effect may change the encoding.
        for tail_words, candidates in sorted(stores.items()):
            if len(candidates) != 1:
                continue
            length_store = candidates[0]
            length = self.value(length_store.operands[1])
            difference = (
                update[1].add(variable_offset(cursor), -1).add(Offset(32 * (tail_words + 1)), -1)
            )
            if not self.aligned(difference, length):
                continue
            payload = self.byte_payload(
                cursor, tail_words, length_store.operands[1], loop, all_loops, plan
            )
            if payload is None:
                continue
            blob, evidence = payload
            evidence.update(update[2] | {length_store.id})
            if tail_words == 0:
                shape, allowed = blob, {length_store.id, blob["copy_statement"]}
            else:
                heads = []
                pointer_fields = []
                allowed = {length_store.id, blob["copy_statement"]}
                for index in range(tail_words):
                    fields = stores[index]
                    if len(fields) != 1:
                        break
                    writer = fields[0]
                    if self.value(writer.operands[1]) == Offset(32 * tail_words):
                        heads.append(blob)
                        pointer_fields.append(index)
                    else:
                        heads.append(
                            {
                                "kind": "canonical_bool_word"
                                if self.boolean_word(writer.operands[1])
                                else "word"
                            }
                        )
                    evidence.add(writer.id)
                    definition = self.definitions.get(writer.operands[1])
                    if definition:
                        evidence.add(definition.id)
                    allowed.add(writer.id)
                if len(heads) != tail_words or len(pointer_fields) != 1:
                    continue
                shape = {"kind": "tuple", "items": heads}
            # Head-offset writes and the final zero padding are the only other
            # stores admitted. An extra unknown store invalidates the candidate.
            head_stores = {
                s.id
                for s in all_stores
                if s.operands[0] != cursor
                and self.value(s.operands[0])
                in {
                    variable_offset(v)
                    for s2 in self.blocks[loop.header].instructions
                    if s2.opcode == "PHI"
                    for v in s2.definitions
                }
            }
            allowed.update(head_stores)
            for writer in all_stores:
                if writer.id in allowed:
                    continue
                expected = variable_offset(cursor).add(Offset(32 * (tail_words + 1))).add(length)
                if (
                    self.value(writer.operands[0]) == expected
                    and self.value(writer.operands[1]) == Offset()
                ):
                    allowed.add(writer.id)
                    evidence.add(writer.id)
            if any(s.id not in allowed for s in all_stores):
                continue
            required = [s.id for ss in stores.values() for s in ss]
            if not self.required_writes(required, loop, plan):
                continue
            return shape, evidence
        return None

    def array_shape(
        self, variable: str, length_variable: str, function: Function, plan: FlowPlan
    ) -> tuple[dict, set[str]] | None:
        data = self.value(variable).add(Offset(32))
        length = self.value(length_variable)
        all_loops = loops(plan.region)
        for loop in all_loops:
            counted = self.count_loop(loop, length, plan, stride=1)
            if counted is None:
                continue
            phis = [
                v
                for s in self.blocks[loop.header].instructions
                if s.opcode == "PHI"
                for v in s.definitions
            ]
            for pointer in phis:
                pointer_update = self.phi(pointer, loop, plan)
                if pointer_update is None or pointer_update[:2] != (
                    data,
                    variable_offset(pointer).add(Offset(32)),
                ):
                    continue
                for cursor in phis:
                    cursor_update = self.phi(cursor, loop, plan)
                    if cursor_update is None or cursor_update[0] != data.add(length.scale(32)):
                        continue
                    writers = [
                        s
                        for block in sorted(loop.nodes)
                        for s in self.blocks[block].instructions
                        if s.opcode == "MSTORE"
                        and len(s.operands) == 2
                        and self.value(s.operands[0]) == variable_offset(pointer)
                        and self.value(s.operands[1]) == variable_offset(cursor).add(data, -1)
                    ]
                    if len(writers) != 1 or not self.required_writes([writers[0].id], loop, plan):
                        continue
                    element = self.element(cursor, loop, all_loops, plan)
                    if element:
                        return {
                            "kind": "array",
                            "element": element[0],
                            "length_variable": length_variable,
                        }, element[1] | counted[1] | pointer_update[2] | cursor_update[2] | {
                            writers[0].id
                        }
        return None

    def summarize(
        self, function: Function, statement: str, memory: MemoryInfo | None
    ) -> ReturnLayout:
        result = ReturnLayout(function.id, statement, "unresolved", None, [], [statement], [])
        if memory is None:
            result.limitations.append(
                "Memory extension unavailable; upstream value hints may be pointers."
            )
            return result
        stmt = self.statements[statement]
        fragments = [w for w in memory.return_writes if w.statement == statement]
        word_sources: defaultdict[int, set[str]] = defaultdict(set)
        evidence = {statement}
        for write in fragments:
            writer = self.statements[write.writer]
            if (
                write.offset >= 0
                and write.offset % 32 == 0
                and write.low == 0
                and write.high == 32
                and writer.opcode == "MSTORE"
                and len(writer.operands) == 2
            ):
                word_sources[write.offset // 32].add(writer.operands[1])
                evidence.add(writer.id)
        words = {
            i: next(iter(values))
            for i, values in word_sources.items()
            if len(values) == 1
            and all(
                w.offset == 32 * i
                and w.low == 0
                and w.high == 32
                and self.statements[w.writer].opcode == "MSTORE"
                for w in fragments
                if w.offset + w.low < 32 * i + 32 and w.offset + w.high > 32 * i
            )
        }
        arrays = [a for a in memory.return_arrays if a.statement == statement]
        if arrays:
            count = max(a.index for a in arrays) + 1
            if count > 128:
                result.limitations.append("Return tuple exceeds the layout bound.")
                return result
            plan = structure_function(self.program, function)
            items = []
            for index in range(count):
                entries = {a.variable for a in arrays if a.index == index}
                if not entries and index in words:
                    items.append({"kind": "word"})
                    continue
                if len(entries) != 1 or index not in words:
                    break
                variable = next(iter(entries))
                header = self.value(words[index])
                if header.terms or header.constant < count * 32 or header.constant % 32:
                    break
                length_word = words.get(header.constant // 32)
                identities = {a for v, a in memory.aliases if v == variable}
                allocations = {
                    (a.element_bytes, a.length) for a in memory.arrays if a.identity in identities
                }
                if len(allocations) != 1 or length_word is None:
                    break
                width, length_variable = next(iter(allocations))
                if self.value(length_variable) != self.value(length_word):
                    break
                candidate: tuple[dict, set[str]] | None
                if width == "0x1":
                    candidate = (
                        {"kind": "byte_sequence", "length_variable": length_variable},
                        set(),
                    )
                elif width == "0x20" and plan.region:
                    candidate = self.array_shape(variable, length_variable, function, plan)
                else:
                    candidate = None
                if candidate is None:
                    break
                items.append(candidate[0])
                evidence.update(candidate[1])
            if len(items) == count:
                result.status = "candidate_dynamic_encoding"
                result.shape = {"kind": "tuple", "items": items}
                result.evidence = sorted(evidence)
            else:
                result.limitations.append("A complete dynamic encoder layout was not established.")
            result.limitations.append(
                "Encoder patterns are candidates from recovered IR, not original ABI types or a completeness proof; bytes/string and bool/integer declarations remain ambiguous."
            )
            return result
        size = (
            self.value(stmt.operands[1])
            if len(stmt.operands) == 2
            else Offset(0, ((Atom("variable", "unknown"), 1),))
        )
        native_size = (
            self.program.constant_hints.get(stmt.operands[1]) if len(stmt.operands) == 2 else None
        )
        count_size = int(native_size, 16) if size.terms and native_size else size.constant
        if (not size.terms or native_size) and count_size % 32 == 0 and count_size <= 32 * 128:
            count = count_size // 32
            complete = sorted(words) == list(range(count)) and all(
                w.low == 0
                and w.high == 32
                and w.offset >= 0
                and w.offset % 32 == 0
                and self.statements[w.writer].opcode == "MSTORE"
                for w in fragments
            )
            if complete:
                if not all(
                    self.saved_value_is_current(
                        function, w.writer, statement, self.statements[w.writer].operands[1]
                    )
                    for w in fragments
                ):
                    result.evidence = sorted(evidence)
                    result.limitations.append(
                        "A stored word may precede a later execution of its SSA definition, "
                        "or its lifetime is unresolved; raw RETURN retained."
                    )
                    return result
                established = not size.terms and all(
                    self.word_write_is_current(function, w.writer, statement, w.offset)
                    for w in fragments
                )
                result.status = "raw_words" if established else "candidate_raw_words"
                result.words = [words[i] for i in range(count)]
                result.shape = {"kind": "tuple", "items": [{"kind": "word"} for _ in range(count)]}
                result.evidence = sorted(evidence)
                result.limitations.append(
                    "These are complete raw return words in the recovered CFG; original Solidity types are unresolved."
                    if established
                    else "Word sources or byte count rely on unverified native hints; the original RETURN range is authoritative."
                )
                return result
        result.limitations.append(
            "Complete returned bytes/layout not established; raw RETURN retained."
        )
        return result


def analyze_returns(program: Program) -> list[ReturnLayout]:
    analysis = ReturnAnalysis(program)
    memory = program.semantics.memory_model if program.semantics else None
    return [
        analysis.summarize(f, s.id, memory)
        for f in program.functions
        for b in f.blocks
        for s in analysis.blocks[b].instructions
        if s.opcode == "RETURN"
    ]


def describe(shape: dict) -> str:
    kind = shape["kind"]
    if kind == "tuple":
        return "(" + ", ".join(describe(s) for s in shape["items"]) + ")"
    if kind == "array":
        return describe(shape["element"]) + "[]"
    return "word{0,1}" if kind == "canonical_bool_word" else kind


def decode_encoding(data: bytes, shape: dict, *, max_items: int = 4096) -> object:
    """Bounded wire-layout validator, independent of ABI names and signature hints."""
    remaining = max_items
    shape_budget = max_items

    def validate(node: dict, depth: int, seen: frozenset[int]):
        nonlocal shape_budget
        shape_budget -= 1
        if shape_budget < 0 or not isinstance(node, dict) or depth > 16 or id(node) in seen:
            raise ValueError("Invalid or excessively nested encoding shape")
        kind = node.get("kind")
        if not isinstance(kind, str) or kind not in {
            "tuple",
            "array",
            "word",
            "canonical_bool_word",
            "byte_sequence",
        }:
            raise ValueError("Unsupported encoding node")
        if kind == "tuple":
            children = node.get("items")
            if not isinstance(children, list) or len(children) > max_items:
                raise ValueError("Invalid encoding tuple")
        else:
            children = [node.get("element")] if kind == "array" else []
        for child in children:
            validate(child, depth + 1, seen | {id(node)})

    validate(shape, 0, frozenset())

    def word(offset: int) -> int:
        if not 0 <= offset <= len(data) - 32:
            raise ValueError("Encoding word is out of bounds")
        return int.from_bytes(data[offset : offset + 32])

    def dynamic(node: dict) -> bool:
        return node["kind"] in {"array", "byte_sequence"} or (
            node["kind"] == "tuple" and any(dynamic(s) for s in node["items"])
        )

    def head_width(node: dict) -> int:
        if dynamic(node):
            return 32
        if node["kind"] == "tuple":
            return sum(head_width(s) for s in node["items"])
        return 32

    def read(node: dict, offset: int, depth: int) -> object:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 16:
            raise ValueError("Encoding exceeds the decoding bound")
        kind = node["kind"]
        if kind in {"word", "canonical_bool_word"}:
            value = word(offset)
            if kind == "canonical_bool_word" and value not in {0, 1}:
                raise ValueError("Noncanonical boolean word")
            return value
        if kind == "byte_sequence":
            size = word(offset)
            start = offset + 32
            padded = ((size + 31) // 32) * 32
            if padded > len(data) - start:
                raise ValueError("Byte sequence is out of bounds")
            if any(data[start + size : start + padded]):
                raise ValueError("Nonzero byte-sequence padding")
            return data[start : start + size]
        if kind == "array":
            size = word(offset)
            width = head_width(node["element"])
            if width == 0 or size > remaining or size > (len(data) - offset - 32) // width:
                raise ValueError("Array exceeds the decoding bound")
            items, start = [node["element"]] * size, offset + 32
        elif kind == "tuple":
            items, start = node["items"], offset
        else:
            raise ValueError("Unsupported encoding node")
        values = []
        head_bytes = sum(head_width(item) for item in items)
        cursor = start
        for item in items:
            address = cursor
            cursor += head_width(item)
            if dynamic(item):
                relative = word(address)
                if relative < head_bytes or relative % 32:
                    raise ValueError("Invalid relative head offset")
                address = start + relative
            values.append(read(item, address, depth + 1))
        return values

    return read(shape, 0, 0)
