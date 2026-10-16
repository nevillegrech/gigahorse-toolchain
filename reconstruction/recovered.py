"""Readable inferred storage/argument view with a line-by-line evidence map."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .calldata import ACCESSORS, CalldataViews
from .constant_memory import proof_is_current
from .controlflow import FlowPlan, Region, plan_metadata, structure_function
from .model import Function, Instruction, Program
from .presentation import InternalInterfaces, LocalNames
from .render import ENVIRONMENT, INFIX, PURE, identifier, render_instruction
from .returns import describe as describe_return
from .revert_folding import HELPERS, RevertFold, find_revert_folds
from .reverts import analyze_reverts, guard_payloads
from .reverts import describe as describe_revert
from .semantics import StorageAccess, Term, atom, child, field_name
from .signatures import SignatureInfo
from .storage_reads import StorageReads

COMPARISONS = {"EQ": "==", "LT": "<", "GT": ">"}


def function_name(function: Function, signatures: SignatureInfo | None = None) -> str:
    selector = function.selectors[0] if len(function.selectors) == 1 else None
    candidates = signatures.candidates.get(selector, []) if signatures and selector else []
    if len(candidates) == 1 and selector:
        return identifier(candidates[0].split("(", 1)[0], "hint_") + "_" + selector[2:]
    return "selector_" + selector[2:] if selector else identifier(function.id, "fn_")


@dataclass(frozen=True)
class Expression:
    text: str
    evidence: frozenset[str] = frozenset()
    references: frozenset[str] = frozenset()


class Expressions:
    def __init__(
        self,
        program: Program,
        function: Function,
        interfaces: InternalInterfaces | None = None,
        *,
        hidden_statements: frozenset[str] = frozenset(),
    ):
        self.program = program
        self.interfaces = interfaces or InternalInterfaces(program)
        self.local_names = LocalNames(program, function, self.interfaces)
        self.name = self.local_names.name
        self.hidden_statements = hidden_statements
        self.storage_reads_analysis = StorageReads(program, function)
        self.constants = program.semantics.constants if program.semantics else program.constants
        self.definitions = {
            v: stmt for b in program.blocks for stmt in b.instructions for v in stmt.definitions
        }
        self.aliases = {}
        self.materialized: set[str] = set()
        self.calldata = CalldataViews(program, function)
        self.storage_aliases = (
            {r.slot: r.alias for r in program.behavior.storage_roles if r.alias}
            if program.behavior
            else {}
        )
        self.storage_reads = (
            {v for access in program.semantics.storage_accesses for v in access.loaded_variables}
            if program.semantics
            else set()
        )
        if program.semantics:
            for arg in program.semantics.arguments:
                if arg.function == function.id:
                    for variable in arg.variables:
                        self.aliases[variable] = f"arg{arg.index}"
        self._retain_referenced_temporaries(function)

    def elides(self, stmt: Instruction) -> bool:
        return (
            stmt.opcode in PURE
            and len(stmt.definitions) == 1
            and stmt.definitions[0] not in self.storage_reads
            and self.value(stmt.definitions[0]).text != self.name(stmt.definitions[0])
        )

    def _retain_referenced_temporaries(self, function: Function):
        """Keep definitions reached by a contextual size/depth fallback.

        A bounded expansion can stop at an otherwise inlineable child. Its
        assignment must then survive too, including any spills its RHS needs.
        Only uses in emitted operations and semantic annotations seed this
        closure; scanning elided definitions would retain needless spills.
        """
        statements = [
            s
            for b in self.program.blocks
            if b.id in function.blocks
            for s in b.instructions
            if s.id not in self.hidden_statements
        ]
        statement_ids = {s.id for s in statements}
        semantics = self.program.semantics
        while True:
            references: set[str] = set()

            def use(expression: Expression, references: set[str] = references):
                references.update(expression.references)

            for stmt in statements:
                if self.elides(stmt):
                    continue
                for variable in stmt.operands:
                    use(self.value(variable))
                if stmt.opcode == "JUMPI" and len(stmt.operands) == 2:
                    use(self.condition(stmt.operands[1]))
            if semantics:
                for guard in semantics.guards:
                    if guard.statement in statement_ids:
                        use(self.condition(guard.predicate, guard.success_when_nonzero))
                for access in semantics.storage_accesses:
                    if access.statement not in statement_ids:
                        continue
                    try:
                        use(storage_expression(access, self))
                    except (ValueError, IndexError):
                        pass  # The renderer also retains the raw operation.
                    for write in access.written_values:
                        if write.constructor == "VariableWrite":
                            use(self.value(atom(write, 0)))
                for call in semantics.external_calls:
                    if call.statement in statement_ids:
                        for arg in call.arguments:
                            if len(arg.variables) == 1:
                                use(self.value(arg.variables[0]))
            for layout in self.program.return_layouts:
                if layout.function == function.id and layout.status in {
                    "raw_words",
                    "candidate_raw_words",
                }:
                    for variable in layout.words:
                        use(self.value(variable))
            retained = {
                v for v in references if v in self.definitions and self.elides(self.definitions[v])
            }
            if not retained:
                return
            self.materialized.update(retained)

    def value(self, variable: str, seen: frozenset[str] = frozenset()) -> Expression:
        stmt = self.definitions.get(variable)
        evidence = frozenset({stmt.id}) if stmt else frozenset()
        fallback = Expression(self.name(variable), references=frozenset({variable}))
        if variable in self.materialized:
            return fallback
        binding = self.calldata.bindings.get(variable)
        if binding and variable not in seen and len(seen) < 24:
            access, sources = binding
            operands: list[Expression] = []

            def index_value(index_variable: str) -> str:
                result = self.value(index_variable, seen | {variable})
                operands.append(result)
                return result.text

            text = self.calldata.render(access, index_value)
            if len(text) <= 500:
                return Expression(
                    text,
                    sources.union(*(v.evidence for v in operands)),
                    frozenset().union(*(v.references for v in operands)),
                )
        if variable in self.aliases:
            return Expression(self.aliases[variable], evidence)
        if variable in self.constants:
            return Expression(self.constants[variable], evidence)
        if (
            variable in self.storage_reads
            or variable in seen
            or len(seen) >= 24
            or stmt is None
            or stmt.opcode not in PURE
            or len(stmt.definitions) != 1
        ):
            return fallback
        operands = [self.value(v, seen | {variable}) for v in stmt.operands]
        args = [item.text for item in operands]
        sources = evidence.union(*(item.evidence for item in operands))
        op = stmt.opcode
        if op in INFIX and len(args) == 2:
            text = f"u256({args[0]} {INFIX[op]} {args[1]})"
        elif op in COMPARISONS and len(args) == 2:
            text = f"word({args[0]} {COMPARISONS[op]} {args[1]})"
        elif op == "ISZERO" and len(args) == 1:
            text = f"word({args[0]} == 0)"
        elif op in {"SHL", "SHR"} and len(args) == 2:
            text = f"u256({args[1]} << {args[0]})" if op == "SHL" else f"({args[1]} >> {args[0]})"
        elif op in ENVIRONMENT and not args:
            text = ENVIRONMENT[op]
        elif op == "MOV" and len(args) == 1:
            text = args[0]
        elif op == "CONST":
            return fallback
        else:
            text = f"evm.{op.lower()}({', '.join(args)})"
        return (
            Expression(text, sources, frozenset().union(*(v.references for v in operands)))
            if len(text) <= 500
            else fallback
        )

    def condition(
        self, variable: str, nonzero: bool = True, seen: frozenset[str] = frozenset()
    ) -> Expression:
        stmt = self.definitions.get(variable)
        if variable not in self.materialized and variable not in seen and len(seen) < 24 and stmt:
            if stmt.opcode == "ISZERO" and len(stmt.operands) == 1:
                result = self.condition(stmt.operands[0], not nonzero, seen | {variable})
                return Expression(result.text, result.evidence | {stmt.id}, result.references)
            if stmt.opcode in COMPARISONS and len(stmt.operands) == 2:
                left, right = [self.value(v) for v in stmt.operands]
                operation = COMPARISONS[stmt.opcode]
                if not nonzero:
                    operation = {"==": "!=", "<": ">=", ">": "<="}[operation]
                return Expression(
                    f"{left.text} {operation} {right.text}",
                    left.evidence | right.evidence | {stmt.id},
                    left.references | right.references,
                )
        value = self.value(variable)
        return Expression(
            f"{value.text} {'!=' if nonzero else '=='} 0", value.evidence, value.references
        )


def storage_expression(access: StorageAccess, expressions: Expressions) -> Expression:
    semantics = expressions.program.semantics

    def index(term: Term) -> Expression:
        if term.constructor == "ConstantIndex":
            slot = hex(int(atom(term, 0), 16))
            fields = (
                [
                    f
                    for f in semantics.storage_fields
                    if f.location == access.location and f.slot == slot
                ]
                if semantics
                else []
            )
            roots = {f.name for f in fields if f.kind in {"Mapping", "Array", "StaticArray"}}
            name = (
                next(iter(roots))
                if len(roots) == 1
                else expressions.storage_aliases.get(
                    slot, field_name(access.location, slot, "Variable")
                )
                if access.location == "storage"
                else field_name(access.location, slot, "Variable")
            )
            return Expression(name)
        parent = index(child(term))
        if term.constructor in {"MappingAccessIndex", "ArrayAccessIndex", "StaticArrayAccessIndex"}:
            key = expressions.value(
                atom(term, 2 if term.constructor == "StaticArrayAccessIndex" else 1)
            )
            return Expression(
                f"{parent.text}[{key.text}]",
                parent.evidence | key.evidence,
                parent.references | key.references,
            )
        if term.constructor == "OffsetIndex":
            return Expression(
                f"word_offset({parent.text}, {int(atom(term, 1))})",
                parent.evidence,
                parent.references,
            )
        if term.constructor == "ArrayDataStartIndex":
            return Expression(
                f"array_data_start({parent.text})", parent.evidence, parent.references
            )
        raise ValueError(f"Unsupported storage index constructor: {term.constructor}")

    result = index(access.index)
    if access.construct.constructor == "TightlyPackedVariable":
        low, high = int(atom(access.construct, 1)), int(atom(access.construct, 2))
        if child(access.construct).constructor == "Constant":
            result = Expression(
                field_name(
                    access.location,
                    atom(child(access.construct), 0),
                    "TightlyPackedVariable",
                    low,
                    high,
                ),
                result.evidence,
            )
        else:
            result = Expression(
                f"packed_bytes({result.text}, {low}, {high})", result.evidence, result.references
            )
    if access.kind == "LENGTH":
        result = Expression(result.text + ".length", result.evidence, result.references)
    return result


def render_recovered(program: Program, *, structure_flow: bool = False) -> tuple[str, dict]:
    lines: list[str] = []
    mapping: list[dict] = []
    flow_metadata: list[dict] = []
    calldata_metadata: list[dict] = []
    naming_metadata: list[dict] = []
    interfaces = InternalInterfaces(program)
    revert_summaries = analyze_reverts(program)
    reverts_by_id = {r["statement"]: r for r in revert_summaries}
    guard_reverts = guard_payloads(program, revert_summaries)
    current_proof = proof_is_current(program)
    plans = (
        {f.id: structure_function(program, f) for f in program.functions} if structure_flow else {}
    )
    function_folds = {
        f.id: find_revert_folds(program, f, plans[f.id], reverts_by_id, current_proof=current_proof)
        for f in program.functions
        if f.id in plans
    }
    folded_reverts: list[dict] = []
    storage_read_proofs: dict[tuple[str, str], dict] = {}
    depth = 0
    all_statements = {s.id: s for b in program.blocks for s in b.instructions}

    def emit(text: str, evidence: frozenset[str] = frozenset(), inference: str | None = None):
        ids = sorted(evidence)
        offsets = sorted(
            {
                offset
                for sid in ids
                if sid in all_statements
                for offset in all_statements[sid].original_statements
            }
        )
        lines.append("    " * depth + text if text.startswith("        ") else text)
        if ids or inference:
            mapping.append(
                {
                    "line": len(lines),
                    "ir_statements": ids,
                    "bytecode_offsets": offsets,
                    "inference": inference,
                    **(
                        {"proof_references": ["constant_verification"]}
                        if inference in {"revert-payload", "guard-revert-payload", "folded-revert"}
                        else {"proof_references": ["storage_read_proofs"]}
                        if inference == "storage-read"
                        else {}
                    ),
                }
            )

    emit("// Inferred Solidity-like view. NOT compilable Solidity or an equivalence proof.")
    emit("// word(bool) is 0 or 1; u256 arithmetic wraps modulo 2**256; evm.* keeps EVM semantics.")
    emit(
        "// Local names describe IR roles; proven return-PC arguments are omitted from inferred private interfaces."
    )
    if program.return_layouts:
        emit(
            "// return(...) lists raw 32-byte words; candidate dynamic layouts retain the original RETURN byte range."
        )
    if any(function_folds.values()):
        emit(
            "// Terminal payload helpers re-encode established bytes; encoding IR is retained in the maps/detailed view."
        )
        emit(
            "// Payload folding omits gas/resource behavior and does not infer an error's origin/cause."
        )
    if program.calldata_fields:
        emit(
            "// Input field constraints describe listed checks of loaded values, not a complete recovered ABI."
        )
    if program.calldata_views:
        emit(
            "// cd_arg* are raw calldata views, not recovered ABI types; access adds no bounds checks."
        )
        emit(
            "// View offsets wrap as u256; word(k) loads offset+32*k with EVM zero padding; length=word(0)."
        )
        emit("// data_offset=offset+32; head_word(i) loads data_offset+32*i.")
        emit(
            "// element(i) follows data_offset+head_word(i); dynamic_field(k) follows offset+word(k)."
        )
    if program.behavior and program.behavior.storage_roles:
        emit(
            "// role_* names describe observed storage uses; caller checks alone do not establish admin privileges."
        )
    emit(
        "// Per-line bytecode evidence is in "
        + ("structured.map.json" if structure_flow else "recovered.map.json")
        + "; full IR and relations accompany this view."
    )
    for warning in program.warnings:
        emit("// WARNING: " + json.dumps(warning))
    semantics = program.semantics
    if semantics is None:
        emit("// Semantic export missing: use pseudocode.sol.txt for the recovered IR.")
        return "\n".join(lines) + "\n", {
            "schema_version": 1,
            "lines": mapping,
            "derived_constants": program.derived_constants,
            "constant_verification": program.constant_verification,
        }
    emit("contract Decompiled {")
    for field in semantics.storage_fields:
        candidates = field.type_candidates
        inferred_type = candidates[0] if len(candidates) == 1 else "word"
        evidence = frozenset(s for s in field.evidence if s in all_statements)
        role = (
            next(
                (r for r in program.behavior.storage_roles if r.slot == field.slot and r.alias),
                None,
            )
            if program.behavior and field.location == "storage"
            else None
        )
        name = role.alias if role else field.name
        emit(
            f"    {inferred_type} {name}; // inferred {field.location} slot {field.slot}, bytes {field.byte_low}..{field.byte_high}",
            evidence,
            "storage-declaration",
        )
        if role:
            emit(
                "    // Observed roles: " + json.dumps(role.roles),
                frozenset(role.evidence),
                "storage-role",
            )
        if len(candidates) != 1:
            emit("    // Type candidates: " + json.dumps(candidates))
        for limitation in field.type_limitations:
            emit("    // " + limitation, evidence, "storage-type-uncertainty")
    blocks = {b.id: b for b in program.blocks}
    access_by_stmt: dict[str, list[StorageAccess]] = {}
    for access in semantics.storage_accesses:
        access_by_stmt.setdefault(access.statement, []).append(access)
    guards = {g.statement: g for g in semantics.guards}
    external_by_stmt = {call.statement: call for call in semantics.external_calls}
    covered_blocks: set[str] = set()
    for function in program.functions:
        plan = plans.get(function.id)
        folds = function_folds.get(function.id, {})
        hidden = frozenset(s for fold in folds.values() for s in fold.ir_statements)
        expressions = Expressions(program, function, interfaces, hidden_statements=hidden)
        folded_reverts.extend(asdict(fold) for b, fold in folds.items() if b == fold.block)
        naming_metadata.append(expressions.local_names.metadata())
        if expressions.calldata.bindings:
            calldata_metadata.append(expressions.calldata.metadata(function.id))
        arguments = [arg for arg in semantics.arguments if arg.function == function.id]
        name = function_name(function, program.signature_info)
        formals = []
        by_index = {argument.index: argument for argument in arguments}
        indices = (
            list(range(max(by_index) + 1)) if by_index and max(by_index) < 64 else sorted(by_index)
        )
        for arg_index in indices:
            argument = by_index.get(arg_index)
            if argument is None:
                formals.append(f"word arg{arg_index} /* unresolved */")
            else:
                inferred_type = (
                    argument.type_candidates[0] if len(argument.type_candidates) == 1 else "word"
                )
                formals.append(f"{inferred_type} arg{arg_index}")
        if not function.selectors:
            formals = [
                f"word {expressions.name(function.formal_variables[i])}"
                for i in interfaces.visible(function)
            ]
        emit("")
        emit("    // Selectors: " + json.dumps(function.selectors))
        if program.signature_info:
            for selector in function.selectors:
                hints = program.signature_info.candidates.get(selector, [])
                if hints:
                    emit(
                        "    // Candidate signatures (external hints, collisions possible): "
                        + json.dumps(hints),
                        inference="signature-hints",
                    )
        emit(f"    function {name}({', '.join(formals)}) {{", inference="function-arguments")
        if function.id in interfaces.hidden:
            emit(
                "        // Return-PC input omitted: used only for internal return control.",
                frozenset(interfaces.proofs[function.id]["ir_statements"]),
                "internal-interface",
            )
        for argument in arguments:
            emit(
                f"        // arg{argument.index} inferred candidates: {json.dumps(argument.type_candidates)}; kind={argument.kind}",
                frozenset(argument.validation_statements),
                "argument-type",
            )
        for index, root in sorted(expressions.calldata.root_info.items()):
            emit(
                f"        raw_calldata_view cd_arg{index} = raw_calldata_view(arg{index});",
                frozenset(root["evidence"]),
                "calldata-root",
            )
        for returned in program.return_layouts:
            if (
                returned.function == function.id
                and returned.status == "candidate_dynamic_encoding"
                and returned.shape
            ):
                emit(
                    "        // Candidate return encoding: "
                    + describe_return(returned.shape)
                    + "; original ABI types remain uncertain.",
                    frozenset(returned.evidence),
                    "return-layout-interface",
                )

        if program.behavior:
            for site in program.behavior.delegate_sites:
                if site.function != function.id:
                    continue
                target = expressions.storage_aliases.get(
                    site.target_slot or "",
                    f"storage[{site.target_slot}]" if site.target_slot else "an unresolved source",
                )
                emit(
                    f"        // Observed DELEGATECALL at {site.statement}: target read from {target}; "
                    + (
                        "entire calldata forwarded."
                        if site.whole_calldata
                        else "whole-calldata forwarding unresolved."
                    ),
                    frozenset(site.evidence),
                    "delegate-behavior",
                )
                if site.return_data_forwarding == "established_in_recovered_cfg":
                    emit(
                        "        // Recovered paths forward return data: RETURN on call success, REVERT on call failure.",
                        frozenset(site.evidence),
                        "delegate-returndata",
                    )
                seen_gates = set()
                for gate in site.caller_gates:
                    key = (
                        gate["slot"],
                        gate["comparison"],
                        gate["caller_mask"],
                        gate["storage_mask"],
                    )
                    if key in seen_gates:
                        continue
                    seen_gates.add(key)
                    stored = expressions.storage_aliases.get(
                        gate["slot"], f"storage[{gate['slot']}]"
                    )
                    operator = "==" if gate["comparison"] == "equal" else "!="
                    caller = (
                        "msg.sender"
                        if int(gate["caller_mask"], 16) == (1 << 160) - 1
                        else f"(msg.sender & {gate['caller_mask']})"
                    )
                    storage_mask = int(gate["storage_mask"], 16)
                    stored = (
                        f"low160({stored})"
                        if storage_mask == (1 << 160) - 1
                        else stored
                        if storage_mask == (1 << 256) - 1
                        else f"({stored} & {gate['storage_mask']})"
                    )
                    emit(
                        f"        // Caller check on this path: {caller} {operator} {stored} (value loaded at the evidence statements).",
                        frozenset(gate["evidence"]),
                        "delegate-caller-gate",
                    )

        for descriptor in program.calldata_fields:
            if descriptor.function != function.id:
                continue
            encoding = (
                "dynamic byte sequence"
                if descriptor.encoding == "byte_sequence"
                else "raw head word"
            )
            constraint = (
                "checked candidates: " + " | ".join(descriptor.checked_type_candidates)
                if descriptor.checked_type_candidates
                else "original type unresolved"
            )
            roles = ", ".join(
                {
                    "call_target": "CALL target",
                    "delegatecall_target": "DELEGATECALL target",
                    "staticcall_target": "STATICCALL target",
                    "call_value": "transferred ETH value",
                }.get(role, role.replace("_", " "))
                for role in descriptor.roles
            )
            emit(
                f"        // Observed {descriptor.label()}: {encoding}; {constraint}"
                + (f"; uses: {roles}." if roles else "."),
                frozenset(descriptor.evidence),
                "calldata-field",
            )

        def emit_block(
            block_id: str,
            *,
            omit_transfer: bool = False,
            resolved_phis: frozenset[str] = frozenset(),
            expressions: Expressions = expressions,
            active_plan: FlowPlan | None = None,
            function_id: str = function.id,
            folds: dict[str, RevertFold] = folds,
        ):
            block = blocks[block_id]
            covered_blocks.add(block_id)
            if active_plan and block_id in folds:
                fold = folds[block_id]
                if block_id != fold.block:
                    return
                ignored = active_plan.transfers[fold.blocks[-1]].ignored_terminal_targets
                if ignored:
                    emit(
                        "        // Ignored non-executable IR edges after EVM halt: "
                        + json.dumps(list(ignored)),
                        frozenset({fold.statement}),
                        "ignored-terminal-edges",
                    )
                emit("        " + fold.helper, frozenset(fold.ir_statements), "folded-revert")
                return
            if not omit_transfer:
                emit(f"    {identifier(block.id, 'block_')}:")
            for stmt in block.instructions:
                if stmt.id in resolved_phis:
                    continue
                if (
                    omit_transfer
                    and stmt == block.instructions[-1]
                    and stmt.opcode in {"JUMP", "JUMPI"}
                ):
                    continue
                evidence = frozenset({stmt.id})
                if active_plan and stmt == block.instructions[-1]:
                    ignored = active_plan.transfers[block_id].ignored_terminal_targets
                    if ignored:
                        emit(
                            "        // Non-executable IR edges after EVM halt retained in the map: "
                            + json.dumps(ignored),
                            evidence,
                            "terminal-edges",
                        )
                # Pure operations are expanded at their uses; state/memory reads stay SSA values.
                if expressions.elides(stmt):
                    continue
                accesses = access_by_stmt.get(stmt.id, [])
                handled = False
                if len(accesses) == 1:
                    access = accesses[0]
                    try:
                        path = storage_expression(access, expressions)
                    except (ValueError, IndexError):
                        path = None
                        emit(
                            "        // Unresolved inferred storage path; raw operation follows.",
                            evidence,
                            "unresolved-storage-path",
                        )
                    read_proof = expressions.storage_reads_analysis.proof(access, stmt)
                    if path and read_proof:
                        storage_read_proofs[(function_id, stmt.id)] = asdict(read_proof)
                        emit(
                            f"        {expressions.name(access.loaded_variables[0])} = {path.text};",
                            evidence | path.evidence | frozenset(read_proof.evidence),
                            "storage-read",
                        )
                        handled = True
                    elif path and len(access.written_values) == 1:
                        value_term = access.written_values[0]
                        write_value: Expression | None
                        if value_term.constructor == "VariableWrite":
                            write_value = expressions.value(atom(value_term, 0))
                        elif value_term.constructor == "ConstantWrite":
                            write_value = Expression(atom(value_term, 0))
                        else:
                            write_value = None
                        if (
                            write_value
                            and access.construct.constructor == "Variable"
                            and stmt.opcode in {"SSTORE", "TSTORE"}
                        ):
                            emit(
                                f"        {path.text} = {write_value.text};",
                                evidence | path.evidence | write_value.evidence,
                                "storage-write",
                            )
                            handled = True
                if handled:
                    continue
                for access in accesses:
                    if access.construct.constructor == "TightlyPackedVariable":
                        try:
                            packed_path = storage_expression(access, expressions)
                            for write in access.written_values:
                                written = (
                                    expressions.value(atom(write, 0))
                                    if write.constructor == "VariableWrite"
                                    else Expression(atom(write, 0))
                                )
                                emit(
                                    f"        // Inferred packed write: {packed_path.text} = {written.text}; word operation follows.",
                                    evidence | packed_path.evidence | written.evidence,
                                    "packed-storage-write",
                                )
                        except (ValueError, IndexError):
                            emit(
                                "        // Unresolved packed field inference; word operation follows.",
                                evidence,
                                "unresolved-packed-storage",
                            )
                guard = guards.get(stmt.id)
                if guard:
                    predicate = expressions.condition(guard.predicate, guard.success_when_nonzero)
                    if stmt.id in guard_reverts:
                        payload = guard_reverts[stmt.id]
                        emit(
                            "        // Failure payload: " + payload["description"],
                            frozenset({stmt.id, *payload["revert_statements"]}),
                            "guard-revert-payload",
                        )
                    emit(
                        f"        require({predicate.text}); // failure reverts via {identifier(guard.failure, 'block_')}",
                        evidence | predicate.evidence,
                        "revert-guard",
                    )
                    emit(f"        goto {identifier(guard.success, 'block_')};", evidence)
                    continue
                args = [expressions.value(v) for v in stmt.operands]
                evidence = evidence.union(*(value.evidence for value in args))
                if stmt.opcode == "REVERT":
                    info = reverts_by_id[stmt.id]
                    if info["status"] in {"static", "partial"} and info["encoding"] != "empty":
                        emit(
                            "        // Revert payload: " + describe_revert(info),
                            frozenset({stmt.id}),
                            "revert-payload",
                        )
                if stmt.id in external_by_stmt:
                    external = external_by_stmt[stmt.id]
                    call_evidence = evidence | frozenset(external.evidence)
                    if external.selector_resolved:
                        words = []
                        for argument in external.arguments:
                            if len(argument.variables) == 1:
                                value = expressions.value(argument.variables[0])
                                words.append(value.text)
                                call_evidence |= value.evidence
                            else:
                                words.append(f"unknown_word({argument.index})")
                        if external.input_word_count is None:
                            words.append("... /* unknown ABI tail */")
                        emit(
                            f"        // Inferred calldata words: selector_{external.selector_candidates[0][2:]}({', '.join(words)}).",
                            call_evidence,
                            "external-calldata",
                        )
                        if external.signature_hints:
                            emit(
                                "        // Signature hints (collisions possible): "
                                + json.dumps(external.signature_hints),
                                call_evidence,
                                "external-signature-hints",
                            )
                    for warning in external.warnings:
                        if "Signature hints" not in warning:
                            emit("        // " + warning, call_evidence, "external-uncertainty")
                    has_value = external.value is not None
                    start = 3 if has_value else 2
                    operands = [f"gas: {args[0].text}", f"to: {args[1].text}"]
                    if has_value:
                        operands.append(f"value: {args[2].text}")
                    operands.extend(
                        [
                            f"input: memory({args[start].text}, {args[start + 1].text})",
                            f"output: memory({args[start + 2].text}, {args[start + 3].text})",
                        ]
                    )
                    lhs = expressions.name(stmt.definitions[0])
                    emit(
                        f"        {lhs} = evm.{stmt.opcode.lower()}({', '.join(operands)});",
                        call_evidence,
                        "external-call",
                    )
                    if external.return_variables:
                        return_evidence = frozenset(
                            expressions.definitions[v].id
                            for values in external.return_variables.values()
                            for v in values
                            if v in expressions.definitions
                        )
                        emit(
                            "        // Recovered returndata consumers (word index; -1 is a byte-array view): "
                            + json.dumps(external.return_variables, sort_keys=True),
                            call_evidence | return_evidence,
                            "external-return-data",
                        )
                    continue
                if stmt.opcode == "CALLPRIVATE":
                    callee = interfaces.callee(block_id, stmt)
                    if callee is not None:
                        inputs = [args[i + 1].text for i in interfaces.visible(callee)]
                        call = (
                            f"{function_name(callee, program.signature_info)}({', '.join(inputs)})"
                        )
                        lhs = ", ".join(expressions.name(v) for v in stmt.definitions)
                        if active_plan and active_plan.transfers[block_id].kind == "end":
                            emit("        tailcall " + call + ";", evidence, "internal-tailcall")
                        else:
                            emit(
                                "        " + (lhs + " = " if lhs else "") + call + ";",
                                evidence,
                                "internal-call",
                            )
                        continue
                if stmt.opcode == "RETURNPRIVATE":
                    emit(
                        f"        return_internal({', '.join(arg.text for arg in args[1:])});",
                        evidence,
                        "internal-return",
                    )
                    continue
                if stmt.opcode == "RETURN":
                    layout = next(
                        (
                            r
                            for r in program.return_layouts
                            if r.function == function_id and r.statement == stmt.id
                        ),
                        None,
                    )
                    if layout and layout.status == "raw_words":
                        values = [expressions.value(v) for v in layout.words]
                        emit(
                            f"        return ({', '.join(v.text for v in values)});",
                            evidence.union(layout.evidence, *(v.evidence for v in values)),
                            "raw-return-words",
                        )
                        continue
                    if layout and layout.status == "candidate_raw_words":
                        values = [expressions.value(v) for v in layout.words]
                        emit(
                            "        // Candidate raw return words (unverified): ("
                            + ", ".join(v.text for v in values)
                            + "). Raw RETURN retained.",
                            evidence.union(layout.evidence, *(v.evidence for v in values)),
                            "candidate-raw-return-words",
                        )
                    elif layout and layout.shape:
                        emit(
                            "        // Candidate return encoding: "
                            + describe_return(layout.shape)
                            + "; original ABI types remain uncertain.",
                            frozenset(layout.evidence),
                            "return-layout-candidate",
                        )
                    if layout and layout.status == "unresolved":
                        for limitation in layout.limitations:
                            emit(
                                "        // " + limitation,
                                frozenset(layout.evidence),
                                "unresolved-return-layout",
                            )
                    if not (layout and layout.shape) and stmt.id in semantics.memory_values:
                        emit(
                            "        // Return layout unresolved; upstream value hints may be memory pointers. Raw bytes follow.",
                            evidence,
                            "unresolved-return-layout",
                        )
                if stmt.opcode == "JUMPI" and len(stmt.operands) == 2:
                    predicate = expressions.condition(stmt.operands[1])
                    raw = render_instruction(
                        stmt, program, variable_names=expressions.local_names.names
                    )
                    target = (
                        raw.split(" goto ", 1)[1] if " goto " in raw else "unresolved_target();"
                    )
                    emit(
                        f"        if ({predicate.text}) goto {target}",
                        evidence | predicate.evidence,
                    )
                    continue
                if stmt.opcode == "JUMP":
                    emit(
                        "        "
                        + render_instruction(
                            stmt, program, variable_names=expressions.local_names.names
                        ),
                        evidence,
                    )
                    continue
                helper = "phi_unordered" if stmt.opcode == "PHI" else f"evm.{stmt.opcode.lower()}"
                rhs = f"{helper}({', '.join(v.text for v in args)})"
                lhs = ", ".join(expressions.name(v) for v in stmt.definitions)
                emit("        " + (lhs + " = " if lhs else "") + rhs + ";", evidence)
            tail = block.instructions[-1].opcode if block.instructions else ""
            if (
                not omit_transfer
                and block.fallthrough
                and tail
                not in {
                    "JUMP",
                    "RETURN",
                    "REVERT",
                    "STOP",
                    "SELFDESTRUCT",
                    "INVALID",
                }
            ):
                if len(block.fallthrough) == 1:
                    if not block.instructions or block.instructions[-1].id not in guards:
                        emit(f"        goto {identifier(block.fallthrough[0], 'block_')};")
            if not omit_transfer:
                emit("        // CFG successors: " + json.dumps(block.successors))

        if plan:
            flow_metadata.append(plan_metadata(plan))
        if plan and plan.region:
            for warning in plan.warnings:
                emit("        // UNCERTAIN: " + json.dumps(warning))

            def emit_region(
                region: Region, *, plan: FlowPlan = plan, expressions: Expressions = expressions
            ):
                nonlocal depth
                if region.kind == "sequence":
                    for nested in region.children:
                        emit_region(nested)
                elif region.kind == "block":
                    assert region.block is not None
                    emit_block(
                        region.block,
                        omit_transfer=True,
                        resolved_phis=frozenset(plan.resolved_phis),
                        active_plan=plan,
                    )
                elif region.kind == "edge":
                    assert region.source is not None and region.target is not None
                    copies = plan.copies.get((region.source, region.target), [])
                    if copies:
                        values = [expressions.value(copy.source) for copy in copies]
                        evidence = frozenset(copy.phi for copy in copies).union(
                            *(value.evidence for value in values)
                        )
                        emit(
                            f"        ({', '.join(expressions.name(copy.destination) for copy in copies)}) = ({', '.join(value.text for value in values)}); // simultaneous PHI edge assignment",
                            evidence,
                            "phi-edge-assignment",
                        )
                elif region.kind == "if":
                    assert region.block is not None
                    transfer = plan.transfers[region.block]
                    assert transfer.predicate is not None and transfer.statement is not None
                    condition = expressions.condition(transfer.predicate, not region.inverted)
                    if transfer.statement in guards:
                        guard = guards[transfer.statement]
                        check = expressions.condition(guard.predicate, guard.success_when_nonzero)
                        emit(
                            f"        // Guard: require({check.text}); failure body preserved below."
                        )
                        if transfer.statement in guard_reverts:
                            payload = guard_reverts[transfer.statement]
                            emit(
                                "        // Failure payload: " + payload["description"],
                                frozenset({transfer.statement, *payload["revert_statements"]}),
                                "guard-revert-payload",
                            )
                    emit(
                        f"        if ({condition.text}) {{",
                        condition.evidence | {transfer.statement},
                        "structured-if",
                    )
                    depth += 1
                    emit_region(region.children[0])
                    depth -= 1
                    if region.children[1].children or region.children[1].kind != "sequence":
                        emit("        } else {")
                        depth += 1
                        emit_region(region.children[1])
                        depth -= 1
                    emit("        }")
                elif region.kind == "loop":
                    emit("        while (true) {", inference="structured-loop")
                    depth += 1
                    emit_region(region.children[0])
                    depth -= 1
                    emit("        }")
                elif region.kind in {"break", "continue"}:
                    action_transfer = plan.transfers.get(region.source or "")
                    evidence = (
                        frozenset({action_transfer.statement})
                        if action_transfer and action_transfer.statement
                        else frozenset()
                    )
                    emit(f"        {region.kind};", evidence, "structured-" + region.kind)
                else:
                    raise ValueError(f"Unknown control-flow region: {region.kind}")

            if plan.entry_copies:
                initial = [expressions.value(copy.source) for copy in plan.entry_copies]
                lhs = ", ".join(expressions.name(copy.destination) for copy in plan.entry_copies)
                rhs = ", ".join(value.text for value in initial)
                evidence = frozenset(copy.phi for copy in plan.entry_copies)
                evidence |= frozenset(s for value in initial for s in value.evidence)
                emit(
                    f"        ({lhs}) = ({rhs}); // simultaneous function-entry PHI assignment",
                    evidence,
                    "phi-entry",
                )
            emit_region(plan.region)
            for block_id in function.blocks:
                if block_id not in plan.reachable_blocks:
                    emit(
                        "        // Unreachable according to the recovered CFG; raw block follows."
                    )
                    emit_block(block_id)
        else:
            if plan:
                emit("        // UNCERTAIN: explicit CFG retained: " + json.dumps(plan.warnings))
            for block_id in function.entries + [
                b for b in function.blocks if b not in function.entries
            ]:
                emit_block(block_id)
        emit("    }")
    for block_id in sorted(blocks.keys() - covered_blocks):
        emit("    // Unassigned block: retained as raw IR.")
        emit(f"    {identifier(block_id, 'block_')}:")
        for stmt in blocks[block_id].instructions:
            emit("        " + render_instruction(stmt, program), frozenset({stmt.id}))
    emit("}")
    represented = {sid for item in mapping for sid in item["ir_statements"]}
    return "\n".join(lines) + "\n", {
        "schema_version": 1,
        "internal_interfaces": interfaces.metadata(),
        "revert_summaries": revert_summaries,
        "storage_read_proofs": list(storage_read_proofs.values()),
        "storage_fields": [asdict(f) for f in semantics.storage_fields],
        "guard_revert_payloads": guard_reverts,
        "revert_folds": folded_reverts,
        "revert_helpers": HELPERS if folded_reverts else {},
        "variable_names": naming_metadata,
        "derived_constants": program.derived_constants,
        "constant_verification": program.constant_verification,
        "external_calls": [asdict(call) for call in semantics.external_calls],
        "signature_info": asdict(program.signature_info) if program.signature_info else None,
        "calldata_views": calldata_metadata,
        "calldata_accessors": ACCESSORS if calldata_metadata else {},
        "behavior": asdict(program.behavior) if program.behavior else None,
        "return_layouts": [asdict(r) for r in program.return_layouts],
        "calldata_fields": [asdict(f) for f in program.calldata_fields],
        "lines": mapping,
        "not_referenced_in_view": sorted(all_statements.keys() - represented),
        "complete_ir_file": "pseudocode.sol.txt",
        "control_flow": flow_metadata,
    }
