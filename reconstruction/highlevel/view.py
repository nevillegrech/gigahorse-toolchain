"""Readable decompiled view: tree lifting, cleanup passes and an evidence map."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from ..model import Function, Program
from .idioms import recognize_string_getters
from .ir import Assign, Emit, Expr, Require, Return, Stmt, Var, is_local
from .lift import FunctionLifter, ProgramContext
from .memory_forwarding import forward_memory
from .memory_liveness import AddressModel, FreePointerVersions, Summaries, compute_summaries
from .naming import Names, load_names, split_signature
from .passes import (
    FunctionState,
    absorb_memory_plumbing,
    constant_branches,
    copy_propagation,
    drop_trivial_requires,
    eth_transfers,
    guards_to_requires,
    is_free_pointer_read,
    iter_expr,
    iter_statements,
    leading_callvalue_check,
    loop_conditions,
    read_expressions,
    remove_unused_reads,
    repeated_checks,
    short_circuit,
    single_use_inline,
    statement_ids,
    trailing_stop,
    unused_call_results,
)
from .printer import Printed, expression, print_statements
from .summaries import summarize, summary_lines
from .types import TypedValue, expression_type, map_body, storage_root, type_variables

LEGEND = [
    "Decompiled view: Gigahorse IR lifted to Solidity-like code by local readability passes.",
    "Not compilable Solidity and not an equivalence proof. Per-line IR/bytecode evidence: decompiled.map.json.",
    "Conventions: arithmetic wraps mod 2**256 unless a check is shown; `/` and `%` by zero give 0 (EVM);",
    "  MEM[p] / msg.data[p] are 32-byte words at byte offset p; `if (x)` tests x != 0; msg.sig is the 4-byte selector;",
    "  require(c, returndata) reverts with the callee's revert data; stor_<slot>[_<bytes>] are inferred storage fields.",
    "Names marked [dict] come from hash-checked local signature dictionaries: hints, not proof of the original source.",
    "UNCERTAIN marks constructs that were not fully recovered; raw EVM operations are kept in those places.",
    "Hidden memory writes: proven unread, or ABI temporaries of a represented call/event/return that are not",
    "  re-read through the same pointer (solc memory discipline; such lines carry rule assumes-solc-memory-discipline).",
]


@dataclass
class FunctionView:
    function: Function
    name: str
    body: list[Stmt]
    arguments: list[TypedValue]
    state: FunctionState
    signature: str | None
    returns: list[str] | None
    nonpayable: Stmt | None
    structured: bool
    argument_evidence: set[str] = field(default_factory=set)


def collect_keys(context: ProgramContext) -> tuple[set[str], set[str], set[str]]:
    program = context.program
    selectors = {s for f in program.functions for s in f.selectors}
    if program.semantics:
        selectors |= {s for c in program.semantics.external_calls for s in c.selector_candidates}
    topics = set()
    for stmt in context.statements.values():
        if stmt.opcode.startswith("LOG") and len(stmt.operands) >= 3:
            value = context.constants.get(stmt.operands[2])
            if value is not None:
                topics.add(f"0x{value:064x}")
    errors = set()
    for info in context.reverts.values():
        selector = info.get("selector")
        if selector and info.get("encoding") not in {"Error(string)", "Panic(uint256)"}:
            errors.add(selector)
    return selectors, topics, errors


def _public_name(selector: str, names: Names) -> tuple[str, str | None]:
    if selector == "0x00000000":
        return "fallback", None
    signature = names.function(selector)
    if signature:
        return split_signature(signature)[0], signature
    return selector, None


def _returns(body: list[Stmt], field_types: dict[str, str] | None = None) -> list[str] | None:
    returns = [
        s for s in iter_statements(body) if isinstance(s, Return) and "tail-call" not in s.rules
    ]
    if not returns or any(s.raw is not None for s in returns):
        return None
    arities = {len(s.values) for s in returns}
    if len(arities) != 1 or arities == {0}:
        return None
    columns = []
    for index in range(arities.pop()):
        types = {
            (field_types or {}).get(getattr(s.values[index], "name", ""), None)
            or expression_type(s.values[index])
            for s in returns
        }
        columns.append(types.pop() if len(types) == 1 else "uint256")
    return columns


@dataclass
class DecompiledProgram:
    context: ProgramContext
    views: list[FunctionView]
    storage_names: dict
    text: str
    mapping: dict

    def storage_root(self, name: str) -> tuple[str, str, int, int] | None:
        """(location, slot, low byte, high byte) for a printed storage root name."""
        original = {info["name"]: root for root, info in self.storage_names.items()}
        return self.context.storage_roots.get(original.get(name, name))


def render_decompiled(
    program: Program, relations: Path | None = None, names: Names | None = None
) -> tuple[str, dict]:
    result = build_decompiled(program, relations, names)
    return result.text, result.mapping


def build_decompiled(
    program: Program, relations: Path | None = None, names: Names | None = None
) -> DecompiledProgram:
    if relations is None:
        relations = program.source_directory
    context = ProgramContext.build(program, relations)
    if names is None:
        names = load_names(*collect_keys(context))
    for topic, candidates in names.events.matches.items():
        if len(candidates) == 1:
            context.event_names[topic] = split_signature(candidates[0])[0]
    for selector, candidates in names.functions.matches.items():
        if len(candidates) == 1:
            context.external_signatures[selector] = candidates[0]
    signatures: dict[str, str | None] = {}
    for function in program.functions:
        if len(function.selectors) == 1:
            name, signature = _public_name(function.selectors[0], names)
            context.function_names[function.id] = name
            signatures[function.id] = signature
        elif "0x0" in function.entries:
            context.function_names[function.id] = "__function_selector__"
        else:
            context.function_names[function.id] = f"fn_{function.id}"
    # Overloaded names (e.g. two safeTransferFrom) get their selector appended so
    # every printed reference denotes exactly one function.
    counts: dict[str, int] = {}
    for name in context.function_names.values():
        counts[name] = counts.get(name, 0) + 1
    for function in program.functions:
        name = context.function_names[function.id]
        if counts[name] > 1 and len(function.selectors) == 1:
            context.function_names[function.id] = f"{name}_{function.selectors[0][2:]}"

    prepared = [prepare_function(context, function) for function in program.functions]
    summaries = memory_summaries(context, prepared)
    views = [
        finish_function(context, entry, signatures.get(entry.function.id), summaries)
        for entry in prepared
    ]
    provisional = DecompiledProgram(context, views, {}, "", {})
    recognitions = recognize_string_getters(provisional)
    storage = name_storage_from_getters(views)
    declarations, field_types = storage_declarations(views, context, storage)
    for view in views:
        view.returns = _returns(view.body, field_types)
    out = Printed(offsets={s.id: s.original_statements for s in context.statements.values()})
    for line in LEGEND:
        out.emit("// " + line, 0)
    out.emit("", 0)
    out.emit("contract Decompiled {", 0)
    if declarations:
        out.emit(
            "// Storage fields inferred from accesses; `_name` fields are named after their getter.",
            1,
        )
        for text, evidence in declarations:
            out.emit(text, 1, evidence=evidence, kind="storage-declaration")
        out.emit("", 0)
    events = used_events(views, names)
    for text in events:
        out.emit(text, 1, kind="event-declaration")
    ordered = sorted(
        views,
        key=lambda v: (
            v.name == "__function_selector__",
            not v.function.selectors,
            v.function.selectors[0] if v.function.selectors else v.function.id,
        ),
    )
    behaviour = summarize(views)
    for view in ordered:
        print_function(out, view, behaviour.get(view.name))
    out.emit("}", 0)
    referenced = {sid for entry in out.entries for sid in entry["ir_statements"]}
    elided: list[dict] = [
        {
            "function": view.function.id,
            "ir_statements": sorted(elision.statements),
            "reason": elision.reason,
        }
        for view in views
        for elision in view.state.elided
    ]
    accounted = referenced | {sid for e in elided for sid in e["ir_statements"]}
    accounted |= {sid for view in views for sid in view.argument_evidence}
    structural = classify_unprinted(context, accounted)
    accounted |= {sid for ids in structural.values() for sid in ids}
    mapping = {
        "schema_version": 1,
        "view": "decompiled",
        "legend": LEGEND,
        "lines": out.entries,
        "elided": elided,
        "argument_types": [
            {
                "function": v.function.id,
                **{k: x for k, x in asdict(a).items() if k != "definition"},
                "definition": expression(a.definition) if a.definition is not None else None,
                "evidence": sorted(a.evidence),
            }
            for v in views
            for a in v.arguments
        ],
        "structural_ir_statements": {k: sorted(v) for k, v in structural.items()},
        "storage_names": storage,
        "recognized_idioms": [asdict(r) for r in recognitions],
        "names": names.metadata(),
        "unaccounted_ir_statements": sorted(set(context.statements) - accounted),
    }
    return DecompiledProgram(context, views, storage, out.text(), mapping)


def classify_unprinted(context: ProgramContext, accounted: set[str]) -> dict[str, set[str]]:
    """Explain IR statements that no printed line needs.

    Jumps are represented by the structured control flow. Pure definitions whose
    results reach only jumps or other unprinted pure definitions are control-only
    or dead computations (solc leaves e.g. unused calldata offsets behind).
    """
    from ..render import PURE

    result: dict[str, set[str]] = {"control_transfer": set(), "dead_or_control_only_pure": set()}
    for sid, stmt in context.statements.items():
        if sid not in accounted and stmt.opcode in {"JUMP", "JUMPI"}:
            result["control_transfer"].add(sid)
    changed = True
    while changed:
        changed = False
        for sid, stmt in context.statements.items():
            if sid in accounted or sid in result["dead_or_control_only_pure"]:
                continue
            if stmt.opcode not in PURE:
                continue
            users = [u for d in stmt.definitions for u in context.uses.get(d, [])]
            if all(
                (
                    u.opcode in {"JUMP", "JUMPI"}
                    and (u.opcode == "JUMP" or u.operands[0] in stmt.definitions)
                )
                or u.id in result["dead_or_control_only_pure"]
                for u in users
            ):
                result["dead_or_control_only_pure"].add(sid)
                changed = True
    return result


@dataclass
class _Prepared:
    function: Function
    lifter: FunctionLifter
    item: object
    state: FunctionState


def prepare_function(context: ProgramContext, function: Function) -> _Prepared:
    lifter = FunctionLifter(context, function)
    item = lifter.lift()
    state = FunctionState(item.body)
    constant_branches(state)
    guards_to_requires(state)
    drop_trivial_requires(state)
    remove_unused_reads(state)
    single_use_inline(state)
    return _Prepared(function, lifter, item, state)


def memory_summaries(context: ProgramContext, prepared: list[_Prepared]) -> Summaries:
    functions = {}
    for entry in prepared:
        free_pointer_vars = {
            stmt.targets[0].name
            for stmt in iter_statements(entry.state.body)
            if isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and is_local(stmt.targets[0])
            and is_free_pointer_read(stmt.value)
        }
        callees = frozenset(context.function_names.values())
        functions[context.function_names[entry.function.id]] = (
            entry.state.body,
            AddressModel(free_pointer_vars, FreePointerVersions(entry.state.body, callees)),
        )
    return compute_summaries(functions)


def finish_function(
    context: ProgramContext, entry: _Prepared, signature: str | None, summaries: Summaries
) -> FunctionView:
    lifter, item, state, function = entry.lifter, entry.item, entry.state, entry.function
    callees = frozenset(context.function_names.values())
    lifter.abstracted |= forward_memory(state, callees)
    copy_propagation(state)
    remove_unused_reads(state)
    absorb_memory_plumbing(
        state,
        lifter.consumer_writers,
        lifter.abstracted,
        frozenset(context.function_names.values()),
        summaries,
        context.function_names[function.id],
    )
    single_use_inline(state)
    short_circuit(state)
    single_use_inline(state)
    repeated_checks(state)
    eth_transfers(state)
    unused_call_results(state)
    leading_callvalue_check(state)
    trailing_stop(state)
    typed = type_variables(state, [arg.name for arg in item.arguments])
    for name, value in typed.items():
        value.kind = lifter.argument_kinds.get(name, "word")
        value.definition = lifter.argument_definitions.get(name)
        if value.kind in {"array", "struct"} and value.type == "uint256":
            value.type = "dynamic"
            value.reason = (
                "native ABI model: calldata position of a dynamic argument (offset + 4); "
                "element types unresolved"
            )
    remove_unused_reads(state)
    loop_conditions(state)
    return FunctionView(
        function,
        context.function_names[function.id],
        state.body,
        [typed[arg.name] for arg in item.arguments],
        state,
        signature,
        _returns(state.body),
        state.nonpayable,
        item.structured,
        set(lifter.argument_evidence),
    )


def print_function(out: Printed, view: FunctionView, summary=None) -> None:
    function = view.function
    out.emit("", 0)
    selector = function.selectors[0] if len(function.selectors) == 1 else None
    if view.name == "__function_selector__":
        out.emit("// Selector dispatch (compiler-generated; shown for completeness).", 1)
    elif selector:
        hint = f" {view.signature} [dict]" if view.signature else ""
        out.emit(f"// {selector}{hint}", 1, kind="function-hint")
        if summary is not None:
            for text, ids in summary_lines(summary, True):
                out.emit(
                    "//   " + text,
                    1,
                    evidence=ids,
                    kind="behaviour-summary",
                    uncertain=text if text.startswith("UNCERTAIN") else None,
                )
    params = ", ".join(f"{a.type} {a.name}" for a in view.arguments)
    if function.selectors:
        visibility = "public " + ("nonpayable" if view.nonpayable is not None else "payable")
    else:
        visibility = "private"
    returns = f" returns ({', '.join(view.returns)})" if view.returns else ""
    evidence = frozenset(view.argument_evidence)
    for argument in view.arguments:
        evidence |= argument.evidence
    if view.nonpayable is not None:
        evidence |= statement_ids(view.nonpayable)
    out.emit(
        f"function {view.name}({params}) {visibility}{returns} {{",
        1,
        evidence=evidence,
        kind="function",
        rules=frozenset({"signature"}),
    )
    print_statements(out, view.body, 2)
    out.emit("}", 1)


def name_storage_from_getters(views: list[FunctionView]) -> dict:
    """Rename a storage root after a public getter that returns exactly it.

    A getter is a public function with a dictionary-named signature whose whole
    body is `return root[arg0][arg1]...` with keys equal to its arguments in order.
    """
    candidates: dict[str, list[tuple[str, str]]] = {}
    for view in views:
        if not view.signature or not view.function.selectors:
            continue
        # Leading argument-decoding checks (empty-payload requires) are allowed.
        if not view.body or not isinstance(view.body[-1], Return):
            continue
        if any(not isinstance(s, Require) or s.payload is not None for s in view.body[:-1]):
            continue
        returned = view.body[-1]
        if len(returned.values) != 1:
            continue
        root = storage_root(returned.values[0])
        if root is None:
            continue
        name, keys = root
        if [k.name if isinstance(k, Var) else None for k in keys] != [
            a.name for a in view.arguments
        ]:
            continue
        candidates.setdefault(name, []).append((view.name, view.function.id))
    renames: dict[str, str] = {}
    taken: set[str] = set()
    for root, getters in sorted(candidates.items()):
        new = "_" + sorted({g for g, _ in getters})[0]
        if new in taken:
            continue
        taken.add(new)
        renames[root] = new
    if renames:

        def rename(expr: Expr) -> Expr:
            if isinstance(expr, Var) and expr.ssa is None and expr.name in renames:
                return replace(expr, name=renames[expr.name])
            return expr

        for view in views:
            map_body(view.body, rename)
    return {
        root: {
            "name": new,
            "getters": sorted(candidates[root]),
            "rule": "dictionary-named public getter returns exactly this field",
        }
        for root, new in renames.items()
    }


def storage_declarations(
    views: list[FunctionView], context: ProgramContext, renames: dict
) -> tuple[list[tuple[str, frozenset[str]]], dict[str, str]]:
    """Declarations for every printed storage root, typed from uses and the native model."""
    original = {info["name"]: root for root, info in renames.items()}
    keys: dict[str, list[set[str]]] = {}
    evidence: dict[str, set[str]] = {}
    values: dict[str, set[str]] = {}
    for view in views:
        for stmt in iter_statements(view.body):
            exprs: list[Expr] = list(read_expressions(stmt))
            written = stmt.targets[0] if isinstance(stmt, Assign) and stmt.targets else None
            if isinstance(stmt, Assign):
                exprs.extend(stmt.targets)
            for expr in exprs:
                for node in iter_expr(expr):
                    root = storage_root(node)
                    if root is None:
                        continue
                    name, path = root
                    slots = keys.setdefault(name, [])
                    while len(slots) < len(path):
                        slots.append(set())
                    for index, key in enumerate(path):
                        slots[index].add(expression_type(key))
                    evidence.setdefault(name, set()).update(node.all_evidence())
                    if written is node and isinstance(stmt, Assign):
                        values.setdefault(name, set()).add(expression_type(stmt.value))
    fields = context.program.semantics.storage_fields if context.program.semantics else []
    lines = []
    types: dict[str, str] = {}
    for name in sorted(keys, key=lambda n: _slot_order(original.get(n, n), context)):
        location, slot, low, high = context.storage_roots.get(
            original.get(name, name), ("storage", "?", 0, 31)
        )
        native = [
            f
            for f in fields
            if f.location == location
            and f.slot == slot
            and (f.byte_low, f.byte_high) == (low, high)
        ]
        candidates = sorted({c for f in native for c in f.type_candidates})
        value_types = values.get(name, set()) - {"uint256"}
        if keys[name]:
            value = value_types.pop() if len(value_types) == 1 else "uint256"
            declared = value
            for slot_types in reversed(keys[name]):
                key = slot_types.pop() if len(slot_types) == 1 else "uint256"
                declared = f"mapping ({key} => {declared})"
        else:
            declared = _scalar_type(candidates, value_types, high - low + 1)
        types[name] = declared
        where = f"STORAGE[{slot}]" if location == "storage" else f"TSTORAGE[{slot}]"
        if (low, high) != (0, 31):
            where += f" bytes {low}..{high}"
        if name in original:
            getters = renames[original[name]]["getters"]
            where += f"; named after getter {getters[0][0]}() [dict]"
        if len(candidates) > 1 and not keys[name]:
            where += "; native type candidates " + "/".join(candidates)
        lines.append((f"{declared} {name}; // {where}", frozenset(evidence.get(name, set()))))
    return lines, types


def _slot_order(name: str, context: ProgramContext) -> tuple:
    location, slot, low, _high = context.storage_roots.get(name, ("storage", "0xffff", 0, 31))
    try:
        number = int(slot, 16)
    except ValueError:
        number = 1 << 256
    return (location != "storage", number, low)


def _scalar_type(candidates: list[str], written: set[str], width: int) -> str:
    plain = [c for c in candidates if c != "bool"]
    if len(written) == 1 and next(iter(written)) in {"address", "bool"}:
        return next(iter(written))
    if len(plain) == 1:
        return plain[0]
    if width == 20 and "address" in candidates:
        return "address"
    return f"uint{8 * width}" if width < 32 else "uint256"


def used_events(views: list[FunctionView], names: Names) -> list[str]:
    by_name = {}
    for candidates in names.events.matches.values():
        if len(candidates) == 1:
            by_name[split_signature(candidates[0])[0]] = candidates[0]
    indexed: dict[str, set[int]] = {}
    for view in views:
        for stmt in iter_statements(view.body):
            if isinstance(stmt, Emit):
                indexed.setdefault(stmt.event, set()).add(stmt.indexed)
    lines = []
    for name in sorted(indexed):
        if name not in by_name:
            continue
        params = split_signature(by_name[name])[1]
        counts = indexed[name]
        if len(counts) == 1 and next(iter(counts)) <= len(params):
            count = next(iter(counts))
            rendered = [p + (" indexed" if i < count else "") for i, p in enumerate(params)]
            note = "[dict] topic hash matches; indexed = leading parameters (topic count)"
        else:
            rendered = params
            note = "[dict] topic hash matches; indexed positions unresolved"
        lines.append(f"event {name}({', '.join(rendered)}); // {note}")
    return lines


__all__ = ["DecompiledProgram", "build_decompiled", "remove_unused_reads", "render_decompiled"]
