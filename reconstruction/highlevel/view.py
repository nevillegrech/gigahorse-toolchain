"""Readable decompiled view: tree lifting, cleanup passes and an evidence map."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from ..model import Function, Program
from .abi_codec import recognize_abi_coders
from .dispatch import dispatch_value_checks, table_dispatcher, uses_table
from .errors import recognize_error_payloads
from .idioms import (
    recognize_arithmetic_helpers,
    recognize_bytes_returns,
    recognize_memory_helpers,
    recognize_string_getters,
)
from .ir import (
    AbiCodec,
    Assign,
    Call,
    Comment,
    CustomError,
    Emit,
    Expr,
    ExprStmt,
    RawBlock,
    Require,
    Return,
    Stmt,
    Var,
    is_local,
    struct_fields,
)
from .lift import (
    FunctionLifter,
    ProgramContext,
    decoder_head_size,
    head_params,
    is_static_abi,
    signature_params,
)
from .memory_forwarding import forward_memory
from .memory_liveness import AddressModel, FreePointerVersions, Summaries, compute_summaries
from .naming import Names, load_names, split_signature
from .numeric import refine_160_bit_returns
from .objects import memory_objects
from .parameters import group_struct_parameters, lazy_whole_head, struct_intervals
from .passes import (
    FunctionState,
    absorb_memory_plumbing,
    common_subexpressions,
    constant_branches,
    copy_propagation,
    drop_trivial_requires,
    empty_memory_operations,
    eth_transfers,
    guards_to_requires,
    is_free_pointer_read,
    iter_expr,
    iter_statements,
    leading_callvalue_check,
    loop_conditions,
    mark_encoded_arguments,
    memcpy_loops,
    read_expressions,
    refresh_output_notes,
    remove_unused_reads,
    repeated_checks,
    sequential_merges,
    short_circuit,
    single_use_inline,
    split_variable_webs,
    statement_ids,
    tidy_branches,
    trailing_stop,
    unused_call_results,
)
from .printer import Printed, expression, print_statements
from .summaries import summarize, summary_lines
from .types import (
    TypedValue,
    expression_type,
    map_body,
    present_dynamic_arguments,
    storage_root,
    type_variables,
)

LEGEND = [
    "Decompiled view: Gigahorse IR lifted to Solidity-like code by local readability passes.",
    "Not compilable Solidity and not an equivalence proof. Per-line IR/bytecode evidence: decompiled.map.json.",
    "Conventions: arithmetic wraps mod 2**256 unless a check is shown; `/` and `%` by zero give 0 (EVM);",
    "  MEM[p] / msg.data[p] are 32-byte words at byte offset p; `if (x)` tests x != 0; msg.sig is the 4-byte selector;",
    "  require(c, returndata) reverts with the callee's revert data; stor_<slot>[_<bytes>] are inferred storage fields.",
    "  For a dynamic calldata argument x: x.length = msg.data[x], x.data = x + 32, x.word(k) = msg.data[x.data + k].",
    "  bytesAt(p) / stringAt(p) / arrayAt(p) / tupleAt(p) / dataAt(p): a dynamic call argument encoded in memory at p",
    "  (its length word first); dataAt when the argument's type is unknown.",
    "abi.decode / abi.encode / abi.encodePacked: solc's ABI coders, recognized step by step from the compiled code",
    "  (rules solc-abi-*); they check (in solc's order), allocate at the free pointer and write memory as compiled.",
    "  Struct members print as .f0, .f1, ... by position; a `bytes` member may be `string` in the source.",
    '  hex"..." in abi.encodePacked is exactly those bytes. A call argument or .call(b) naming a bytes',
    "  value b sends its ABI encoding (resp. its bytes).",
    "Memory objects (allocated at the free pointer, rule memory-object): `new struct(k)` is k words, not zeroed;",
    "  `struct(a, b)` the same with its words written in order; v.wordN is MEM[v + 32*N]. `new bytes(n)` /",
    "  `new uint256[](n)` write the length word (v.length) and reserve the data (v[i] is word i after it);",
    '  `v = x` with a "copied to memory" note copies a calldata argument or the returned data into a new',
    '  object; "..." / hex"..." is a bytes constant. Where the analysis folded the pointer to 0x80, the object',
    "  assumes it (rule assumes-folded-free-pointer; checked when the view is executed).",
    "Errors: `revert Name(args)` / require(c, Name(args)) send that custom error (selector and argument words);",
    "  abi.encodeWithSelector(0x..., words) when the selector has no dictionary name; `error ...` lines declare names.",
    "Names marked [dict] come from hash-checked local signature dictionaries: hints, not proof of the original source.",
    "UNCERTAIN marks constructs that were not fully recovered; raw EVM operations are kept in those places.",
    'Error("...") reasons copied from code: padding bytes after the reason are not modeled',
    "  (rule error-padding-not-modeled); the reason, its length and offset are exact.",
    "Hidden memory writes: proven unread, or ABI temporaries of a represented call/event/return that are not",
    "  re-read through the same pointer (solc memory discipline; such lines carry rule assumes-solc-memory-discipline).",
]

# Added when a function returns a narrow integer: its width comes from a mask (or a
# sign extension) on the returned value, which solc emits alike for a narrow
# declared type and for a wider declared type holding a narrow value.
NARROW_RETURNS = [
    "returns (uint256 /* uint128 */): the returned word is masked (or sign-extended) to the type in the",
    "  comment; the source may declare that type or a wider one holding the value (the bytecode is the same).",
]
NARROW = re.compile(r"u?int(\d+)")
# Added when the dispatcher is a selector table printed as its chain (dispatch.py).
SELECTOR_TABLE = [
    "Selector table (Vyper 0.3.10+): the dispatcher's chain of `if (msg.sig == ...)` is what executing its",
    "  table lookup does for each selector (src/selector_table.py), not the compiled control flow.",
]


def _narrow(kind: str) -> bool:
    match = NARROW.fullmatch(kind)
    return match is not None and int(match.group(1)) < 256


def _printed_return(kind: str) -> str:
    """A narrow integer return prints as a 256-bit word with its proven width as a comment:
    the declared type may be that width or wider (see NARROW_RETURNS)."""
    return f"uint256 /* {kind} */" if _narrow(kind) else kind


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
    # The dispatcher's shared callvalue check, when it covers this entry point.
    nonpayable_by_dispatcher: Stmt | None = None
    # The view of this function failed: its arguments are not claimed.
    arguments_unknown: bool = False
    # A dictionary name the ABI decoder contradicts: (signature, needed, head bytes).
    rejected_signature: tuple[str, int, int] | None = None
    # Static struct parameters: (name, head-word arguments, struct name, field types).
    parameter_groups: list[tuple[str, list[str], str, list[str]]] = field(default_factory=list)


def _bits(kind: str) -> int | None:
    if kind == "address":
        return 160
    if kind.startswith("uint") and kind[4:].isdigit():
        return int(kind[4:])
    return None


def _declared_word_type(state: FunctionState, value: TypedValue, declared: str, signature: str):
    """Masks show only the bits the code uses, not the declared type: a 160-bit
    value may be uint160, and a word masked at every use may be declared wider
    (e.g. `uint256 id` used as an address). The hash-matched signature decides."""
    code, wide = _bits(value.type), _bits(declared)
    if code is None or wide is None or declared == value.type:
        return
    if value.type == "address" and declared == "uint160":
        value.type = "uint160"
        value.reason += (
            f"; a 160-bit value, uint160 in the hash-matched signature {signature} [dict]"
        )
        return
    if value.enforcement == "mask" and wide > code:
        # The uses keep their mask (as compiled); the parameter is the wider word.
        mask = value.type

        def recast(expr: Expr, name: str = value.name) -> Expr:
            if isinstance(expr, Var) and expr.name == name and expr.typed == mask:
                return Call(mask, (replace(expr, typed=None),), evidence=expr.evidence)
            return expr

        map_body(state.body, recast)
        value.type = declared
        value.enforcement = None
        value.reason = (
            f"masked to {mask} at every use; declared {declared} in the hash-matched "
            f"signature {signature} [dict]"
        )


def _strict() -> bool:
    """Tests set RECONSTRUCTION_STRICT=1 so a failing function raises instead of falling back."""
    return os.environ.get("RECONSTRUCTION_STRICT") == "1"


def _failed_view(
    context: ProgramContext, function: Function, signature: str | None, error: Exception
) -> FunctionView:
    """One function's view failed: print a visible stub, not a guess, and keep the rest."""
    detail = f"{type(error).__name__}: {error}".replace("\n", " ")[:240]
    body: list[Stmt] = [
        RawBlock(
            "view_failed",
            [Comment("its IR is printed in structured.sol.txt")],
            uncertain=f"readable view not produced for this function ({detail})",
        )
    ]
    name = context.function_names[function.id]
    view = FunctionView(function, name, body, [], FunctionState(body), signature, None, None, False)
    view.arguments_unknown = True
    return view


def collect_keys(context: ProgramContext) -> tuple[set[str], set[str], set[str]]:
    program = context.program
    selectors = {s for f in program.functions for s in f.selectors}
    if program.semantics:
        selectors |= {s for c in program.semantics.external_calls for s in c.selector_candidates}
    # Selector-shaped words stored to memory (or merged into a word): calls whose
    # input the view decodes from memory itself, when the native model did not.
    for stmt in context.statements.values():
        if stmt.opcode not in {"MSTORE", "OR"}:
            continue
        operands = stmt.operands[1:] if stmt.opcode == "MSTORE" else stmt.operands
        for operand in operands:
            value = context.constants.get(operand)
            if value and value >> 224 and not value & ((1 << 224) - 1):
                selectors.add(f"0x{value >> 224:08x}")
    topics = set()
    for stmt in context.statements.values():
        if stmt.opcode.startswith("LOG") and len(stmt.operands) >= 3:
            value = context.constants.get(stmt.operands[2])
            if value is not None:
                topics.add(f"0x{value:064x}")
    errors = set()
    # Selector words stored to memory may start a custom error payload (see errors.py).
    for stmt in context.statements.values():
        if stmt.opcode == "MSTORE" and len(stmt.operands) == 2:
            value = context.constants.get(stmt.operands[1])
            if value and value >> 224 and not value & ((1 << 224) - 1):
                errors.add(f"0x{value >> 224:08x}")
            elif value and 1 << 16 <= value < 1 << 32:
                # Right-aligned selector (`mstore(0, sel)` then `revert(0x1c, ...)`).
                errors.add(f"0x{value:08x}")
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
    program: Program,
    relations: Path | None = None,
    names: Names | None = None,
    *,
    online_signatures: bool = False,
) -> tuple[str, dict]:
    result = build_decompiled(program, relations, names, online_signatures=online_signatures)
    return result.text, result.mapping


def dispatched_selectors(program: Program) -> Program:
    """A selector claimed by several functions belongs to the dispatched entry.

    The native analysis marks a function public when code compares `msg.sig`
    with a selector before reaching it; an internal function that does so
    (Balancer's vault checks `msg.sig` inside its swap and join paths) then
    shares the selector with the real entry. The dispatcher passes no stack
    arguments, so when exactly one claimant has none, the others are internal
    functions and are printed as such."""
    claimants: dict[str, list[Function]] = {}
    for function in program.functions:
        for selector in function.selectors:
            claimants.setdefault(selector, []).append(function)
    demoted: dict[str, set[str]] = {}
    for selector, functions in claimants.items():
        entries = [f for f in functions if not f.formal_variables]
        if len(functions) > 1 and len(entries) == 1:
            for function in functions:
                if function.formal_variables:
                    demoted.setdefault(function.id, set()).add(selector)
    if not demoted:
        return program
    functions = [
        replace(f, selectors=[s for s in f.selectors if s not in demoted[f.id]])
        if f.id in demoted
        else f
        for f in program.functions
    ]
    return replace(program, functions=functions)


def build_decompiled(
    program: Program,
    relations: Path | None = None,
    names: Names | None = None,
    *,
    online_signatures: bool = False,
) -> DecompiledProgram:
    if relations is None:
        relations = program.source_directory
    program = dispatched_selectors(program)
    context = ProgramContext.build(program, relations)
    if names is None:
        names = load_names(*collect_keys(context), online=online_signatures)
    for topic, candidates in names.events.matches.items():
        if len(candidates) == 1:
            context.event_names[topic] = split_signature(candidates[0])[0]
    for selector, candidates in names.functions.matches.items():
        if len(candidates) == 1:
            context.external_signatures[selector] = candidates[0]
    for selector, candidates in names.errors.matches.items():
        if len(candidates) == 1:
            context.error_signatures[int(selector, 16)] = candidates[0]
    signatures: dict[str, str | None] = {}
    for function in program.functions:
        if len(function.selectors) == 1:
            name, signature = _public_name(function.selectors[0], names)
            if signature is not None:
                # A hash-matched name whose parameters are fewer head bytes than the
                # ABI decoder requires is a selector collision, not the source name.
                head = 32 * len(head_params(signature_params(signature)))
                needed = decoder_head_size(context, function)
                if needed is not None and needed > head:
                    context.rejected_signatures[function.id] = (signature, needed, head)
                    name, signature = function.selectors[0], None
            context.function_names[function.id] = name
            signatures[function.id] = signature
            if signature:
                context.function_signatures[function.id] = signature
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

    # A failure in one function costs only that function (see _failed_view).
    failed: dict[str, Exception] = {}
    prepared = []
    for function in program.functions:
        try:
            prepared.append(prepare_function(context, function))
        except Exception as error:
            if _strict():
                raise
            failed[function.id] = error
    summaries = memory_summaries(context, prepared, {context.function_names[f] for f in failed})
    views = []
    for entry in prepared:
        try:
            views.append(
                finish_function(context, entry, signatures.get(entry.function.id), summaries)
            )
        except Exception as error:
            if _strict():
                raise
            failed[entry.function.id] = error
    for function in program.functions:
        if function.id in failed:
            views.append(
                _failed_view(context, function, signatures.get(function.id), failed[function.id])
            )
    for view in views:
        view.rejected_signature = context.rejected_signatures.get(view.function.id)
    table_dispatcher(program.runtime_bytecode, views)
    dispatcher_value_check = _dispatcher_nonpayable(views)
    dispatched_checks = dispatch_value_checks(views)
    for view in views:
        if view.function.selectors and view.nonpayable is None:
            check = dispatcher_value_check or dispatched_checks.get(view.name)
            if check is not None:
                view.nonpayable_by_dispatcher = check
    provisional = DecompiledProgram(context, views, {}, "", {})
    recognitions = recognize_string_getters(provisional)
    recognitions += recognize_arithmetic_helpers(provisional)
    recognitions += recognize_memory_helpers(provisional)
    recognitions += recognize_string_getters(provisional)
    recognitions += recognize_bytes_returns(provisional)
    # Last presentation step: allocations as values, words as fields (after
    # every memory analysis and idiom recognizer has seen plain MEM accesses).
    for view in views:
        view.state.body = view.body
        memory_objects(view.state, bool(view.function.selectors))
        view.body = view.state.body
    refine_160_bit_returns(views)
    storage = name_storage_from_getters(views)
    declarations, field_types = storage_declarations(views, context, storage)
    for view in views:
        view.returns = _returns(view.body, field_types)
    out = Printed(offsets={s.id: s.original_statements for s in context.statements.values()})
    legend = list(LEGEND)
    if any(v.function.selectors and any(map(_narrow, v.returns or [])) for v in views):
        legend += NARROW_RETURNS
    if uses_table(views):
        legend += SELECTOR_TABLE
    for line in legend:
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
    structs = used_structs(views)
    if structs:
        out.emit("// Structs inferred from ABI coding; members are named by position.", 1)
        for text in structs:
            out.emit(text, 1, kind="struct-declaration")
        out.emit("", 0)
    events = used_events(views, names)
    for text in events:
        out.emit(text, 1, kind="event-declaration")
    for text in used_errors(views, context):
        out.emit(text, 1, kind="error-declaration")
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
    # Sorted: passes collect elisions from sets, and the map must not depend on hash order.
    elided: list[dict] = sorted(
        (
            {
                "function": view.function.id,
                "ir_statements": sorted(elision.statements),
                "reason": elision.reason,
            }
            for view in views
            for elision in view.state.elided
        ),
        key=lambda e: (e["function"], e["reason"], e["ir_statements"]),
    )
    accounted = referenced | {sid for e in elided for sid in e["ir_statements"]}
    accounted |= {sid for view in views for sid in view.argument_evidence}
    structural = classify_unprinted(context, accounted)
    accounted |= {sid for ids in structural.values() for sid in ids}
    mapping = {
        "schema_version": 1,
        "view": "decompiled",
        "legend": legend,
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

    result: dict[str, set[str]] = {
        "control_transfer": set(),
        "dead_or_control_only_pure": set(),
        "callee_copy_not_executed": set(),
    }
    # Copies of a callee's blocks next to a call that runs the callee: entered
    # only by the call's ignored edges, so they are not part of the structured flow.
    for function in context.program.functions:
        plan = context.plans.get(function.id)
        if plan is None or plan.region is None:
            continue
        members = set(function.blocks)
        todo = [c for t in plan.transfers.values() for c in t.ignored_callee_copies]
        seen: set[str] = set()
        while todo:
            node = todo.pop()
            if node in seen or node in plan.reachable_blocks or node not in members:
                continue
            seen.add(node)
            block = context.blocks[node]
            result["callee_copy_not_executed"] |= {
                s.id for s in block.instructions if s.id not in accounted
            }
            todo.extend(block.successors)
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
    if lifter.plan is not None and lifter.plan.origin:
        # Duplicated shared regions reuse the IR's names once per copy.
        split_variable_webs(state)
    sequential_merges(state)
    constant_branches(state)
    code = (
        bytes.fromhex(context.program.runtime_bytecode)
        if context.program.runtime_bytecode
        else None
    )
    recognize_error_payloads(state, context.error_signatures)
    guards_to_requires(state, code)
    drop_trivial_requires(state)
    remove_unused_reads(state)
    single_use_inline(state)
    loop_conditions(state)
    return _Prepared(function, lifter, item, state)


def memory_summaries(
    context: ProgramContext,
    prepared: list[_Prepared],
    failed: set[str] | frozenset[str] = frozenset(),
) -> Summaries:
    functions = {}
    callees = frozenset(context.function_names.values())
    for name in failed:
        # No view: calling it may read any memory, so no write before a call is hidden.
        body: list[Stmt] = [ExprStmt(Call("private_call_unresolved", ()))]
        functions[name] = (body, AddressModel(set(), FreePointerVersions(body, callees)))
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
    memcpy_loops(state)
    # Twice: forwarding can reveal a constant (e.g. the length 0 of `new bytes(0)`),
    # whose copy loop then disappears, giving the buffers around it exact bounds.
    for _ in range(2):
        copy_propagation(state)
        constant_branches(state)
        sequential_merges(state)
        copy_propagation(state)
        lifter.abstracted |= forward_memory(
            state, callees, context.external_signatures, lifter.consumer_writers
        )
    copy_propagation(state)
    empty_memory_operations(state, callees)
    mark_encoded_arguments(state, callees)
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
    constant_branches(state)
    drop_trivial_requires(state)
    leading_callvalue_check(state, public=bool(function.selectors))
    trailing_stop(state)
    # Calldata structs whose members are validated where read: returned as
    # pointers by a decoder helper, or (inlined decoder) the whole head.
    known = list(lifter.pointer_structs)
    if function.selectors and not signature and not known:
        whole = lazy_whole_head(state.body, item.arguments)
        known += [whole] if whole else []
    intervals = (
        struct_intervals(state.body, split_signature(signature)[1] if signature else None, known)
        if function.selectors
        else []
    )
    # Fields of these structs are typed from validators where they are read.
    lazy = frozenset(
        item.arguments[index].name
        for first, count in known
        for index in range(first, min(first + count, len(item.arguments)))
    )
    typed = type_variables(state, [arg.name for arg in item.arguments], lazy)
    for name, value in typed.items():
        value.kind = lifter.argument_kinds.get(name, "word")
        value.definition = lifter.argument_definitions.get(name)
        if value.kind in {"array", "struct"} and value.type == "uint256":
            value.type = "dynamic"
            value.reason = (
                "native ABI model: calldata position of a dynamic argument (offset + 4); "
                "element types unresolved"
            )
    dynamic = {name for name, value in typed.items() if value.kind in {"array", "struct"}}
    if dynamic:
        present_dynamic_arguments(state, dynamic)
    decoded = recognize_abi_coders(
        state,
        frozenset(dynamic),
        context.structs,
        {name: value.type for name, value in typed.items()},
    )
    common_subexpressions(state)
    copy_propagation(state)
    if signature and function.selectors:
        # Head words of the signature: static tuples flattened, like the arguments.
        params = head_params(split_signature(signature)[1])
        for index, arg in enumerate(item.arguments):
            value = typed[arg.name]
            if (
                value.kind in {"array", "struct"}
                and index < len(params)
                and not is_static_abi(params[index])
            ):
                value.type = params[index]
                value.reason += f"; ABI type from the hash-matched signature {signature} [dict]"
            elif value.kind == "unread" and index < len(params):
                value.type = params[index]
                value.reason = (
                    f"not read by the code; type from the hash-matched signature {signature} [dict]"
                )
            elif value.kind == "word" and index < len(params):
                _declared_word_type(state, value, params[index], signature)
    for name in decoded:
        value = typed[name]
        if value.type == "dynamic":
            value.type = "bytes"
            value.reason += "; decoded with abi.decode, whose source is bytes"
    groups = group_struct_parameters(state, item.arguments, typed, context.structs, intervals)
    remove_unused_reads(state)
    loop_conditions(state)
    # Loop conditions are formed last; a constant one (e.g. a copy loop over 0
    # bytes) removes the loop and leaves single-definition merges behind.
    constant_branches(state)
    sequential_merges(state)
    copy_propagation(state)
    remove_unused_reads(state)
    tidy_branches(state)
    refresh_output_notes(state)
    view = FunctionView(
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
    view.parameter_groups = groups
    return view


def _dispatcher_nonpayable(views: list[FunctionView]) -> Stmt | None:
    """A dispatcher-level require(!msg.value) before any branch applies to every entry."""
    from .ir import Comment, Env, If, Unary

    for view in views:
        if view.name != "__function_selector__":
            continue
        for stmt in view.body:
            if isinstance(stmt, If):
                return None
            if (
                isinstance(stmt, Require)
                and stmt.payload is None
                and isinstance(stmt.condition, Unary)
                and stmt.condition.op == "!"
                and stmt.condition.operand == Env("msg.value")
            ):
                return stmt
            if not isinstance(stmt, (Assign, Comment)):
                return None
    return None


def print_function(out: Printed, view: FunctionView, summary=None) -> None:
    function = view.function
    out.emit("", 0)
    selector = function.selectors[0] if len(function.selectors) == 1 else None
    if view.name == "__function_selector__":
        out.emit("// Selector dispatch (compiler-generated; shown for completeness).", 1)
    elif selector:
        hint = f" {view.signature} [dict]" if view.signature else ""
        out.emit(f"// {selector}{hint}", 1, kind="function-hint")
        rejected = view.rejected_signature
        if rejected is not None:
            signature, needed, head = rejected
            out.emit(
                f"//   dictionary name {signature} [dict] rejected: the ABI decoder requires "
                f"{needed} bytes of arguments, the signature has {head}",
                1,
                kind="function-hint",
            )
        if summary is not None:
            for text, ids in summary_lines(summary, True):
                out.emit(
                    "//   " + text,
                    1,
                    evidence=ids,
                    kind="behaviour-summary",
                    uncertain=text if text.startswith("UNCERTAIN") else None,
                )
    leading = {words[0]: struct for _, words, struct, _ in view.parameter_groups}
    inside = {word for _, words, _, _ in view.parameter_groups for word in words[1:]}
    params = ", ".join(
        f"{leading.get(a.name, a.type)} {a.name}" for a in view.arguments if a.name not in inside
    )
    if view.arguments_unknown:
        params = "/* arguments not recovered */"
    if function.selectors:
        nonpayable = view.nonpayable is not None or view.nonpayable_by_dispatcher is not None
        if nonpayable:
            visibility = "public nonpayable"
        elif view.structured:
            visibility = "public payable"
        else:
            # Without structured flow the callvalue check may exist but was not located.
            visibility = "public /* payability unresolved */"
    else:
        visibility = "private"
    returns = f" returns ({', '.join(map(_printed_return, view.returns))})" if view.returns else ""
    evidence = frozenset(view.argument_evidence)
    for argument in view.arguments:
        evidence |= argument.evidence
    if view.nonpayable is not None:
        evidence |= statement_ids(view.nonpayable)
    if view.nonpayable_by_dispatcher is not None:
        evidence |= statement_ids(view.nonpayable_by_dispatcher)
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
        for view in views:
            for root, new in renames.items():
                if view.name.endswith("_" + root):
                    old_name = view.name
                    view.name = view.name[: -len(root)] + new.lstrip("_")

                    def rename_call(
                        expr: Expr, old_name: str = old_name, new_name: str = view.name
                    ) -> Expr:
                        from .ir import Call

                        if isinstance(expr, Call) and expr.name == old_name:
                            return replace(expr, name=new_name)
                        return expr

                    for other in views:
                        map_body(other.body, rename_call)
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


def used_structs(views: list[FunctionView]) -> list[str]:
    found: dict[str, list[str]] = {}
    for view in views:
        for _, _, struct, types in view.parameter_groups:
            if not struct.endswith("]"):  # arrays need no declaration
                found[struct] = types
        for stmt in iter_statements(view.body):
            for expr in stmt.expressions():
                for node in iter_expr(expr):
                    if isinstance(node, AbiCodec):
                        for kind in node.types:
                            struct = struct_fields(kind)
                            if struct is not None:
                                found[struct[0]] = struct[1]
    return [
        f"struct {name} {{ {' '.join(f'{t} f{i};' for i, t in enumerate(fields))} }}"
        for name, fields in sorted(found.items(), key=lambda item: int(item[0][1:]))
    ]


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


def used_errors(views: list[FunctionView], context: ProgramContext) -> list[str]:
    """`error Name(types);` for each dictionary-named custom error the view prints."""
    selectors = {
        node.selector
        for view in views
        for stmt in iter_statements(view.body)
        for expr in stmt.expressions()
        for node in iter_expr(expr)
        if isinstance(node, CustomError) and node.name is not None
    }
    lines = []
    for selector in sorted(selectors, key=lambda s: context.error_signatures[s]):
        signature = context.error_signatures[selector]
        lines.append(f"error {signature}; // [dict] 0x{selector:08x}: selector hash matches")
    return lines


__all__ = ["DecompiledProgram", "build_decompiled", "remove_unused_reads", "render_decompiled"]
