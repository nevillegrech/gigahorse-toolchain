"""Readability passes over lifted statement trees.

Each pass removes or merges printed statements only under a stated condition,
and records the IR statements it absorbed (`hidden`) on the line that explains
them, or in the function's elision list with a reason. Nothing is deleted from
the evidence: unprinted IR remains listed in the map.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace

from .ir import (
    Assign,
    Binary,
    Call,
    Comment,
    Const,
    Emit,
    Env,
    Expr,
    ExprStmt,
    ExternalCallExpr,
    Halt,
    If,
    Index,
    Jump,
    ParallelAssign,
    RawBlock,
    Require,
    Return,
    Revert,
    Slice,
    Stmt,
    Unary,
    Var,
    While,
    annotate,
    is_local,
)
from .simplify import is_boolean, simplify

# Calls/builtins whose evaluation has no effect on state, memory or control.
PURE_CALLS = {
    "keccak256",
    "blockhash",
    "blobhash",
    "gasleft",
    "msize",
    "address",
    "bool",
    "byte",
    "signextend",
    "addmod",
    "mulmod",
    "phi",
}


@dataclass
class Elision:
    statements: frozenset[str]
    reason: str


@dataclass
class FunctionState:
    body: list[Stmt]
    elided: list[Elision] = field(default_factory=list)
    nonpayable: Stmt | None = None


# --- generic traversal helpers -------------------------------------------------


def map_bodies(statements: list[Stmt], visit: Callable[[list[Stmt]], list[Stmt]]) -> list[Stmt]:
    """Apply `visit` to every statement list, innermost first."""
    for stmt in statements:
        if isinstance(stmt, If):
            stmt.then = map_bodies(stmt.then, visit)
            stmt.otherwise = map_bodies(stmt.otherwise, visit)
        elif isinstance(stmt, While):
            stmt.body = map_bodies(stmt.body, visit)
        elif isinstance(stmt, RawBlock):
            stmt.body = map_bodies(stmt.body, visit)
    return visit(statements)


def iter_statements(statements: list[Stmt]) -> Iterator[Stmt]:
    for stmt in statements:
        yield stmt
        for block in stmt.blocks():
            yield from iter_statements(block)


def iter_expr(expr: Expr) -> Iterator[Expr]:
    yield expr
    for child in expr.children():
        yield from iter_expr(child)


def read_expressions(stmt: Stmt) -> tuple[Expr, ...]:
    """Expressions evaluated by a statement (assignment targets contribute only their indices)."""
    if isinstance(stmt, Assign):
        result: list[Expr] = [stmt.value]
        # A call's output buffer is an operand: the EVM writes returned bytes there.
        result.extend(stmt.meta.get("output", ()))
        for target in stmt.targets:
            if isinstance(target, Index):
                result.append(target.key)
                if not isinstance(target.base, Env):
                    result.append(target.base)
            elif not isinstance(target, Var):
                result.append(target)
        return tuple(result)
    if isinstance(stmt, ParallelAssign):
        return stmt.values
    return stmt.expressions()


def variable_uses(statements: list[Stmt]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for stmt in iter_statements(statements):
        for expr in read_expressions(stmt):
            for node in iter_expr(expr):
                if isinstance(node, Var):
                    counts[node.name] += 1
    return counts


def substitute(expr: Expr, mapping: dict[str, Expr]) -> Expr:
    if isinstance(expr, Var) and expr.name in mapping:
        replacement = mapping[expr.name]
        return replace(replacement, evidence=replacement.evidence | expr.evidence)
    children = expr.children()
    if not children:
        return expr
    new = tuple(substitute(child, mapping) for child in children)
    if all(a is b for a, b in zip(new, children, strict=True)):
        return expr
    return simplify(expr.with_children(new))


def substitute_statement(stmt: Stmt, mapping: dict[str, Expr]) -> None:
    if isinstance(stmt, Assign):
        stmt.value = substitute(stmt.value, mapping)
        if "output" in stmt.meta:
            stmt.meta["output"] = tuple(substitute(e, mapping) for e in stmt.meta["output"])
        stmt.targets = tuple(
            t if isinstance(t, Var) else substitute(t, mapping) for t in stmt.targets
        )
    elif isinstance(stmt, ParallelAssign):
        stmt.values = tuple(substitute(v, mapping) for v in stmt.values)
    elif isinstance(stmt, ExprStmt):
        stmt.expr = substitute(stmt.expr, mapping)
    elif isinstance(stmt, Require):
        stmt.condition = substitute(stmt.condition, mapping)
        if stmt.payload is not None:
            stmt.payload = substitute(stmt.payload, mapping)
    elif isinstance(stmt, If):
        stmt.condition = substitute(stmt.condition, mapping)
    elif isinstance(stmt, While) and stmt.condition is not None:
        stmt.condition = substitute(stmt.condition, mapping)
    elif isinstance(stmt, Return):
        stmt.values = tuple(substitute(v, mapping) for v in stmt.values)
        if stmt.raw is not None:
            stmt.raw = substitute(stmt.raw, mapping)
    elif isinstance(stmt, Revert) and stmt.payload is not None:
        stmt.payload = substitute(stmt.payload, mapping)
    elif isinstance(stmt, Emit):
        stmt.args = tuple(substitute(a, mapping) for a in stmt.args)
    elif isinstance(stmt, Halt) and stmt.operand is not None:
        stmt.operand = substitute(stmt.operand, mapping)


def has_effect(expr: Expr) -> bool:
    """Evaluating expr can change state, memory, control or call another contract."""
    for node in iter_expr(expr):
        if isinstance(node, ExternalCallExpr):
            return True
        if isinstance(node, Call) and not (
            node.name in PURE_CALLS
            or node.name.startswith(("uint", "int", "bytes"))
            or node.name in {"Error", "Panic"}
        ):
            return True
    return False


def statement_ids(stmt: Stmt) -> frozenset[str]:
    ids = set(stmt.evidence) | set(stmt.hidden)
    for expr in (*stmt.expressions(), *stmt.meta.get("output", ())):
        ids |= expr.all_evidence()
    for block in stmt.blocks():
        for nested in iter_statements(block):
            ids |= statement_ids(nested)
    return frozenset(ids)


# --- condition presentation -------------------------------------------------


def condition_text_form(expr: Expr) -> Expr:
    """In a condition, bool(x) and x != 0 both read as truthiness of x."""
    if isinstance(expr, Call) and expr.name == "bool" and len(expr.args) == 1:
        return annotate(expr.args[0], expr.evidence)
    if (
        isinstance(expr, Binary)
        and expr.op == "!="
        and isinstance(expr.right, Const)
        and expr.right.value == 0
    ):
        return annotate(expr.left, expr.evidence | expr.right.evidence)
    return expr


def negate(expr: Expr) -> Expr:
    return simplify(Unary("!", expr))


# --- passes -----------------------------------------------------------------


def is_failure(statements: list[Stmt]) -> tuple[str, Expr | None, frozenset[str]] | None:
    """Recognize an arm that only reverts/aborts. Returns (kind, payload, absorbed ids)."""
    if not statements:
        return None
    *prefix, last = statements
    absorbed: set[str] = set()
    for stmt in prefix:
        # Only payload construction (memory writes / pure reads) may precede the abort.
        if isinstance(stmt, Comment):
            continue
        if isinstance(stmt, Assign) and not has_effect(stmt.value):
            absorbed |= statement_ids(stmt)
            continue
        if (
            isinstance(stmt, ExprStmt)
            and isinstance(stmt.expr, Call)
            and stmt.expr.name == "RETURNDATACOPY"
        ):
            absorbed |= statement_ids(stmt)
            continue
        return None
    if isinstance(last, Revert):
        payload = last.payload
        absorbed |= statement_ids(last)
        if isinstance(payload, Slice) and _is_returndata_forward(prefix, payload):
            return "require", Env("returndata"), frozenset(absorbed)
        if isinstance(payload, Slice):
            decoded = decode_relative_payload(prefix, payload)
            if decoded is not None:
                return "require", decoded, frozenset(absorbed)
        if prefix and not (isinstance(payload, Call) or payload is None):
            # An undecoded payload refers to values built by the prefix: keep the arm.
            return None
        if prefix and payload is None and not _payload_only(prefix):
            return None
        return "require", payload, frozenset(absorbed)
    if isinstance(last, Halt) and last.kind == "invalid" and not prefix:
        return "assert", None, statement_ids(last)
    return None


def decode_relative_payload(prefix: list[Stmt], payload: Slice) -> Expr | None:
    """Decode revert bytes written at base+constant offsets in a straight-line arm.

    Every byte of [base, base+n) must be written by a constant MSTORE relative to
    the same base inside the arm, with no other memory effect in between. Covers
    solc's Error(string)/Panic/custom-error encoders after the free pointer moved.
    """
    from .memory_liveness import AddressModel

    model = AddressModel(set())
    # Free-pointer reads in the arm see the same value while only heap bytes
    # (never the pointer word at 0x40) are written in between.
    pointer: str | None = None
    alias: dict[str, str] = {}
    data: dict[int, int] = {}
    for stmt in prefix:
        if isinstance(stmt, Comment):
            continue
        if not isinstance(stmt, Assign) or len(stmt.targets) != 1:
            return None
        target = stmt.targets[0]
        if isinstance(target, Var):
            if is_free_pointer_read(stmt.value):
                if pointer is None:
                    pointer = target.name
                alias[target.name] = pointer
            continue
        if not (
            isinstance(target, Index) and isinstance(target.base, Env) and target.base.name == "MEM"
        ):
            return None
        base, offset = model.split(target.key)
        if base is None or base == "any" or not isinstance(stmt.value, Const):
            return None
        base = "var:" + alias.get(base[4:], base[4:])
        if base != "var:" + (pointer or "") or offset < 0:
            return None
        word = stmt.value.value.to_bytes(32, "big")
        for i in range(32):
            data[offset + i] = word[i]
    if pointer is None:
        return None
    start_base, start_offset = model.split(payload.start)
    end_base, end_offset = model.split(payload.end)
    if start_base in {None, "any"} or end_base in {None, "any"}:
        return None
    if alias.get(start_base[4:]) != pointer or alias.get(end_base[4:]) != pointer:
        return None
    size = end_offset - start_offset
    if not 4 <= size <= 1024:
        return None
    try:
        raw = bytes(data[start_offset + i] for i in range(size))
    except KeyError:
        return None
    from ..reverts import decode_payload

    info = decode_payload(raw)
    from .ir import Raw
    from .printer import quote

    if info.get("encoding") == "Error(string)" and info.get("reason") is not None:
        return Call(
            "Error", (Raw(quote(info["reason"])),), rules=frozenset({"relative-revert-payload"})
        )
    if info.get("encoding") == "Panic(uint256)":
        code = info["panic_code"]
        return Call(
            "Panic",
            (Const(int(code, 16) if isinstance(code, str) else code),),
            rules=frozenset({"relative-revert-payload"}),
        )
    return Raw("0x" + raw.hex(), rules=frozenset({"relative-revert-payload"}))


def _payload_only(prefix: list[Stmt]) -> bool:
    return all(isinstance(s, (Assign, ExprStmt, Comment)) for s in prefix)


def _is_returndata_forward(prefix: list[Stmt], payload: Slice) -> bool:
    copies = [
        s
        for s in prefix
        if isinstance(s, ExprStmt) and isinstance(s.expr, Call) and s.expr.name == "RETURNDATACOPY"
    ]
    if len(copies) != 1:
        return False
    destination, source, _size = copies[0].expr.args
    return (
        isinstance(destination, Const)
        and isinstance(source, Const)
        and source.value == 0
        and isinstance(payload.start, Const)
        and payload.start.value == destination.value
    )


def guards_to_requires(state: FunctionState) -> None:
    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        for stmt in statements:
            if isinstance(stmt, If) and not stmt.otherwise:
                failure = is_failure(stmt.then)
                if failure:
                    kind, payload, absorbed = failure
                    condition = condition_text_form(negate(stmt.condition))
                    result.append(
                        Require(
                            condition,
                            payload,
                            kind=kind,
                            evidence=stmt.evidence,
                            hidden=absorbed | stmt.hidden,
                            rules=frozenset({"guard-to-require"}),
                            uncertain=next((s.uncertain for s in stmt.then if s.uncertain), None),
                        )
                    )
                    continue
            if isinstance(stmt, If) and not stmt.then and stmt.otherwise:
                stmt.condition, stmt.then, stmt.otherwise = (
                    negate(stmt.condition),
                    stmt.otherwise,
                    [],
                )
            if isinstance(stmt, If):
                stmt.condition = condition_text_form(stmt.condition)
            result.append(stmt)
        return result

    state.body = map_bodies(state.body, visit)


def is_side_effect_free_value(expr: Expr) -> bool:
    return not has_effect(expr)


def remove_unused_reads(state: FunctionState, protected: set[str] = frozenset()) -> None:
    """Drop assignments of effect-free values to locals that nothing reads."""
    while True:
        uses = variable_uses(state.body)
        removed: list[Stmt] = []

        def visit(
            statements: list[Stmt], uses: Counter[str] = uses, removed: list[Stmt] = removed
        ) -> list[Stmt]:
            kept = []
            for stmt in statements:
                if (
                    isinstance(stmt, Assign)
                    and all(is_local(t) for t in stmt.targets)
                    and not any(uses[t.name] for t in stmt.targets)
                    and not any(t.name in protected for t in stmt.targets)
                    and is_side_effect_free_value(stmt.value)
                ):
                    removed.append(stmt)
                    continue
                if isinstance(stmt, ParallelAssign):
                    keep = [
                        i
                        for i, t in enumerate(stmt.targets)
                        if not is_local(t) or uses[t.name] or has_effect(stmt.values[i])
                    ]
                    if len(keep) < len(stmt.targets):
                        dropped = [i for i in range(len(stmt.targets)) if i not in keep]
                        ids = frozenset().union(*(stmt.values[i].all_evidence() for i in dropped))
                        state.elided.append(Elision(ids, "unused merge value"))
                        if not keep:
                            state.elided.append(Elision(statement_ids(stmt), "unused merge value"))
                            removed.append(stmt)
                            continue
                        stmt.targets = tuple(stmt.targets[i] for i in keep)
                        stmt.values = tuple(stmt.values[i] for i in keep)
                        removed.append(stmt)
                kept.append(stmt)
            return kept

        state.body = map_bodies(state.body, visit)
        if not removed:
            return
        for stmt in removed:
            state.elided.append(Elision(statement_ids(stmt), "unused effect-free read or value"))


def drop_trivial_requires(state: FunctionState) -> None:
    """require(true): the check can never fail (e.g. uint256 validator x == x)."""

    def visit(statements: list[Stmt]) -> list[Stmt]:
        kept = []
        for stmt in statements:
            if isinstance(stmt, Require) and (
                (isinstance(stmt.condition, Const) and stmt.condition.value)
                or stmt.condition == Env("true")
            ):
                state.elided.append(
                    Elision(statement_ids(stmt), "check that cannot fail (constant true)")
                )
                continue
            kept.append(stmt)
        return kept

    state.body = map_bodies(state.body, visit)


def trailing_stop(state: FunctionState) -> None:
    if state.body and isinstance(state.body[-1], Halt) and state.body[-1].kind == "stop":
        stop = state.body.pop()
        state.elided.append(Elision(statement_ids(stop), "STOP at the end of the function body"))


def leading_callvalue_check(state: FunctionState) -> None:
    """A first-statement require(!msg.value) is the compiler's nonpayable check."""
    for index, stmt in enumerate(state.body):
        if isinstance(stmt, Comment):
            continue
        if (
            isinstance(stmt, Require)
            and stmt.payload is None
            and isinstance(stmt.condition, Unary)
            and stmt.condition.op == "!"
            and stmt.condition.operand == Env("msg.value")
        ):
            state.nonpayable = state.body.pop(index)
        return


def loop_conditions(state: FunctionState) -> None:
    """while (true) { if (c) break; ... } -> while (!c) { ... } when nothing precedes the test."""

    def visit(statements: list[Stmt]) -> list[Stmt]:
        for stmt in statements:
            if not isinstance(stmt, While) or stmt.condition is not None or not stmt.body:
                continue
            first = stmt.body[0]
            if (
                isinstance(first, If)
                and len(first.then) == 1
                and isinstance(first.then[0], Jump)
                and first.then[0].kind == "break"
                and not first.otherwise
                and not _contains_jump(stmt.body[1:], "break", top=True)
            ):
                stmt.condition = condition_text_form(negate(first.condition))
                stmt.evidence = stmt.evidence | statement_ids(first)
                stmt.body = stmt.body[1:]
            # A trailing `continue` at the end of the loop body is implicit.
            if stmt.body and isinstance(stmt.body[-1], Jump) and stmt.body[-1].kind == "continue":
                stmt.evidence = stmt.evidence | statement_ids(stmt.body[-1])
                stmt.body.pop()
            if (
                stmt.condition is None
                and stmt.body
                and isinstance(stmt.body[-1], If)
                and _ends_with(stmt.body[-1].then, "continue")
                and not stmt.body[-1].otherwise
            ):
                # do { ... } while (c): if (c) { copies; continue; } break;
                pass
        return statements

    state.body = map_bodies(state.body, visit)


def _ends_with(statements: list[Stmt], kind: str) -> bool:
    return bool(statements) and isinstance(statements[-1], Jump) and statements[-1].kind == kind


def _contains_jump(statements: list[Stmt], kind: str, *, top: bool) -> bool:
    for stmt in statements:
        if isinstance(stmt, Jump) and stmt.kind == kind:
            return True
        if isinstance(stmt, While):
            continue  # jumps inside nested loops target the nested loop
        for block in stmt.blocks():
            if _contains_jump(block, kind, top=False):
                return True
    return False


def single_use_inline(state: FunctionState) -> None:
    """Inline `v = <read>` into the immediately following statement when v is used once there.

    Only straight-line neighbours are merged: no statement runs between the read
    and its use, so no write can change the value in between.
    """
    while True:
        uses = variable_uses(state.body)
        changed = False

        def visit(statements: list[Stmt], uses: Counter[str] = uses) -> list[Stmt]:
            nonlocal changed
            result: list[Stmt] = []
            index = 0
            while index < len(statements):
                stmt = statements[index]
                following = statements[index + 1] if index + 1 < len(statements) else None
                if (
                    isinstance(stmt, Assign)
                    and len(stmt.targets) == 1
                    and is_local(stmt.targets[0])
                    and stmt.targets[0].name.startswith("v")
                    and uses[stmt.targets[0].name] == 1
                    and not stmt.uncertain
                    and not has_effect(stmt.value)
                    and following is not None
                    and not isinstance(following, (While, RawBlock))
                    and _reads_in_head(following, stmt.targets[0].name)
                ):
                    name = stmt.targets[0].name
                    value = replace(stmt.value, evidence=stmt.value.evidence | stmt.evidence)
                    substitute_statement(following, {name: value})
                    following.hidden = following.hidden | stmt.hidden
                    changed = True
                    index += 1
                    continue
                result.append(stmt)
                index += 1
            return result

        state.body = map_bodies(state.body, visit)
        if not changed:
            return


def _reads_in_head(stmt: Stmt, name: str) -> bool:
    """The variable is read by the statement's own expressions (not a nested body)."""
    for expr in read_expressions(stmt):
        for node in iter_expr(expr):
            if isinstance(node, Var) and node.name == name:
                return True
    return False


# --- memory writes absorbed by high-level consumers ---------------------------

# solc never places the free-memory region below 0x60 (0x80 since 0.4.22);
# scratch space [0, 0x40) and the free pointer word [0x40, 0x60) lie below it.
HEAP_FLOOR = 0x60


@dataclass(frozen=True)
class Address:
    base: str | None  # None: absolute constant; "heap:<var>": free-pointer value; other: opaque
    offset: int


def address_of(expr: Expr, free_pointer_vars: set[str]) -> Address | None:
    if isinstance(expr, Const):
        return Address(None, expr.value)
    if isinstance(expr, Var):
        return Address(("heap:" if expr.name in free_pointer_vars else "var:") + expr.name, 0)
    if is_free_pointer_read(expr):
        # Each inlined read is its own base: two reads may differ if the pointer moved.
        return Address(f"heap:@{id(expr)}", 0)
    if isinstance(expr, Binary) and expr.op == "+":
        for base, extra in ((expr.left, expr.right), (expr.right, expr.left)):
            if isinstance(extra, Const) and extra.value < (1 << 64):
                inner = address_of(base, free_pointer_vars)
                if inner is not None:
                    return Address(inner.base, inner.offset + extra.value)
    return None


def is_free_pointer_read(expr: Expr) -> bool:
    return (
        isinstance(expr, Index)
        and isinstance(expr.base, Env)
        and expr.base.name == "MEM"
        and isinstance(expr.key, Const)
        and expr.key.value == 0x40
    )


def may_overlap(
    write: Address, write_size: int, read: Address | None, read_size: int | None
) -> bool:
    if read is None:
        return True
    if write.base == read.base:
        if read_size is None:
            return read.offset < write.offset + write_size
        return read.offset < write.offset + write_size and write.offset < read.offset + read_size
    if write.base is None and read.base and read.base.startswith("heap:"):
        return write.offset + write_size > HEAP_FLOOR
    if read.base is None and write.base and write.base.startswith("heap:"):
        return read_size is None or read.offset + read_size > HEAP_FLOOR
    return True


def memory_reads(stmt: Stmt) -> Iterator[tuple[Expr, Expr | None]]:
    """(start, size-or-None) of every memory range a printed statement reads."""
    for expr in read_expressions(stmt):
        for node in iter_expr(expr):
            if (
                isinstance(node, Index)
                and isinstance(node.base, Env)
                and node.base.name in {"MEM", "MEM8"}
            ):
                yield node.key, Const(32)
            elif isinstance(node, Slice) and node.space == "MEM":
                yield node.start, _difference(node.end, node.start)
            elif isinstance(node, Call) and node.name == "MCOPY" and len(node.args) == 3:
                yield node.args[1], node.args[2]


def _difference(end: Expr, start: Expr) -> Expr | None:
    if isinstance(end, Binary) and end.op == "+" and end.left == start:
        return end.right
    if isinstance(end, Const) and isinstance(start, Const):
        return Const(end.value - start.value)
    return None


def hide_absorbed_writes(
    state: FunctionState,
    consumer_writers: dict[str, set[str]],
    abstracted: set[str],
    callees: frozenset[str] = frozenset(),
    summaries=None,
    function: str | None = None,
) -> None:
    """Hide memory writes (and inner hashes) consumed only by high-level lines.

    The hidden set H is the greatest fixpoint of: a write is in H if every
    consumer it feeds is represented by a printed abstraction (or was itself
    elided/absorbed) and no printed read can observe its bytes; an inner SHA3 is
    in H if its consumer writers are known and only H writes use its result.
    """
    from .memory_liveness import AddressModel, Live, Liveness

    elided_ids = {sid for elision in state.elided for sid in elision.statements}
    writer_consumers: dict[str, set[str]] = {}
    for consumer, writers in consumer_writers.items():
        for writer in writers:
            writer_consumers.setdefault(writer, set()).add(consumer)
    statements = list(iter_statements(state.body))
    free_pointer_vars = {
        stmt.targets[0].name
        for stmt in statements
        if isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and is_local(stmt.targets[0])
        and is_free_pointer_read(stmt.value)
    }
    model = AddressModel(free_pointer_vars)
    # Every memory write is a candidate: memory is only observable through reads,
    # so a write no printed statement can read is invisible. Consumers whose
    # memory input is represented by their printed form do not count as readers.
    writers: dict[int, Stmt] = {}
    write_ranges: dict[int, tuple[Expr, int | None]] = {}
    for stmt in statements:
        if (
            isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], Index)
            and isinstance(stmt.targets[0].base, Env)
            and stmt.targets[0].base.name in {"MEM", "MEM8"}
            and not has_effect(stmt.value)
        ):
            writers[id(stmt)] = stmt
            write_ranges[id(stmt)] = (
                stmt.targets[0].key,
                32 if stmt.targets[0].base.name == "MEM" else 1,
            )
        elif (
            isinstance(stmt, ExprStmt)
            and isinstance(stmt.expr, Call)
            and stmt.expr.name in {"CALLDATACOPY", "MCOPY", "CODECOPY"}
            and len(stmt.expr.args) == 3
        ):
            # RETURNDATACOPY is excluded: it reverts when copying past the data.
            size = stmt.expr.args[2]
            writers[id(stmt)] = stmt
            write_ranges[id(stmt)] = (
                stmt.expr.args[0],
                size.value if isinstance(size, Const) else None,
            )
    hashes = {
        id(stmt): stmt
        for stmt in statements
        if isinstance(stmt, Assign)
        and stmt.origin in consumer_writers
        and len(stmt.targets) == 1
        and is_local(stmt.targets[0])
        and isinstance(stmt.value, Call)
        and stmt.value.name == "keccak256"
    }
    hidden = set(writers) | set(hashes)
    if not writers:
        return
    while True:
        absorbed = (
            set(abstracted)
            | {c for c in consumer_writers if c in elided_ids}
            | {hashes[h].origin or "" for h in hidden if h in hashes}
        )
        remove: set[int] = set()
        outside_uses: Counter[str] = Counter()
        for stmt in statements:
            if id(stmt) in hidden:
                continue
            for expr in read_expressions(stmt):
                for node in iter_expr(expr):
                    if isinstance(node, Var):
                        outside_uses[node.name] += 1
        for key in hidden & set(hashes):
            target = hashes[key].targets[0]
            assert isinstance(target, Var)
            if outside_uses[target.name]:
                remove.add(key)
        liveness = Liveness(model, hidden, absorbed, callees, summaries, function)
        liveness.block(state.body, Live(), None)
        for key in hidden & set(writers):
            start_expr, size = write_ranges[key]
            if size == 0:
                continue
            if liveness.after.get(key, Live()).observes(model.range(start_expr, size)):
                remove.add(key)
        if not remove:
            break
        hidden -= remove
    hidden_writers = hidden & set(writers)
    if not hidden_writers:
        return
    by_consumer: dict[str, set[str]] = {}
    for key in hidden:
        stmt = writers.get(key) or hashes[key]
        consumers = (
            writer_consumers.get(stmt.origin or "", set())
            if key in writers
            else {stmt.origin or ""}
        )
        if not consumers:
            target = stmt.targets[0] if isinstance(stmt, Assign) else None
            reason = (
                "free-memory-pointer update; no printed statement reads the pointer it sets"
                if isinstance(target, Index) and is_free_pointer_read(target)
                else "dead memory write; no printed statement reads these bytes"
            )
            state.elided.append(Elision(statement_ids(stmt), reason))
        for consumer in consumers:
            by_consumer.setdefault(consumer, set()).update(statement_ids(stmt))
    attached: set[str] = set()

    def attach(statements: list[Stmt]) -> list[Stmt]:
        kept = []
        for stmt in statements:
            if id(stmt) in hidden:
                continue
            if stmt.origin in by_consumer:
                stmt.hidden = stmt.hidden | frozenset(by_consumer[stmt.origin])
                attached.add(stmt.origin or "")
            kept.append(stmt)
        return kept

    state.body = map_bodies(state.body, attach)
    for consumer, ids in by_consumer.items():
        if consumer not in attached:
            state.elided.append(
                Elision(
                    frozenset(ids),
                    f"memory input of {consumer}, represented by its high-level form",
                )
            )


def absorb_memory_plumbing(
    state: FunctionState,
    consumer_writers: dict[str, set[str]],
    abstracted: set[str],
    callees: frozenset[str] = frozenset(),
    summaries=None,
    function: str | None = None,
) -> None:
    """Alternate write hiding and dead-read removal until neither changes the body."""
    for _ in range(16):
        before = sum(1 for _ in iter_statements(state.body))
        hide_absorbed_writes(state, consumer_writers, abstracted, callees, summaries, function)
        remove_unused_reads(state)
        if sum(1 for _ in iter_statements(state.body)) == before:
            return


def _false_given(value: Expr, condition: Expr) -> bool:
    return (isinstance(value, Const) and value.value == 0) or value == negate(condition)


def _true_given(value: Expr, condition: Expr) -> bool:
    return (isinstance(value, Const) and value.value == 1 and True) or (
        value == condition and is_boolean(condition)
    )


def short_circuit(state: FunctionState) -> None:
    """if (c) { v = x } else { v = y }  ->  v = c && x / !c && y / c || y / !c || x.

    Applies when one arm's value is decided by c itself (as compilers emit for
    && and ||) and both arms consist of the single assignment to v.
    """

    def single(arm: list[Stmt]) -> ParallelAssign | Assign | None:
        if len(arm) == 1 and isinstance(arm[0], (ParallelAssign, Assign)):
            stmt = arm[0]
            targets = stmt.targets
            values = stmt.values if isinstance(stmt, ParallelAssign) else (stmt.value,)
            if len(targets) == 1 and len(values) == 1 and is_local(targets[0]):
                return stmt
        return None

    def value(stmt: ParallelAssign | Assign) -> Expr:
        return stmt.values[0] if isinstance(stmt, ParallelAssign) else stmt.value

    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        for stmt in statements:
            if isinstance(stmt, If):
                then, other = single(stmt.then), single(stmt.otherwise)
                if then and other and then.targets[0] == other.targets[0]:
                    c, x, y = stmt.condition, value(then), value(other)
                    combined: Expr | None = None
                    if _false_given(x, c) and is_boolean(y):
                        combined = Binary("&&", negate(c), y)
                    elif _true_given(x, c) and is_boolean(y):
                        combined = Binary("||", c, y)
                    elif _false_given(y, negate(c)) and is_boolean(x):
                        combined = Binary("&&", c, x)
                    elif _true_given(y, negate(c)) and is_boolean(x):
                        combined = Binary("||", negate(c), x)
                    if combined is not None:
                        result.append(
                            Assign(
                                then.targets,
                                combined,
                                evidence=stmt.evidence | then.evidence | other.evidence,
                                hidden=stmt.hidden | statement_ids(then) | statement_ids(other),
                                rules=frozenset({"short-circuit"}),
                                origin=stmt.origin,
                            )
                        )
                        continue
            result.append(stmt)
        return result

    state.body = map_bodies(state.body, visit)


STIPEND = 2300


def eth_transfers(state: FunctionState) -> None:
    """solc's .transfer/.send: CALL(gas = value == 0 ? 2300 : 0 ... ) with no input/output.

    gas is `!value * 2300` (the stipend is added by the EVM only when value != 0;
    solc passes 2300 when value == 0). Followed by require(success) it is .transfer,
    otherwise .send. The rule is recorded on the line; the call itself is unchanged.
    """

    def gas_matches(gas: Expr | None, value: Expr | None) -> bool:
        if gas is None or value is None:
            return False
        if isinstance(gas, Binary) and gas.op == "*":
            for a, b in ((gas.left, gas.right), (gas.right, gas.left)):
                if isinstance(b, Const) and b.value == STIPEND and a == negate(value):
                    return True
        return isinstance(gas, Const) and gas.value == 0

    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        index = 0
        while index < len(statements):
            stmt = statements[index]
            call = stmt.value if isinstance(stmt, Assign) else None
            output = stmt.meta.get("output") if isinstance(stmt, Assign) else None
            if (
                isinstance(call, ExternalCallExpr)
                and call.kind == "call"
                and call.method is None
                and isinstance(call.raw_input, Slice)
                and call.raw_input.start == call.raw_input.end
                and output is not None
                and isinstance(output[1], Const)
                and output[1].value == 0
                and gas_matches(call.gas, call.value)
            ):
                assert isinstance(stmt, Assign)
                following = statements[index + 1] if index + 1 < len(statements) else None
                success = stmt.targets[0]
                if (
                    isinstance(following, Require)
                    and following.condition == success
                    and (following.payload is None or following.payload == Env("returndata"))
                ):
                    transfer = ExternalCallExpr(
                        "eth-transfer",
                        call.target,
                        "transfer",
                        (call.value,),
                        evidence=call.all_evidence(),
                    )
                    result.append(
                        ExprStmt(
                            transfer,
                            evidence=stmt.evidence | following.evidence,
                            hidden=stmt.hidden | statement_ids(following),
                            rules=frozenset({"eth-transfer-idiom"}),
                            origin=stmt.origin,
                        )
                    )
                    index += 2
                    continue
                stmt.value = ExternalCallExpr(
                    "eth-send", call.target, "send", (call.value,), evidence=call.all_evidence()
                )
                stmt.rules = stmt.rules | {"eth-send-idiom"}
            result.append(stmt)
            index += 1
        return result

    state.body = map_bodies(state.body, visit)


def unused_call_results(state: FunctionState) -> None:
    """`v = f(...)` with v never read prints as the call statement alone."""
    uses = variable_uses(state.body)

    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        for stmt in statements:
            if (
                isinstance(stmt, Assign)
                and all(is_local(t) and not uses[t.name] for t in stmt.targets)
                and has_effect(stmt.value)
                and not isinstance(stmt.value, ExternalCallExpr)
            ):
                result.append(
                    ExprStmt(
                        stmt.value,
                        evidence=stmt.evidence,
                        hidden=stmt.hidden,
                        rules=stmt.rules,
                        uncertain=stmt.uncertain,
                        origin=stmt.origin,
                        note=stmt.note,
                    )
                )
                continue
            result.append(stmt)
        return result

    state.body = map_bodies(state.body, visit)


def constant_branches(state: FunctionState) -> None:
    """Branches whose condition the native analysis folded to a constant."""

    def truth(expr: Expr) -> bool | None:
        if isinstance(expr, Const):
            return bool(expr.value)
        if expr == Env("true"):
            return True
        if expr == Env("false"):
            return False
        return None

    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        for stmt in statements:
            if isinstance(stmt, If):
                value = truth(stmt.condition)
                if value is not None:
                    dead = stmt.otherwise if value else stmt.then
                    live = stmt.then if value else stmt.otherwise
                    ids = set(stmt.evidence) | set(stmt.condition.all_evidence())
                    for nested in iter_statements(dead):
                        ids |= statement_ids(nested)
                    state.elided.append(
                        Elision(
                            frozenset(ids), "branch never taken: condition is a native constant"
                        )
                    )
                    result.extend(live)
                    continue
            result.append(stmt)
        return result

    state.body = map_bodies(state.body, visit)


def repeated_checks(state: FunctionState) -> None:
    """require(c); require(c);  ->  one check (nothing runs in between)."""

    def visit(statements: list[Stmt]) -> list[Stmt]:
        result: list[Stmt] = []
        for stmt in statements:
            previous = result[-1] if result else None
            if (
                isinstance(stmt, Require)
                and isinstance(previous, Require)
                and previous.condition == stmt.condition
                and previous.payload == stmt.payload
                and previous.kind == stmt.kind
                and not has_effect(stmt.condition)
            ):
                previous.hidden = previous.hidden | statement_ids(stmt)
                continue
            result.append(stmt)
        return result

    state.body = map_bodies(state.body, visit)


def copy_propagation(state: FunctionState) -> None:
    """`a = b` between locals assigned exactly once: print b at a's uses."""
    assignments: Counter[str] = Counter()
    for stmt in iter_statements(state.body):
        if isinstance(stmt, (Assign, ParallelAssign)):
            for target in stmt.targets:
                if is_local(target):
                    assignments[target.name] += 1
    mapping: dict[str, Expr] = {}
    copies: set[int] = set()
    for stmt in iter_statements(state.body):
        if (
            isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and is_local(stmt.targets[0])
            and assignments[stmt.targets[0].name] == 1
            and is_local(stmt.value)
            and assignments[stmt.value.name] <= 1
            and not stmt.uncertain
        ):
            mapping[stmt.targets[0].name] = annotate(
                stmt.value, statement_ids(stmt), {"copy-propagation"}
            )
            copies.add(id(stmt))
    if not mapping:
        return
    # Resolve chains a = b, b = c.
    for name in list(mapping):
        seen = {name}
        value = mapping[name]
        while isinstance(value, Var) and value.name in mapping and value.name not in seen:
            seen.add(value.name)
            value = annotate(mapping[value.name], value.evidence)
        mapping[name] = value

    def visit(statements: list[Stmt]) -> list[Stmt]:
        kept = []
        for stmt in statements:
            if id(stmt) in copies:
                state.elided.append(
                    Elision(statement_ids(stmt), "copy of another local, propagated")
                )
                continue
            substitute_statement(stmt, mapping)
            kept.append(stmt)
        return kept

    state.body = map_bodies(state.body, visit)
