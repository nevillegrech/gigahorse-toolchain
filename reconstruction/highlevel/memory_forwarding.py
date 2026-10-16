"""Store-to-load forwarding for memory words in structured statement trees.

`MEM[a] = x; ...; y = MEM[a]` prints `y = x` when, on every path between them,
no write that may overlap [a, a+32) happens and `x` still denotes the same value
(it mentions no variable reassigned in between and reads no mutable state).
Addresses compare by symbolic base + constant offset; different bases may alias
unless one is a constant below the heap floor and the other a free-pointer value.
Branch joins keep only facts that hold on both arms; loops drop every fact their
body may invalidate.
"""

from __future__ import annotations

from dataclasses import replace

from .ir import (
    Assign,
    Call,
    Comment,
    Const,
    Env,
    Expr,
    ExprStmt,
    ExternalCallExpr,
    If,
    Index,
    Jump,
    Member,
    ParallelAssign,
    RawBlock,
    Slice,
    Stmt,
    Var,
    While,
    is_local,
)
from .memory_liveness import ANY, HEAP_FLOOR, AddressModel, FreePointerVersions, Range, size_of

# key: (base, offset) of a 32-byte word -> (stored value, its evidence)
Facts = dict[tuple[str | None, int], Expr]


def _stable(expr: Expr) -> bool:
    """Same value wherever it is printed later (no mutable reads, no effects)."""
    if isinstance(expr, (Const, Var)):
        return True
    if isinstance(expr, Env):
        return expr.name not in {"returndata"}
    if isinstance(expr, Index) and isinstance(expr.base, Env) and expr.base.name == "msg.data":
        return _stable(expr.key)  # calldata is immutable during the call
    if isinstance(expr, Member) and expr.name in {"length", "data"} and isinstance(expr.base, Var):
        return True  # calldata accessors of an argument
    if isinstance(expr, (Index, Member, ExternalCallExpr)):
        return False
    if isinstance(expr, Call) and expr.name in {"gasleft", "msize", "keccak256", "blockhash"}:
        return False
    if isinstance(expr, Call) and not (
        expr.name in {"address", "bool", "byte", "signextend", "addmod", "mulmod"}
        or expr.name.startswith(("uint", "int", "bytes"))
    ):
        return False
    return all(_stable(child) for child in expr.children())


def _names(expr: Expr) -> set[str]:
    result = set()
    if isinstance(expr, Var):
        result.add(expr.name)
    for child in expr.children():
        result |= _names(child)
    return result


def _overlaps(a: Range, b: Range) -> bool:
    from .memory_liveness import _intersects

    return _intersects(a, b)


class Forwarder:
    def __init__(self, model: AddressModel, callees: frozenset[str]):
        self.model = model
        self.callees = callees
        self.forwarded = 0
        # Consumers (IR statement ids) whose raw memory input became printed words.
        self.decoded: set[str] = set()

    def words(self, start: Expr, end: Expr, facts: Facts) -> tuple[Expr, ...] | None:
        """All 32-byte words of MEM[start:end] when each is a known stored value."""
        base, offset = self.model.split(start)
        end_base, end_offset = self.model.split(end)
        if base == ANY or base != end_base or (base and base.startswith("heap:@")):
            return None
        size = end_offset - offset
        if size <= 0 or size % 32 or size > 32 * 16:
            return None
        values = []
        for word in range(size // 32):
            value = facts.get((base, offset + 32 * word))
            if value is None:
                return None
            values.append(value)
        return tuple(values)

    def decode_consumer(self, stmt: Stmt, facts: Facts) -> None:
        from .ir import Emit, Return

        if (
            isinstance(stmt, Emit)
            and stmt.args
            and isinstance(stmt.args[-1], Slice)
            and stmt.origin
        ):
            data = stmt.args[-1]
            words = self.words(data.start, data.end, facts)
            if words is not None and len(stmt.args) - 1 == stmt.indexed:
                stmt.args = (
                    *stmt.args[:-1],
                    *(replace(w, evidence=w.evidence | data.all_evidence()) for w in words),
                )
                stmt.uncertain = None
                stmt.rules = stmt.rules | {"event-words-from-memory-forwarding"}
                self.decoded.add(stmt.origin)
        elif (
            isinstance(stmt, Return)
            and stmt.raw is not None
            and isinstance(stmt.raw, Slice)
            and stmt.origin
        ):
            words = self.words(stmt.raw.start, stmt.raw.end, facts)
            if words is not None:
                stmt.values = tuple(
                    replace(w, evidence=w.evidence | stmt.raw.all_evidence()) for w in words
                )
                stmt.raw = None
                stmt.rules = stmt.rules | {"return-words-from-memory-forwarding"}
                self.decoded.add(stmt.origin)

    # --- fact maintenance ----------------------------------------------------

    def kill_range(self, facts: Facts, written: Range) -> None:
        for key in list(facts):
            base, offset = key
            if _overlaps(Range(base, offset, 32), written):
                del facts[key]

    def kill_names(self, facts: Facts, names: set[str]) -> None:
        for key in list(facts):
            base = key[0]
            if base and base.split(":", 1)[-1] in names:
                del facts[key]
            elif _names(facts[key]) & names:
                del facts[key]

    def key(self, address: Expr) -> tuple[str | None, int] | None:
        base, offset = self.model.split(address)
        if base in {ANY, "at-least"} or (base and base.startswith("heap:@")):
            # Inlined free-pointer reads are distinct occurrences: never forwarded.
            return None
        return base, offset

    # --- rewriting -------------------------------------------------------------

    def rewrite(self, expr: Expr, facts: Facts) -> Expr:
        children = expr.children()
        if children:
            new = tuple(self.rewrite(child, facts) for child in children)
            if any(a is not b for a, b in zip(new, children, strict=True)):
                expr = expr.with_children(new)
        if (
            isinstance(expr, Index)
            and isinstance(expr.base, Env)
            and expr.base.name == "MEM"
            and not (isinstance(expr.key, Const) and expr.key.value == 0x40)
        ):
            # The pointer word itself is not forwarded: `v = MEM[64]` stays a
            # recognizable free-pointer read (and keeps its value number).
            key = self.key(expr.key)
            if key is not None and key in facts:
                value = facts[key]
                self.forwarded += 1
                return replace(
                    value,
                    evidence=value.evidence | expr.all_evidence(),
                    rules=value.rules | {"memory-forwarding"},
                )
        return expr

    def block(self, statements: list[Stmt], facts: Facts) -> Facts:
        for stmt in statements:
            facts = self.statement(stmt, facts)
        return facts

    def statement(self, stmt: Stmt, facts: Facts) -> Facts:
        if isinstance(stmt, Comment):
            return facts
        if isinstance(stmt, If):
            stmt.condition = self.rewrite(stmt.condition, facts)
            then = self.block(stmt.then, dict(facts))
            other = self.block(stmt.otherwise, dict(facts))
            return {k: v for k, v in then.items() if other.get(k) == v}
        if isinstance(stmt, While):
            killed = dict(facts)
            self.invalidate_body(stmt.body, killed)
            if stmt.condition is not None:
                stmt.condition = self.rewrite(stmt.condition, killed)
            self.block(stmt.body, dict(killed))
            return killed
        if isinstance(stmt, RawBlock):
            self.block(stmt.body, {})
            return {}
        if isinstance(stmt, Jump):
            return facts
        # Rewrite the reads this statement performs.
        self.decode_consumer(stmt, facts)
        self.rewrite_reads(stmt, facts)
        # Then apply its effects to the facts.
        self.apply_effects(stmt, facts)
        return facts

    def rewrite_reads(self, stmt: Stmt, facts: Facts) -> None:
        def f(expr: Expr) -> Expr:
            return self.rewrite(expr, facts)

        map_reads(stmt, f)

    def apply_effects(self, stmt: Stmt, facts: Facts) -> None:
        exprs = []
        if isinstance(stmt, Assign):
            exprs.append(stmt.value)
        elif isinstance(stmt, ExprStmt):
            exprs.append(stmt.expr)
        for expr in exprs:
            if self.calls_function(expr):
                facts.clear()
                return
        if isinstance(stmt, Assign):
            if isinstance(stmt.value, ExternalCallExpr):
                output = stmt.meta.get("output")
                if output is None:
                    facts.clear()
                else:
                    start, size = output
                    self.kill_range(
                        facts,
                        self.model.range(start, size.value if isinstance(size, Const) else None),
                    )
            for target in stmt.targets:
                if is_local(target):
                    self.kill_names(facts, {target.name})
                elif (
                    isinstance(target, Index)
                    and isinstance(target.base, Env)
                    and target.base.name in {"MEM", "MEM8"}
                ):
                    width = 32 if target.base.name == "MEM" else 1
                    written = self.model.range(target.key, width)
                    self.kill_range(facts, written)
                    key = self.key(target.key)
                    if key is not None and width == 32 and _stable(stmt.value):
                        facts[key] = stmt.value
        elif isinstance(stmt, ParallelAssign):
            self.kill_names(facts, {t.name for t in stmt.targets if isinstance(t, Var)})
        elif isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
            call = stmt.expr
            if (
                call.name in {"CALLDATACOPY", "RETURNDATACOPY", "MCOPY", "CODECOPY"}
                and len(call.args) == 3
            ):
                size = call.args[2]
                self.kill_range(
                    facts,
                    self.model.range(call.args[0], size.value if isinstance(size, Const) else None),
                )
        elif isinstance(stmt, ExprStmt) and isinstance(stmt.expr, ExternalCallExpr):
            output = stmt.meta.get("output")
            if output is None:
                facts.clear()
            else:
                start, size = output
                self.kill_range(
                    facts, self.model.range(start, size.value if isinstance(size, Const) else None)
                )

    def calls_function(self, expr: Expr) -> bool:
        if isinstance(expr, Call) and (expr.name in self.callees or expr.name.startswith("fn_")):
            return True
        if isinstance(expr, Call) and expr.name == "msize":
            return True
        return any(self.calls_function(child) for child in expr.children())

    def invalidate_body(self, statements: list[Stmt], facts: Facts) -> None:
        """Drop facts any statement in a loop body may invalidate (any iteration)."""
        from .passes import iter_statements

        for stmt in iter_statements(statements):
            scratch = dict(facts)
            self.apply_effects(stmt, scratch)
            for key in list(facts):
                if key not in scratch or scratch[key] is not facts[key]:
                    del facts[key]
            if isinstance(stmt, While) or isinstance(stmt, RawBlock):
                continue


def forward_memory(state, callees: frozenset[str]) -> set[str]:
    """Apply forwarding to a function body; returns consumers decoded into words."""
    from .passes import is_free_pointer_read, iter_statements

    free_pointer_vars = {
        stmt.targets[0].name
        for stmt in iter_statements(state.body)
        if isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and is_local(stmt.targets[0])
        and is_free_pointer_read(stmt.value)
    }
    # A local reassigned anywhere (loop variables) is not a stable base/value.
    assigned: dict[str, int] = {}
    for stmt in iter_statements(state.body):
        if isinstance(stmt, (Assign, ParallelAssign)):
            for target in stmt.targets:
                if is_local(target):
                    assigned[target.name] = assigned.get(target.name, 0) + 1
    versions = FreePointerVersions(state.body, callees)
    forwarder = Forwarder(AddressModel(free_pointer_vars, versions), callees)
    forwarder.block(state.body, {})
    _ = (HEAP_FLOOR, size_of)
    return forwarder.decoded


def map_reads(stmt: Stmt, f) -> None:
    """Apply f to every expression a statement evaluates (not to what it assigns)."""
    from .ir import Emit, Halt, Require, Return, Revert

    if isinstance(stmt, Assign):
        stmt.value = f(stmt.value)
        stmt.targets = tuple(
            replace(t, key=f(t.key)) if isinstance(t, Index) and not is_local(t) else t
            for t in stmt.targets
        )
        if "output" in stmt.meta:
            stmt.meta["output"] = tuple(f(e) for e in stmt.meta["output"])
    elif isinstance(stmt, ParallelAssign):
        stmt.values = tuple(f(v) for v in stmt.values)
    elif isinstance(stmt, ExprStmt):
        stmt.expr = f(stmt.expr)
        if "output" in stmt.meta:
            stmt.meta["output"] = tuple(f(e) for e in stmt.meta["output"])
    elif isinstance(stmt, Require):
        stmt.condition = f(stmt.condition)
        if stmt.payload is not None:
            stmt.payload = f(stmt.payload)
    elif isinstance(stmt, Return):
        stmt.values = tuple(f(v) for v in stmt.values)
        if stmt.raw is not None:
            stmt.raw = f(stmt.raw)
    elif isinstance(stmt, Revert) and stmt.payload is not None:
        stmt.payload = f(stmt.payload)
    elif isinstance(stmt, Emit):
        stmt.args = tuple(f(a) for a in stmt.args)
    elif isinstance(stmt, Halt) and stmt.operand is not None:
        stmt.operand = f(stmt.operand)
