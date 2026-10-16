"""Backward memory liveness over structured statement trees.

A memory write may be left out of the readable view only if no *printed*
statement can read its bytes before they are overwritten. Ranges are tracked
symbolically as (base, offset, size): constant addresses share base None; a
free-memory-pointer value or another local is its own base. Unknown sizes,
unknown bases and private calls are treated as possible reads of the write.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .ir import (
    Assign,
    Call,
    Const,
    Env,
    Expr,
    ExternalCallExpr,
    Halt,
    If,
    Index,
    Jump,
    RawBlock,
    Return,
    Revert,
    Stmt,
    While,
)

HEAP_FLOOR = 0x60
ANY = "any"


@dataclass(frozen=True)
class Range:
    base: str | None  # None = absolute; "heap:..." free-pointer based; ANY = unknown
    start: int
    size: int | None  # None = unbounded


def _intersects(a: Range, b: Range) -> bool:
    if a.base == ANY or b.base == ANY:
        return True
    if a.base == b.base:
        a_end = None if a.size is None else a.start + a.size
        b_end = None if b.size is None else b.start + b.size
        return (a_end is None or b.start < a_end) and (b_end is None or a.start < b_end)
    # Constant ranges below the heap floor cannot meet free-pointer-based ranges.
    if a.base is None and b.base and b.base.startswith("heap:"):
        return a.size is None or a.start + a.size > HEAP_FLOOR
    if b.base is None and a.base and a.base.startswith("heap:"):
        return b.size is None or b.start + b.size > HEAP_FLOOR
    return True


def _subtract(live: Range, kill: Range) -> list[Range]:
    """Bytes of `live` not certainly overwritten by `kill`."""
    if kill.base in {ANY} or live.base != kill.base or kill.size is None:
        return [live]
    k_start, k_end = kill.start, kill.start + kill.size
    if live.size is None:
        if k_start <= live.start < k_end:
            return [Range(live.base, k_end, None)]
        return [live]
    l_start, l_end = live.start, live.start + live.size
    if k_end <= l_start or l_end <= k_start:
        return [live]
    pieces = []
    if l_start < k_start:
        pieces.append(Range(live.base, l_start, k_start - l_start))
    if k_end < l_end:
        pieces.append(Range(live.base, k_end, l_end - k_end))
    return pieces


class Live:
    def __init__(self, ranges: Iterable[Range] = ()):
        self.ranges: frozenset[Range] = frozenset(ranges)

    def union(self, other: Live) -> Live:
        return Live(self.ranges | other.ranges)

    def kill(self, write: Range) -> Live:
        result: set[Range] = set()
        for item in self.ranges:
            result.update(_subtract(item, write))
        return Live(result)

    def add(self, ranges: Iterable[Range]) -> Live:
        return Live(self.ranges | frozenset(ranges))

    def observes(self, write: Range) -> bool:
        return any(_intersects(item, write) for item in self.ranges)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Live) and self.ranges == other.ranges

    def __hash__(self) -> int:
        return hash(self.ranges)


class AddressModel:
    def __init__(self, free_pointer_vars: set[str]):
        self.free_pointer_vars = free_pointer_vars

    def range(self, start: Expr, size: int | None) -> Range:
        base, offset = self.split(start)
        if base == ANY:
            return Range(ANY, 0, None)
        return Range(base, offset, size)

    def split(self, expr: Expr) -> tuple[str | None, int]:
        from .ir import Binary, Var

        if isinstance(expr, Const):
            return None, expr.value
        if isinstance(expr, Var):
            prefix = "heap:" if expr.name in self.free_pointer_vars else "var:"
            return prefix + expr.name, 0
        if _is_free_pointer_read(expr):
            return f"heap:@{id(expr)}", 0
        if isinstance(expr, Binary) and expr.op == "+":
            for base, extra in ((expr.left, expr.right), (expr.right, expr.left)):
                if isinstance(extra, Const) and extra.value < (1 << 64):
                    inner, offset = self.split(base)
                    if inner != ANY:
                        return inner, offset + extra.value
        return ANY, 0


def _is_free_pointer_read(expr: Expr) -> bool:
    return (
        isinstance(expr, Index)
        and isinstance(expr.base, Env)
        and expr.base.name == "MEM"
        and isinstance(expr.key, Const)
        and expr.key.value == 0x40
    )


def size_of(start: Expr, end: Expr) -> int | None:
    from .ir import Binary

    if end == start:
        return 0
    if (
        isinstance(end, Binary)
        and end.op == "+"
        and end.left == start
        and isinstance(end.right, Const)
    ):
        return end.right.value
    if isinstance(end, Const) and isinstance(start, Const):
        return max(end.value - start.value, 0)
    return None


class Liveness:
    """Compute, for each statement, memory possibly read later by printed statements."""

    def __init__(
        self,
        model: AddressModel,
        ignored_reads: set[int],
        absorbed_origins: set[str],
        callees: frozenset[str] = frozenset(),
        summaries: Summaries | None = None,
        function: str | None = None,
    ):
        self.model = model
        # Names of lifted functions. Without summaries a call may read any memory.
        self.callees = callees
        self.summaries = summaries
        self.function = function
        self.ignored_reads = ignored_reads  # id(stmt) whose reads are absorbed/hidden
        self.absorbed_origins = absorbed_origins
        self.after: dict[int, Live] = {}

    # Reads and writes of a single statement's own expressions.
    def reads(self, stmt: Stmt) -> list[Range]:
        from .ir import Slice
        from .passes import iter_expr, read_expressions

        if id(stmt) in self.ignored_reads or (stmt.origin in self.absorbed_origins):
            exprs: tuple[Expr, ...] = ()
            # Absorbed consumers still evaluate their printed arguments.
            exprs = tuple(e for e in read_expressions(stmt) if not isinstance(e, Slice))
        else:
            exprs = read_expressions(stmt)
        result: list[Range] = []
        for expr in exprs:
            for node in iter_expr(expr):
                if (
                    isinstance(node, Index)
                    and isinstance(node.base, Env)
                    and node.base.name in {"MEM", "MEM8"}
                ):
                    result.append(self.model.range(node.key, 32))
                elif isinstance(node, Slice) and node.space == "MEM":
                    result.append(self.model.range(node.start, size_of(node.start, node.end)))
                elif isinstance(node, Call):
                    if node.name == "MCOPY" and len(node.args) == 3:
                        size = node.args[2].value if isinstance(node.args[2], Const) else None
                        result.append(self.model.range(node.args[1], size))
                    elif node.name in self.callees and self.summaries is not None:
                        result.extend(self.summaries.entry_of(node.name).ranges)
                    elif (
                        node.name in self.callees
                        or node.name.startswith("fn_")
                        or node.name == "private_call_unresolved"
                    ):
                        result.append(Range(ANY, 0, None))
                elif isinstance(node, ExternalCallExpr) and node.raw_input is None and node.method:
                    pass  # ABI arguments are printed values, not memory
        return result

    def writes(self, stmt: Stmt) -> list[Range]:
        result: list[Range] = []
        if isinstance(stmt, Assign):
            for target in stmt.targets:
                if isinstance(target, Index) and isinstance(target.base, Env):
                    if target.base.name == "MEM":
                        result.append(self.model.range(target.key, 32))
                    elif target.base.name == "MEM8":
                        result.append(self.model.range(target.key, 1))
        from .ir import ExprStmt

        if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
            call = stmt.expr
            if (
                call.name in {"CALLDATACOPY", "CODECOPY", "RETURNDATACOPY", "MCOPY"}
                and len(call.args) == 3
            ):
                size = call.args[2].value if isinstance(call.args[2], Const) else None
                result.append(self.model.range(call.args[0], size))
        return result

    def block(self, statements: list[Stmt], live_out: Live, loop: tuple[Live, Live] | None) -> Live:
        live = live_out
        for stmt in reversed(statements):
            live = self.statement(stmt, live, loop)
        return live

    def statement(self, stmt: Stmt, live_out: Live, loop: tuple[Live, Live] | None) -> Live:
        """loop = (live at loop head, live after loop)."""
        self.after[id(stmt)] = live_out
        if isinstance(stmt, If):
            then_live = self.block(stmt.then, live_out, loop)
            else_live = self.block(stmt.otherwise, live_out, loop)
            return then_live.union(else_live).add(self.reads(stmt))
        if isinstance(stmt, While):
            head = Live()
            for _ in range(32):
                body = self.block(stmt.body, head, (head, live_out))
                # The condition is read on entry and each iteration; exit flows to live_out.
                new_head = body.union(live_out).add(self.reads(stmt))
                if new_head == head:
                    break
                head = new_head
            else:
                head = Live([Range(ANY, 0, None)])
            self.block(stmt.body, head, (head, live_out))
            return head
        if isinstance(stmt, Jump):
            if loop is None:
                return Live([Range(ANY, 0, None)])
            return loop[0] if stmt.kind == "continue" else loop[1]
        if isinstance(stmt, RawBlock):
            # Unstructured code: assume anything may be read.
            self.block(stmt.body, Live([Range(ANY, 0, None)]), None)
            return Live([Range(ANY, 0, None)])
        if isinstance(stmt, Return) and "internal-return" in stmt.rules:
            # The caller continues and may read memory this function wrote.
            after = (
                self.summaries.return_of(self.function)
                if self.summaries is not None and self.function is not None
                else Live([Range(ANY, 0, None)])
            )
            return after.add(self.reads(stmt))
        if isinstance(stmt, Return) and "tail-call" in stmt.rules:
            # The callee's reads are included via the call expression's summary.
            if self.summaries is None:
                return Live([Range(ANY, 0, None)]).add(self.reads(stmt))
            return Live(self.reads(stmt))
        if isinstance(stmt, (Return, Revert, Halt)):
            # The transaction ends; only this statement's own reads matter.
            return Live(self.reads(stmt))
        live = live_out
        for write in self.writes(stmt):
            live = live.kill(write)
        return live.add(self.reads(stmt))


UNKNOWN_HEAP = Range("heap:?", 0, None)
EVERYTHING = Range(ANY, 0, None)


def widen(live: Live) -> Live:
    """Make a function-local live set meaningful in another function.

    Constant ranges keep their bytes; free-pointer-based ranges become "some heap
    address" (still disjoint from scratch space and the pointer word); any other
    base is unknown everywhere.
    """
    result: set[Range] = set()
    for item in live.ranges:
        if item.base is None:
            result.add(item)
        elif item.base.startswith("heap:"):
            result.add(UNKNOWN_HEAP)
        else:
            result.add(EVERYTHING)
    return Live(result)


class Summaries:
    """Interprocedural memory-read summaries over the printed function bodies.

    entry[f]: memory possibly read (before being overwritten) once f is called.
    returns[f]: memory possibly read by any caller after f returns to it.
    Computed as a monotone fixpoint; non-convergence widens to EVERYTHING.
    """

    def __init__(self) -> None:
        self.entry: dict[str, Live] = {}
        self.returns: dict[str, Live] = {}

    def entry_of(self, name: str) -> Live:
        return self.entry.get(name, Live())

    def return_of(self, name: str) -> Live:
        return self.returns.get(name, Live())


def compute_summaries(
    functions: dict[str, tuple[list[Stmt], AddressModel]], rounds: int = 24
) -> Summaries:
    from .passes import iter_expr, iter_statements, read_expressions

    summaries = Summaries()
    names = frozenset(functions)
    for _ in range(rounds):
        entry: dict[str, Live] = {}
        returns: dict[str, Live] = {name: Live() for name in functions}
        for name, (body, model) in functions.items():
            liveness = Liveness(model, set(), set(), names, summaries, name)
            entry[name] = widen(liveness.block(body, Live(), None))
            for stmt in iter_statements(body):
                for expr in read_expressions(stmt):
                    for node in iter_expr(expr):
                        if isinstance(node, Call) and node.name in functions:
                            after = liveness.after.get(id(stmt), Live([EVERYTHING]))
                            returns[node.name] = returns[node.name].union(widen(after))
        if entry == summaries.entry and returns == summaries.returns:
            return summaries
        summaries.entry, summaries.returns = entry, returns
    widened = Summaries()
    widened.entry = {name: Live([EVERYTHING]) for name in functions}
    widened.returns = {name: Live([EVERYTHING]) for name in functions}
    return widened
