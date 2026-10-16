"""Backward memory liveness over structured statement trees.

A memory write may be left out of the readable view only if no *printed*
statement can read its bytes before they are overwritten. Ranges are tracked
symbolically as (base, offset, size): constant addresses share base None; a
free-memory-pointer value or another local is its own base. Unknown sizes,
unknown bases and private calls are treated as possible reads of the write.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

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
    Var,
    While,
)

HEAP_FLOOR = 0x60
ANY = "any"
# Unknown address known to be >= start: `x + c` with x unknown. Memory beyond
# ~2**32 is unaffordable (quadratic gas), so such sums do not wrap below c.
AT_LEAST = "at-least"


@dataclass(frozen=True)
class Range:
    base: str | None  # None = absolute; "heap:..." free-pointer based; ANY = unknown
    start: int
    size: int | None  # None = unbounded
    # For heap bases: a lower bound of the base address (the pointer never
    # decreases under solc's allocator). Same base => same floor.
    floor: int = field(default=0x60, compare=False)
    # Heap bases only: (other version, d) meaning this base >= other base + d.
    above: tuple[tuple[str, int], ...] = field(default=(), compare=False)


def _ordered_apart(low: Range, high: Range) -> bool:
    """`high` starts at or after the end of `low` (different heap versions)."""
    if low.size is None:
        return False
    for version, delta in high.above:
        if version == low.base and delta + high.start >= low.start + low.size:
            return True
    return False


def _intersects(a: Range, b: Range) -> bool:
    if a.base == ANY or b.base == ANY:
        return True
    if (
        a.base
        and b.base
        and a.base != b.base
        and a.base.startswith("heap:")
        and b.base.startswith("heap:")
        and (_ordered_apart(a, b) or _ordered_apart(b, a))
    ):
        return False
    if a.base == AT_LEAST or b.base == AT_LEAST:
        bounded, other = (a, b) if a.base == AT_LEAST else (b, a)
        if other.base is None:
            return other.size is None or other.start + other.size > bounded.start
        return True
    if a.base == b.base:
        a_end = None if a.size is None else a.start + a.size
        b_end = None if b.size is None else b.start + b.size
        return (a_end is None or b.start < a_end) and (b_end is None or a.start < b_end)
    # Constant ranges below a heap range's floor cannot meet it.
    if a.base is None and b.base and b.base.startswith("heap:"):
        return a.size is None or a.start + a.size > max(b.floor, HEAP_FLOOR) + b.start
    if b.base is None and a.base and a.base.startswith("heap:"):
        return b.size is None or b.start + b.size > max(a.floor, HEAP_FLOOR) + a.start
    return True


def _subtract(live: Range, kill: Range) -> list[Range]:
    """Bytes of `live` not certainly overwritten by `kill`."""
    if kill.base in {ANY, AT_LEAST} or live.base != kill.base or kill.size is None:
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
    def __init__(self, free_pointer_vars: set[str], versions: FreePointerVersions | None = None):
        self.free_pointer_vars = free_pointer_vars
        self.versions = versions

    def range(self, start: Expr, size: int | None) -> Range:
        base, offset = self.split(start)
        if base == ANY:
            return Range(ANY, 0, None)
        if base == AT_LEAST:
            return Range(AT_LEAST, offset, None)
        if base and base.endswith("+?"):
            base, size = base[:-2], None  # inexact start: reaches from base+offset upwards
        floor = self.versions.floor.get(base, HEAP_FLOOR) if self.versions and base else HEAP_FLOOR
        above = (
            tuple(sorted(self.versions.relative.get(base, {}).items()))
            if self.versions and base
            else ()
        )
        return Range(base, offset, size, floor, above)

    def split(self, expr: Expr) -> tuple[str | None, int]:
        from .ir import Binary, Var

        if isinstance(expr, Const):
            return None, expr.value
        if isinstance(expr, Var):
            if self.versions is not None and expr.name in self.versions.var_version:
                version = self.versions.var_version[expr.name]
                if version in self.versions.constant:
                    return None, self.versions.constant[version]
                return version, 0
            prefix = "heap:" if expr.name in self.free_pointer_vars else "var:"
            return prefix + expr.name, 0
        if _is_free_pointer_read(expr):
            if self.versions is not None and id(expr) in self.versions.node_version:
                version = self.versions.node_version[id(expr)]
                if version in self.versions.constant:
                    return None, self.versions.constant[version]
                return version, 0
            return f"heap:@{id(expr)}", 0
        if isinstance(expr, Binary) and expr.op == "+":
            for base, extra in ((expr.left, expr.right), (expr.right, expr.left)):
                if isinstance(extra, Const) and extra.value < (1 << 64):
                    inner, offset = self.split(base)
                    if inner == ANY:
                        return AT_LEAST, extra.value
                    if inner == AT_LEAST:
                        return AT_LEAST, offset + extra.value
                    return inner, offset + extra.value
            # base + unknown non-negative term: at least the base's lower bound.
            for base in (expr.left, expr.right):
                inner, offset = self.split(base)
                if inner is None:
                    return AT_LEAST, offset
                if inner == AT_LEAST:
                    return AT_LEAST, offset
                if inner != ANY and inner.startswith("heap:") and not inner.endswith("+?"):
                    # Somewhere at or above base + offset: same version, inexact.
                    return inner + "+?", offset
                if inner != ANY and inner.endswith("+?"):
                    return inner, offset
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
                    result.append(
                        self.model.range(node.start, self.slice_size(node.start, node.end))
                    )
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

    def slice_size(self, start: Expr, end: Expr) -> int | None:
        size = size_of(start, end)
        if size is not None:
            return size
        start_base, start_offset = self.model.split(start)
        end_base, end_offset = self.model.split(end)
        exact = start_base not in {ANY, AT_LEAST} and not (start_base or "").endswith("+?")
        if exact and start_base == end_base and end_offset >= start_offset:
            return end_offset - start_offset
        return None

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
        if item.base is None or item.base == AT_LEAST:
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


class FreePointerVersions:
    """Value-number reads of the free-memory pointer (MEM[0x40]).

    Two reads see the same value when no statement between them may change the
    pointer word: a write to [0x40, 0x60), a write/copy to an unknown or low
    address, a call into another lifted function, or a merge of paths that
    changed it differently. Equal versions share an address base, so offsets
    from them are comparable; different versions may still alias.
    """

    def __init__(self, body: list[Stmt], callees: frozenset[str]):
        self.callees = callees
        self.var_version: dict[str, str] = {}
        self.node_version: dict[int, str] = {}
        # Versions whose pointer value is a known constant (set by MEM[64] = c).
        self.constant: dict[str, int] = {}
        # Lower bounds of each version's pointer value (monotonic allocator).
        self.floor: dict[str, int] = {}
        # relative[b][a] = d: version b's pointer >= version a's pointer + d.
        self.relative: dict[str, dict[str, int]] = {}
        self.counter = 0
        self.walk(body, self.fresh())

    def fresh(self, floor: int = HEAP_FLOOR, above: dict[str, int] | None = None) -> str:
        self.counter += 1
        version = f"heap:fp#{self.counter}"
        self.floor[version] = floor
        self.relative[version] = dict(above or {})
        return version

    def above(self, version: str, delta: int = 0) -> dict[str, int]:
        """Relations of a pointer >= version + delta (inherits version's relations)."""
        result = {version: delta}
        for other, d in self.relative.get(version, {}).items():
            result[other] = max(result.get(other, d + delta), d + delta)
        return result

    def walk(self, statements: list[Stmt], current: str) -> str:
        for stmt in statements:
            current = self.statement(stmt, current)
        return current

    def statement(self, stmt: Stmt, current: str) -> str:
        from .passes import read_expressions

        if isinstance(stmt, If):
            self.visit(stmt.condition, current)
            then = self.walk(stmt.then, current)
            other = self.walk(stmt.otherwise, current)
            if then == other:
                return then
            left, right = self.above(then), self.above(other)
            common = {k: min(v, right[k]) for k, v in left.items() if k in right}
            common.setdefault(current, 0)
            return self.fresh(
                min(self.floor.get(then, HEAP_FLOOR), self.floor.get(other, HEAP_FLOOR)), common
            )
        if isinstance(stmt, While):
            changes = self.changes_pointer(stmt.body)
            floor = self.floor.get(current, HEAP_FLOOR)
            head = self.fresh(floor, self.above(current)) if changes else current
            if stmt.condition is not None:
                self.visit(stmt.condition, head)
            self.walk(stmt.body, head)
            return self.fresh(floor, self.above(current)) if changes else current
        if isinstance(stmt, RawBlock):
            self.walk(stmt.body, self.fresh())
            return self.fresh()
        for expr in read_expressions(stmt):
            self.visit(expr, current)
        if (
            isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], Var)
            and stmt.targets[0].ssa is not None
            and _is_free_pointer_read(stmt.value)
        ):
            self.var_version[stmt.targets[0].name] = current
        if not self.changes_pointer([stmt]):
            return current
        floor = self.floor.get(current, HEAP_FLOOR)
        if (
            isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], Index)
            and _is_free_pointer_read(stmt.targets[0])
        ):
            value = stmt.value
            if isinstance(value, Const):
                version = self.fresh(value.value)
                self.constant[version] = value.value
                return version
            # New pointer = (known pointer or constant) + non-negative terms.
            bound = self.lower_bound(value)
            return self.fresh(bound if bound is not None else HEAP_FLOOR, self.relations_of(value))
        # Calls and other updates only move the pointer up (allocator discipline).
        return self.fresh(floor, self.above(current))

    def relations_of(self, expr: Expr) -> dict[str, int]:
        """For pointer = version + c + (non-negative terms): relations version + c."""
        from .ir import Binary

        terms: list[Expr] = []

        def collect(node: Expr) -> None:
            if isinstance(node, Binary) and node.op == "+":
                collect(node.left)
                collect(node.right)
            else:
                terms.append(node)

        collect(expr)
        constant = sum(t.value for t in terms if isinstance(t, Const))
        result: dict[str, int] = {}
        for term in terms:
            version = None
            if isinstance(term, Var):
                version = self.var_version.get(term.name)
            elif _is_free_pointer_read(term):
                version = self.node_version.get(id(term))
            if version is not None:
                for other, delta in self.above(version, constant).items():
                    result[other] = max(result.get(other, delta), delta)
        return result

    def lower_bound(self, expr: Expr) -> int | None:
        from .ir import Binary

        terms: list[Expr] = []

        def collect(node: Expr) -> None:
            if isinstance(node, Binary) and node.op == "+":
                collect(node.left)
                collect(node.right)
            else:
                terms.append(node)

        collect(expr)
        best: int | None = None
        constant = 0
        for term in terms:
            if isinstance(term, Const):
                constant += term.value
                continue
            version = None
            if isinstance(term, Var):
                version = self.var_version.get(term.name)
            elif _is_free_pointer_read(term):
                version = self.node_version.get(id(term))
            if version is not None:
                bound = self.constant.get(version, self.floor.get(version, HEAP_FLOOR))
                best = bound if best is None else max(best, bound)
        if best is None:
            return None
        return best + constant

    def visit(self, expr: Expr, current: str) -> None:
        if _is_free_pointer_read(expr):
            self.node_version[id(expr)] = current
        for child in expr.children():
            self.visit(child, current)

    def changes_pointer(self, statements: list[Stmt]) -> bool:
        from .ir import ExprStmt
        from .passes import iter_expr, iter_statements, read_expressions

        for stmt in iter_statements(statements):
            for expr in read_expressions(stmt):
                for node in iter_expr(expr):
                    if isinstance(node, Call) and (
                        node.name in self.callees or node.name.startswith("fn_")
                    ):
                        return True
            if isinstance(stmt, Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, Index)
                        and isinstance(target.base, Env)
                        and target.base.name in {"MEM", "MEM8"}
                    ):
                        if not self.surely_misses_pointer(target.key):
                            return True
            if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
                if stmt.expr.name in {"CALLDATACOPY", "RETURNDATACOPY", "MCOPY", "CODECOPY"}:
                    if not self.surely_misses_pointer(stmt.expr.args[0]):
                        return True
        return False

    def surely_misses_pointer(self, address: Expr) -> bool:
        """A write starting here cannot touch [0x40, 0x60) (heap or scratch-only)."""
        from .ir import Binary

        if isinstance(address, Const):
            return address.value >= 0x60 or address.value + 32 <= 0x40
        base = address
        while isinstance(base, Binary) and base.op == "+" and isinstance(base.right, Const):
            base = base.left
        if _is_free_pointer_read(base):
            return True
        return isinstance(base, Var) and base.name in self.var_version


def observes_under_discipline(live: Live, write: Range) -> bool:
    """Observation check for consumer-linked ABI-encoding temporaries.

    Under solc's memory discipline a temporary written at the free pointer for a
    consumer is not read after that consumer except through the same pointer
    value; reads through unknown or other-version heap pointers refer to other
    (allocated or freshly written) memory. Same-base and constant overlaps still
    count. This is an explicit assumption, recorded on every elision it enables.
    """
    for item in live.ranges:
        if item.base == ANY or item.base == UNKNOWN_HEAP.base:
            continue
        if (
            item.base != write.base
            and item.base
            and write.base
            and item.base.startswith("heap:")
            and write.base.startswith("heap:")
        ):
            continue
        if _intersects(item, write):
            return True
    return False
