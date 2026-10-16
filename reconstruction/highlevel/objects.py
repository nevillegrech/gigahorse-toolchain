"""Memory objects: allocations at the free pointer printed as values.

solc allocates memory by reading the free pointer and moving it past the new
object (`allocate_memory`):

    v0 = MEM[64]; MEM[64] = v0 + 224;                    -> v0 = new struct(7)
    v2 = MEM[64]; MEM[64] = v2 + round(n) + 32;
        MEM[v2] = n;                                     -> v2 = new bytes(n)
        [CALLDATACOPY(v2 + 32, x.data, x.length);
         MEM[v2 + 32 + x.length] = 0;]                   -> v2 = x  (copied to memory)

Words at constant offsets from such a pointer print as fields (`v0.word3`,
`v2.length`); a struct whose words are all written right after the
allocation, with values that read no memory, prints as `struct(a, b, ...)`.
Where the analysis folded the pointer to a constant (`MEM[64] = 352`,
`MEM[160] = x`), the object's base is assumed to be solc's initial free
pointer 0x80; the interpreter checks that when it executes the allocation
(rule assumes-folded-free-pointer).

This runs last, after every memory analysis, and only renames: a Field reads
and writes exactly MEM[base + offset], and an Allocation performs exactly the
statements it replaced, in their order.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .abi_codec import (
    NOT31,
    Form,
    Tracker,
    _pointer_read,
    _pointer_update,
    _store,
    _walk,
    add,
    constant_of,
)
from .ir import (
    Allocation,
    Assign,
    Binary,
    Call,
    Comment,
    Const,
    Emit,
    Env,
    Expr,
    ExprStmt,
    Field,
    Halt,
    If,
    Index,
    Member,
    MemoryBytes,
    ParallelAssign,
    Require,
    Return,
    Revert,
    Slice,
    Stmt,
    Var,
    While,
    annotate,
    is_local,
)
from .passes import FunctionState, has_effect, iter_statements, statement_ids
from .types import map_expr

INITIAL_POINTER = 0x80  # solc's free pointer before any allocation
MAX_WORDS = 64
WINDOW = 6


@dataclass
class _Object:
    name: str
    kind: str
    size: int | None  # struct: bytes
    assumed_base: int | None
    statement: Assign
    # The base address when it is a constant (MEM[64] was set to one, or the
    # folded initial pointer is assumed): constant addresses can name fields.
    constant_base: int | None = None


def _reads_memory(expr: Expr) -> bool:
    for node in _walk(expr):
        if isinstance(node, (Field, Slice, MemoryBytes)):
            return True
        if (
            isinstance(node, Index)
            and isinstance(node.base, Env)
            and node.base.name
            in {
                "MEM",
                "MEM8",
            }
        ):
            return True
        if isinstance(node, Env) and node.name in {"MEM", "MEM8"}:
            return True
    return False


def _quiet(stmt: Stmt) -> bool:
    """No effect, no memory access: may move across an allocation."""
    if isinstance(stmt, Assign):
        return (
            len(stmt.targets) == 1
            and is_local(stmt.targets[0])
            and not has_effect(stmt.value)
            and not _reads_memory(stmt.value)
        )
    if isinstance(stmt, Require):
        exprs = [stmt.condition] + ([stmt.payload] if stmt.payload is not None else [])
        return not any(has_effect(e) or _reads_memory(e) for e in exprs)
    return False


def _mentions(expr: Expr, name: str) -> bool:
    return any(isinstance(node, Var) and node.name == name for node in _walk(expr))


def _rounded_forms(length: Expr) -> list[Expr]:
    """solc's byte-array allocation sizes: round_up(length) + 32 (three spellings)."""
    plus31 = Binary("+", length, Const(31))
    masked = Binary("&", plus31, Const(NOT31))
    return [
        Binary("+", Binary("*", Binary("/", plus31, Const(32)), Const(32)), Const(32)),
        Binary("+", masked, Const(32)),
        Binary("&", Binary("+", masked, Const(63)), Const(NOT31)),
        Binary("&", Binary("+", length, Const(63)), Const(NOT31)),
    ]


def _keeps_pointer(stmt: Stmt) -> bool:
    """Cannot move the free pointer (memory reads and word stores are fine)."""
    if isinstance(stmt, Comment) or _store(stmt) is not None:
        return True
    if isinstance(stmt, Assign):
        return len(stmt.targets) == 1 and is_local(stmt.targets[0]) and not has_effect(stmt.value)
    if isinstance(stmt, ParallelAssign):
        return all(is_local(x) for x in stmt.targets) and not any(
            has_effect(v) for v in stmt.values
        )
    if isinstance(stmt, Require):
        return not has_effect(stmt.condition)
    if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
        return stmt.expr.name in {"CALLDATACOPY", "CODECOPY", "RETURNDATACOPY", "MCOPY"}
    if isinstance(stmt, If):
        return not has_effect(stmt.condition) and all(
            _keeps_pointer(s) for body in stmt.blocks() for s in body
        )
    return False


def _array_forms(length: Expr) -> list[Expr]:
    """solc's array allocation sizes: length * 32 + 32."""
    return [
        Binary("+", Binary("*", length, Const(32)), Const(32)),
        Binary("+", Binary("<<", length, Const(5)), Const(32)),
    ]


def _match(
    statements: list[Stmt],
    index: int,
    tracker: Tracker,
    assignments: Counter[str],
    entry: bool,
) -> tuple[list[Stmt], int, _Object, Tracker] | None:
    first = statements[index]
    pointer = _pointer_read(first)
    if pointer is None or assignments[pointer.name] != 1:
        return None
    t = tracker.copy()
    t.observe(first)
    base = t.canon(pointer)
    kept: list[Stmt] = []
    early: Stmt | None = None  # a word stored at the base before the pointer moves
    position = index + 1
    while position < len(statements) and position <= index + WINDOW:
        stmt = statements[position]
        if _pointer_update(stmt) is not None:
            break
        stored = _store(stmt)
        if early is None and stored is not None and t.canon(stored[0]) == base:
            early = stmt
        elif not _quiet(stmt):
            break
        else:
            kept.append(stmt)
        t.observe(stmt)
        position += 1
    if position >= len(statements):
        return None
    update_stmt = statements[position]
    update = _pointer_update(update_stmt)
    if update is None:
        return None
    end = t.canon(update)
    t.observe(update_stmt)
    consumed = [update_stmt]
    after = position + 1
    size = constant_of(add(end, base, -1))
    assumed = None
    # The pointer is still the one the dispatcher set (0x80) only at a public
    # entry point before anything could move it; checked when executed.
    folded = entry and base[0] == "fp" and base in t.bases
    if size is None and folded and constant_of(end) is not None:
        assumed = INITIAL_POINTER
        size = (constant_of(end) or 0) - INITIAL_POINTER
    if size is not None:
        if not (0 < size <= 32 * MAX_WORDS and size % 32 == 0):
            return None
        node = Allocation("struct", update, words=size // 32, assumed_base=assumed)
        obj = _Object(pointer.name, "struct", size, assumed, first)
        if early is not None:
            kept.insert(0, early)  # a word-0 write: it stays, after the allocation
    else:
        # new bytes(n) / new T[](n): a length word at the base, and a size from it.
        length_stmt = early
        if length_stmt is None and after < len(statements):
            stored = _store(statements[after])
            if stored is not None and t.canon(stored[0]) == base:
                length_stmt = statements[after]
                t.observe(length_stmt)
                after += 1
        if length_stmt is None:
            return None
        stored = _store(length_stmt)
        assert stored is not None
        length = stored[1]
        if has_effect(length) or _reads_memory(length) or _mentions(length, pointer.name):
            return None
        consumed.append(length_stmt)
        added = add(end, base, -1)
        if any(t.canon(form) == added for form in _rounded_forms(length)):
            kind = "bytes"
        elif any(t.canon(form) == added for form in _array_forms(length)):
            kind = "array"
        else:
            return None
        node = Allocation(kind, update, length=length)
        obj = _Object(pointer.name, kind, None, None, first)
        fill = _fill(statements, after, t, base, kind, length, folded)
        if fill is not None:
            moved, (space, source, copied, pad), consumed_fill, after, assumed = fill
            kept.extend(moved)
            consumed.extend(consumed_fill)
            for stmt in [*moved, *consumed_fill]:
                t.observe(stmt)
            node = Allocation(
                kind,
                update,
                length=length,
                copy=(source, copied),
                pad=pad,
                assumed_base=assumed,
                copy_space=space,
            )
            obj.assumed_base = assumed
    rules = {"memory-object"} | ({"assumes-folded-free-pointer"} if node.assumed_base else set())
    allocation = Assign(
        (pointer,),
        annotate(node, rules=frozenset(rules)),
        evidence=first.evidence,
        hidden=first.hidden.union(*(statement_ids(s) for s in consumed)),
        rules=first.rules | frozenset(rules),
        origin=first.origin,
    )
    if node.copy is not None:
        allocation.note = {
            "calldata": f"calldata {'array' if node.kind == 'array' else 'bytes'} copied to memory",
            "returndata": "returned data copied to memory",
        }[node.copy_space]
    obj.statement = allocation
    if obj.assumed_base is not None:
        obj.constant_base = obj.assumed_base
    elif base[0] == "const":
        obj.constant_base = base[1]
    # t: the facts after the replaced statements (the pointer is now `end`).
    return [allocation, *kept], after, obj, t


def _fill(
    statements: list[Stmt],
    index: int,
    t: Tracker,
    base: Form,
    kind: str,
    length: Expr,
    folded: bool,
):
    """The data copied in right after the length word (after quiet code):
    CALLDATACOPY(base + 32, x.data, size) for a calldata argument, or
    RETURNDATACOPY(base + 32, 0, returndata.length); then maybe a zero word.
    (Zeroing `new T[](n)` from past the end of calldata is already removed as
    a no-op on fresh memory by the memory passes.)"""
    moved: list[Stmt] = []
    position = index
    while position < len(statements) and _quiet(statements[position]) and len(moved) < WINDOW:
        moved.append(statements[position])
        position += 1
    if position >= len(statements):
        return None
    stmt = statements[position]
    if not (
        isinstance(stmt, ExprStmt)
        and isinstance(stmt.expr, Call)
        and stmt.expr.name in {"CALLDATACOPY", "RETURNDATACOPY"}
        and len(stmt.expr.args) == 3
    ):
        return None
    destination, source, size = stmt.expr.args
    sizes = (
        [length]
        if kind == "bytes"
        else [Binary("*", length, Const(32)), Binary("<<", length, Const(5))]
    )
    if not any(t.canon(size) == t.canon(s) for s in sizes):
        return None
    if stmt.expr.name == "RETURNDATACOPY":
        if not (
            kind == "bytes"
            and isinstance(source, Const)
            and source.value == 0
            and isinstance(length, Member)
            and isinstance(length.base, Env)
            and length.base.name == "returndata"
        ):
            return None
        space = "returndata"
    elif isinstance(source, Member) and source.name == "data" and is_local(source.base):
        space = "calldata"
    else:
        return None
    assumed = None
    data = add(base, ("const", 32))
    if t.canon(destination) != data:
        constant = constant_of(t.canon(destination))
        if not (folded and constant == INITIAL_POINTER + 32):
            return None
        assumed = INITIAL_POINTER
        data = ("const", constant)
    consumed = [stmt]
    pad = False
    following = position + 1
    if following < len(statements):
        stored = _store(statements[following])
        if (
            stored is not None
            and isinstance(stored[1], Const)
            and stored[1].value == 0
            and t.canon(stored[0]) == add(data, t.canon(size))
        ):
            consumed.append(statements[following])
            pad = True
            following += 1
    return moved, (space, source, size, pad), consumed, following, assumed


def _find(
    statements: list[Stmt],
    tracker: Tracker,
    assignments: Counter[str],
    objects: dict[str, _Object],
    scopes: dict[str, list[Stmt]],
    entry: bool,
) -> list[Stmt]:
    result: list[Stmt] = []
    index = 0
    while index < len(statements):
        match = _match(statements, index, tracker, assignments, entry)
        if match is not None:
            replacement, index, obj, after = match
            objects[obj.name] = obj
            tracker.adopt(after)
            entry = False
            # Constant addresses are renamed only where the allocation dominates.
            scopes[obj.name] = statements[index:]
            result.extend(replacement)
            continue
        stmt = statements[index]
        for body in stmt.blocks():
            body[:] = _find(body, tracker.copy(), assignments, objects, scopes, entry)
        if isinstance(stmt, If) and _keeps_pointer(stmt):
            # Neither branch moves the pointer: only the locals they assign change.
            for nested in iter_statements([stmt]):
                for target in getattr(nested, "targets", ()):
                    if is_local(target):
                        tracker.env.pop(target.name, None)
        else:
            tracker.observe(stmt)
        entry = entry and _keeps_pointer(stmt)
        result.append(stmt)
        index += 1
    return result


def _field(obj: _Object, offset: int, evidence) -> Field | None:
    if obj.kind in {"bytes", "array"} and offset == 0:
        return Field(Var(obj.name, None), 0, "length", evidence=evidence)
    if obj.kind == "array" and offset >= 32 and offset % 32 == 0:
        return Field(Var(obj.name, None), offset, f"[{offset // 32 - 1}]", evidence=evidence)
    if obj.kind in {"bytes", "array"}:
        return None
    assert obj.size is not None
    if 0 <= offset < obj.size and offset % 32 == 0:
        return Field(Var(obj.name, None), offset, f"word{offset // 32}", evidence=evidence)
    return None


def _relative(key: Expr) -> tuple[str, int] | None:
    if isinstance(key, Var) and is_local(key):
        return key.name, 0
    if isinstance(key, Binary) and key.op == "+":
        for a, b in ((key.left, key.right), (key.right, key.left)):
            if isinstance(a, Var) and is_local(a) and isinstance(b, Const):
                return a.name, b.value
    return None


def _map_statement(stmt: Stmt, fn) -> None:
    """Rewrite a statement's own expressions (not nested bodies); locals stay bound."""
    if isinstance(stmt, Assign):
        stmt.targets = tuple(t if is_local(t) else map_expr(t, fn) for t in stmt.targets)
        stmt.value = map_expr(stmt.value, fn)
    elif isinstance(stmt, ParallelAssign):
        stmt.values = tuple(map_expr(v, fn) for v in stmt.values)
    elif isinstance(stmt, ExprStmt):
        stmt.expr = map_expr(stmt.expr, fn)
    elif isinstance(stmt, Require):
        stmt.condition = map_expr(stmt.condition, fn)
        if stmt.payload is not None:
            stmt.payload = map_expr(stmt.payload, fn)
    elif isinstance(stmt, (If, While)) and stmt.condition is not None:
        stmt.condition = map_expr(stmt.condition, fn)
    elif isinstance(stmt, Return):
        stmt.values = tuple(map_expr(v, fn) for v in stmt.values)
        if stmt.raw is not None:
            stmt.raw = map_expr(stmt.raw, fn)
    elif isinstance(stmt, Revert) and stmt.payload is not None:
        stmt.payload = map_expr(stmt.payload, fn)
    elif isinstance(stmt, Emit):
        stmt.args = tuple(map_expr(a, fn) for a in stmt.args)
    elif isinstance(stmt, Halt) and stmt.operand is not None:
        stmt.operand = map_expr(stmt.operand, fn)


def _rename(statements: list[Stmt], objects: dict[str, _Object], constants: dict[int, tuple]):
    """MEM[p + c] -> p.wordN everywhere; MEM[A] -> p.wordN for constant-base objects in scope."""

    def fn(expr: Expr) -> Expr:
        if not (isinstance(expr, Index) and isinstance(expr.base, Env) and expr.base.name == "MEM"):
            return expr
        relative = _relative(expr.key)
        if relative is not None and relative[0] in objects:
            obj = objects[relative[0]]
            field = _field(obj, relative[1], expr.all_evidence())
            return field if field is not None else expr
        if isinstance(expr.key, Const) and expr.key.value in constants:
            obj, offset = constants[expr.key.value]
            field = _field(obj, offset, expr.all_evidence())
            return field if field is not None else expr
        return expr

    for stmt in iter_statements(statements):
        _map_statement(stmt, fn)


def _literals(statements: list[Stmt], objects: dict[str, _Object]) -> list[Stmt]:
    """`p = new struct(k)` followed by writes of all k words: `p = struct(values)`."""
    result: list[Stmt] = []
    index = 0
    while index < len(statements):
        stmt = statements[index]
        for body in stmt.blocks():
            body[:] = _literals(body, objects)
        obj = None
        if isinstance(stmt, Assign) and len(stmt.targets) == 1 and is_local(stmt.targets[0]):
            obj = objects.get(stmt.targets[0].name)
        node = stmt.value if isinstance(stmt, Assign) else None
        if obj is None or not isinstance(node, Allocation) or node.kind != "struct":
            result.append(stmt)
            index += 1
            continue
        assert node.words is not None
        values: dict[int, Expr] = {}
        moved: list[Stmt] = []
        writes: list[Stmt] = []
        position = index + 1
        while position < len(statements) and len(values) < node.words:
            other = statements[position]
            target = other.targets[0] if isinstance(other, Assign) and other.targets else None
            if (
                isinstance(target, Field)
                and isinstance(target.base, Var)
                and target.base.name == obj.name
                and len(other.targets) == 1
                and target.offset // 32 not in values
                and not has_effect(other.value)
                and not _reads_memory(other.value)
                and not _mentions(other.value, obj.name)
            ):
                values[target.offset // 32] = other.value
                writes.append(other)
            elif _quiet(other) and not any(_mentions(e, obj.name) for e in other.expressions()):
                moved.append(other)
            else:
                break
            position += 1
        if len(values) != node.words or node.words > 16:
            result.append(stmt)
            index += 1
            continue
        ordered = tuple(values[i] for i in range(node.words))
        text = _constant_bytes(ordered)
        literal = Allocation(
            "struct",
            node.end,
            words=node.words,
            values=ordered,
            assumed_base=node.assumed_base,
            text=text,
            evidence=node.evidence,
            rules=node.rules | {"string-literal" if text is not None else "struct-literal"},
        )
        if text is not None:
            obj.kind = "bytes-literal"
        stmt.value = literal
        stmt.hidden = stmt.hidden.union(*(statement_ids(w) for w in writes))
        result.extend(moved)
        result.append(stmt)
        index = position
    return result


def _constant_bytes(values: tuple[Expr, ...]) -> bytes | None:
    """The bytes of `length, data...` words laid out exactly as a bytes/string constant."""
    if len(values) < 2 or not all(isinstance(v, Const) for v in values):
        return None
    length = values[0].value  # type: ignore[attr-defined]
    if not (0 < length <= 32 * (len(values) - 1)) or (length + 31) // 32 != len(values) - 1:
        return None
    data = b"".join(v.value.to_bytes(32, "big") for v in values[1:])  # type: ignore[attr-defined]
    if any(data[length:]):
        return None
    return data[:length]


def _relabel_lengths(statements: list[Stmt], names: set[str]) -> None:
    """word0 of a bytes constant is its length."""

    def fn(expr: Expr) -> Expr:
        if (
            isinstance(expr, Field)
            and expr.offset == 0
            and isinstance(expr.base, Var)
            and expr.base.name in names
        ):
            return Field(expr.base, 0, "length", evidence=expr.evidence, rules=expr.rules)
        return expr

    for stmt in iter_statements(statements):
        _map_statement(stmt, fn)


def memory_objects(state: FunctionState, public: bool) -> None:
    assignments: Counter[str] = Counter(
        target.name
        for stmt in iter_statements(state.body)
        if isinstance(stmt, (Assign, ParallelAssign))
        for target in stmt.targets
        if is_local(target)
    )
    objects: dict[str, _Object] = {}
    scopes: dict[str, list[Stmt]] = {}
    state.body = _find(state.body, Tracker(frozenset()), assignments, objects, scopes, public)
    if not objects:
        return
    _rename(state.body, objects, {})
    for name, obj in objects.items():
        if obj.constant_base is None:
            continue
        offsets = range(0, obj.size, 32) if obj.size is not None else range(1)
        constants = {obj.constant_base + offset: (obj, offset) for offset in offsets}
        _rename(scopes[name], {}, constants)
    state.body = _literals(state.body, objects)
    constants = {name for name, obj in objects.items() if obj.kind == "bytes-literal"}
    if constants:
        _relabel_lengths(state.body, constants)
