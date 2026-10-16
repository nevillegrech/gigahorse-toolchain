"""Solidity ABI coders recovered from their compiled statement sequences.

solc compiles `abi.decode`, `abi.encode` and `abi.encodePacked` into fixed
statement sequences: for 0.8 the Yul ABI utility functions
(`abi_decode_t_struct`, `allocate_memory`, `abi_decode_available_length_t_bytes`,
...), for older versions the legacy code generator. Each recognizer below walks
such a sequence statement by statement and compares every statement with the
step solc emits. Expressions are compared in a canonical form: linear
arithmetic normalized, free-pointer reads resolved to the value the pointer
holds at that point, calldata accessors expanded. Anything unexpected leaves
the statements as they are.

A recognized sequence becomes one statement. The replaced statements are kept
as that line's evidence. The interpreter executes the printed construct itself,
with the same checks in the same order, the same allocations at the free
pointer and the same bytes written, so the execution tests compare the
recognized form (not the original statements) with the EVM.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from itertools import pairwise

from .ir import (
    AbiCodec,
    Assign,
    Binary,
    Call,
    Const,
    Env,
    Expr,
    ExprStmt,
    ExternalCallExpr,
    If,
    Index,
    Member,
    MemoryBytes,
    ParallelAssign,
    RawBlock,
    Require,
    Slice,
    Stmt,
    Unary,
    Var,
    While,
    annotate,
    is_local,
)
from .passes import (
    FunctionState,
    has_effect,
    is_free_pointer_read,
    iter_statements,
    map_bodies,
    statement_ids,
)
from .simplify import simplify

WORD = (1 << 256) - 1
U64 = (1 << 64) - 1
NOT31 = WORD ^ 31
MSGDATA = ("env", "msg.data")
COMMUTATIVE = {"&", "|", "^", "==", "!=", "*", "&&", "||"}
VALIDATED = (
    {"address", "bool"}
    | {f"uint{n}" for n in range(8, 256, 8)}
    | {f"int{n}" for n in range(8, 257, 8)}
    | {f"bytes{n}" for n in range(1, 32)}
)

Form = tuple


# --- canonical forms ----------------------------------------------------------


def _lin(terms: dict[Form, int], const: int) -> Form:
    terms = {atom: coeff & WORD for atom, coeff in terms.items() if coeff & WORD}
    const &= WORD
    if not terms:
        return ("const", const)
    if const == 0 and len(terms) == 1:
        ((atom, coeff),) = terms.items()
        if coeff == 1:
            return atom
    return ("lin", tuple(sorted(terms.items(), key=repr)), const)


def _parts(form: Form) -> tuple[dict[Form, int], int]:
    if form[0] == "const":
        return {}, form[1]
    if form[0] == "lin":
        return dict(form[1]), form[2]
    return {form: 1}, 0


def add(a: Form, b: Form, sign: int = 1) -> Form:
    terms, const = _parts(a)
    other, extra = _parts(b)
    terms = dict(terms)
    for atom, coeff in other.items():
        terms[atom] = terms.get(atom, 0) + sign * coeff
    return _lin(terms, const + sign * extra)


def plus(form: Form, constant: int) -> Form:
    return add(form, ("const", constant & WORD))


def _scale(form: Form, factor: int) -> Form:
    terms, const = _parts(form)
    return _lin({atom: coeff * factor for atom, coeff in terms.items()}, const * factor)


def constant_of(form: Form) -> int | None:
    return form[1] if form[0] == "const" else None


class Tracker:
    """Free-pointer and local-value facts along one straight-line statement list.

    `fp` is the canonical value of MEM[0x40] (None: unknown). A read of an
    unknown pointer introduces a fresh base atom, so later reads compare equal
    while no write intervenes. `env` binds locals to the canonical values they
    hold: free-pointer reads and effect-free values that read no memory.
    """

    def __init__(self, dynamic: frozenset[str]):
        self.dynamic = dynamic
        self.env: dict[str, Form] = {}
        self.fp: Form | None = None
        self.bases: set[Form] = set()
        self.fresh = 0

    def copy(self) -> Tracker:
        other = Tracker(self.dynamic)
        other.env, other.fp = dict(self.env), self.fp
        other.bases, other.fresh = set(self.bases), self.fresh
        return other

    def adopt(self, other: Tracker) -> None:
        self.env, self.fp, self.bases, self.fresh = other.env, other.fp, other.bases, other.fresh

    def current_fp(self) -> Form:
        if self.fp is None:
            self.fp = ("fp", self.fresh)
            self.fresh += 1
            self.bases.add(self.fp)
        return self.fp

    def canon(self, expr: Expr) -> Form:
        if isinstance(expr, Const):
            return ("const", expr.value & WORD)
        if isinstance(expr, Var):
            return self.env.get(expr.name, ("var", expr.name))
        if is_free_pointer_read(expr):
            return self.current_fp()
        if isinstance(expr, Member):
            if (
                isinstance(expr.base, Var)
                and expr.base.name in self.dynamic
                and expr.name in {"data", "length"}
            ):
                base = self.canon(expr.base)
                return plus(base, 32) if expr.name == "data" else ("idx", MSGDATA, base)
            return ("member", self.canon(expr.base), expr.name)
        if isinstance(expr, Call):
            if (
                expr.name == "word"
                and len(expr.args) == 2
                and isinstance(expr.args[0], Member)
                and expr.args[0].name == "data"
            ):
                return ("idx", MSGDATA, add(self.canon(expr.args[0]), self.canon(expr.args[1])))
            return ("call", expr.name, tuple(self.canon(a) for a in expr.args))
        if isinstance(expr, Binary):
            left, right = self.canon(expr.left), self.canon(expr.right)
            if expr.op == "+":
                return add(left, right)
            if expr.op == "-":
                return add(left, right, -1)
            if expr.op == "*" and (left[0] == "const" or right[0] == "const"):
                factor, other = (left, right) if left[0] == "const" else (right, left)
                return _scale(other, factor[1])
            if expr.op in COMMUTATIVE:
                left, right = sorted((left, right), key=repr)
            return ("bin", expr.op, left, right)
        if isinstance(expr, Unary):
            return ("un", expr.op, self.canon(expr.operand))
        if isinstance(expr, Index):
            return ("idx", self.canon(expr.base), self.canon(expr.key))
        if isinstance(expr, Env):
            return ("env", expr.name)
        if isinstance(expr, Slice):
            return ("slice", expr.space, self.canon(expr.start), self.canon(expr.end))
        # Opaque: never equal to anything else.
        return ("opaque", id(expr))

    def heap_safe(self, address: Form) -> bool:
        """A word written here cannot touch the free pointer (solc keeps it >= 0x80)."""
        terms, const = _parts(address)
        if not terms:
            return const >= 0x60 or const + 32 <= 0x40
        if len(terms) == 1:
            ((atom, coeff),) = terms.items()
            return coeff == 1 and atom in self.bases and const < (1 << 64)
        return False

    def observe(self, stmt: Stmt) -> None:
        """Update the facts after a statement outside any recognized sequence."""
        if isinstance(stmt, Assign):
            if isinstance(stmt.value, ExternalCallExpr):
                for target in stmt.targets:
                    if is_local(target):
                        self.env.pop(target.name, None)
                output = stmt.meta.get("output")
                if output is not None and not self.heap_safe(self.canon(output[0])):
                    self.fp = None
                return
            if has_effect(stmt.value):
                # A private call (or other effect) may move the free pointer.
                for target in stmt.targets:
                    if is_local(target):
                        self.env.pop(target.name, None)
                self.fp = None
                return
            if len(stmt.targets) == 1 and is_local(stmt.targets[0]):
                name = stmt.targets[0].name
                if is_free_pointer_read(stmt.value):
                    self.env[name] = self.current_fp()
                elif _memoryless(stmt.value):
                    self.env[name] = self.canon(stmt.value)
                else:
                    self.env.pop(name, None)
                return
            if len(stmt.targets) == 1 and is_free_pointer_read(stmt.targets[0]):
                self.fp = self.canon(stmt.value)
                return
            for target in stmt.targets:
                if is_local(target):
                    self.env.pop(target.name, None)
                elif _memory_target(target):
                    if not self.heap_safe(self.canon(target.key)):
                        self.fp = None
                elif not isinstance(target, Var):
                    self.fp = None
            return
        if isinstance(stmt, ExprStmt):
            expr = stmt.expr
            if isinstance(expr, Call) and expr.name in {
                "CALLDATACOPY",
                "MCOPY",
                "CODECOPY",
                "RETURNDATACOPY",
            }:
                if not self.heap_safe(self.canon(expr.args[0])):
                    self.fp = None
                return
            if not isinstance(expr, ExternalCallExpr):
                self.fp = None
            return
        if isinstance(stmt, ParallelAssign):
            for target in stmt.targets:
                if is_local(target):
                    self.env.pop(target.name, None)
            if any(has_effect(v) for v in stmt.values):
                self.fp = None
            return
        if isinstance(stmt, (If, While, RawBlock)):
            for nested in iter_statements([stmt]):
                if isinstance(nested, Assign):
                    for target in nested.targets:
                        if is_local(target):
                            self.env.pop(target.name, None)
            self.fp = None


def _memory_target(expr: Expr) -> bool:
    return (
        isinstance(expr, Index) and isinstance(expr.base, Env) and expr.base.name in {"MEM", "MEM8"}
    )


def _memoryless(expr: Expr) -> bool:
    """Effect-free and independent of memory and call results: its value never changes."""
    for node in _walk(expr):
        if isinstance(node, (ExternalCallExpr, AbiCodec, Slice)):
            return False
        if isinstance(node, Index) and isinstance(node.base, Env) and node.base.name != "msg.data":
            return False
        if isinstance(node, Env) and node.name in {"returndata", "MEM", "MEM8"}:
            return False
        if isinstance(node, Member) and node.name == "length" and isinstance(node.base, Env):
            return False
        if isinstance(node, Call) and not (
            node.name.startswith(("uint", "int", "bytes", "address", "bool")) or node.name == "word"
        ):
            return False
    return True


def _walk(expr: Expr):
    yield expr
    for child in expr.children():
        yield from _walk(child)


# --- statement shapes -------------------------------------------------------------


def _check(stmt: Stmt, op: str, payload: str | None = None) -> tuple[Expr, Expr] | None:
    """(left, right) of `require(left <op> right[, payload])`."""
    if not isinstance(stmt, Require) or stmt.kind != "require":
        return None
    if payload is None and stmt.payload is not None:
        return None
    if payload is not None and not _is_panic(stmt.payload, payload):
        return None
    condition = stmt.condition
    if isinstance(condition, Binary) and condition.op == op:
        return condition.left, condition.right
    return None


def _is_panic(payload: Expr | None, code: str) -> bool:
    return (
        isinstance(payload, Call)
        and payload.name == "Panic"
        and len(payload.args) == 1
        and isinstance(payload.args[0], Const)
        and payload.args[0].value == int(code, 16)
    )


def _store(stmt: Stmt) -> tuple[Expr, Expr] | None:
    """(address, value) of a 32-byte memory store `MEM[address] = value`."""
    if (
        isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], Index)
        and isinstance(stmt.targets[0].base, Env)
        and stmt.targets[0].base.name == "MEM"
        and not is_free_pointer_read(stmt.targets[0])
    ):
        return stmt.targets[0].key, stmt.value
    return None


def _pointer_update(stmt: Stmt) -> Expr | None:
    if (
        isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and is_free_pointer_read(stmt.targets[0])
    ):
        return stmt.value
    return None


def _pointer_read(stmt: Stmt) -> Var | None:
    if (
        isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and is_local(stmt.targets[0])
        and is_free_pointer_read(stmt.value)
    ):
        target = stmt.targets[0]
        assert isinstance(target, Var)
        return target
    return None


def _copy(stmt: Stmt, name: str) -> tuple[Expr, Expr, Expr] | None:
    if (
        isinstance(stmt, ExprStmt)
        and isinstance(stmt.expr, Call)
        and stmt.expr.name == name
        and len(stmt.expr.args) == 3
    ):
        destination, source, size = stmt.expr.args
        return destination, source, size
    return None


def allocation_check(base: Expr, size: Expr) -> Expr:
    """solc's finalize_allocation guard, as the view prints it (reverts with Panic(0x41))."""
    end = Binary("+", base, size)
    return Unary("!", Binary("|", Binary(">", end, Const(U64)), Binary("<", end, base)))


def rounded(size: Expr) -> Expr:
    """round_up_to_mul_of_32(size)."""
    return Binary("&", Binary("+", size, Const(31)), Const(NOT31))


class Cursor:
    """Sequential access to a statement list with canonical comparisons."""

    def __init__(self, statements: list[Stmt], index: int, tracker: Tracker):
        self.statements, self.index, self.t = statements, index, tracker
        self.start = index

    def peek(self) -> Stmt | None:
        return self.statements[self.index] if self.index < len(self.statements) else None

    def take(self) -> Stmt:
        stmt = self.statements[self.index]
        self.index += 1
        return stmt

    def same(self, expr: Expr, form: Form) -> bool:
        return self.t.canon(expr) == form

    def consumed(self) -> list[Stmt]:
        return self.statements[self.start : self.index]


class NoMatch(Exception):
    pass


def expect(condition: bool) -> None:
    if not condition:
        raise NoMatch


@dataclass
class Rewrite:
    """A recognized sequence: replacement statements plus renamings for what follows."""

    end: int
    replacement: list[Stmt]
    expressions: dict[Form, Expr] = field(default_factory=dict)
    variables: dict[str, Expr] = field(default_factory=dict)


# --- abi.decode of a struct from calldata bytes (solc 0.8 Yul ABI decoder) -----------


def match_struct_decode(
    statements: list[Stmt], index: int, tracker: Tracker, context: CodecContext
) -> Rewrite | None:
    """`abi.decode(x, (S))` for calldata `bytes x` and a struct S with a dynamic member.

    abi_decode_tuple_t_struct(headStart = x.data, dataEnd = x.data + x.length):
      if slt(sub(dataEnd, headStart), 32) revert;  offset := calldataload(headStart)
      if gt(offset, 2**64-1) revert;  abi_decode_t_struct(headStart + offset, dataEnd)
    abi_decode_t_struct(start, end): if slt(sub(end, start), size) revert;
      value := allocate_memory(size); then each member in order (validated
      static words; bytes/string through abi_decode_t_bytes_memory_ptr).
    """
    t = tracker.copy()
    c = Cursor(statements, index, t)
    try:
        minimum = _check(c.take(), "s>=")
        expect(minimum is not None and isinstance(minimum[1], Const) and minimum[1].value == 32)
        assert minimum is not None
        offset_check = _check(c.take(), "<=")
        expect(offset_check is not None and _is_u64(offset_check[1]))
        assert offset_check is not None
        head_read = offset_check[0]
        expect(isinstance(head_read, Index) and _is_calldata(head_read))
        assert isinstance(head_read, Index)
        source_member = head_read.key
        expect(
            isinstance(source_member, Member)
            and source_member.name == "data"
            and isinstance(source_member.base, Var)
            and source_member.base.name in t.dynamic
        )
        assert isinstance(source_member, Member) and isinstance(source_member.base, Var)
        source = source_member.base
        expect(c.same(minimum[0], t.canon(Member(source, "length"))))
        head = t.canon(source_member)
        end = add(head, t.canon(Member(source, "length")))
        base = add(head, ("idx", MSGDATA, head))
        size_check = _check(c.take(), "s>=")
        expect(size_check is not None and isinstance(size_check[1], Const))
        assert size_check is not None
        size = size_check[1].value
        expect(0 < size <= 64 * 32 and size % 32 == 0 and c.same(size_check[0], add(end, base, -1)))
        # value := allocate_memory(size)
        constant_struct = None
        struct_var: Var | None = None
        stmt = c.take()
        update = _pointer_update(stmt)
        if update is not None and isinstance(update, Const):
            constant_struct = update.value - size
            expect(constant_struct >= 0x80)
            pointer = ("const", constant_struct)
            t.fp = ("const", update.value)
        else:
            struct_var = _pointer_read(stmt)
            expect(struct_var is not None)
            assert struct_var is not None
            t.observe(stmt)
            pointer = t.canon(struct_var)
            check = c.take()
            expect(
                isinstance(check, Require)
                and _is_panic(check.payload, "0x41")
                and c.same(check.condition, t.canon(allocation_check(struct_var, Const(size))))
            )
            update = _pointer_update(c.take())
            expect(update is not None and c.same(update, plus(pointer, size)))
            assert update is not None
            t.fp = t.canon(update)
        fields: list[str] = []
        heads: dict[int, Form] = {}
        lengths: dict[int, Form] = {}
        pointers: dict[str, int] = {}
        for k in range(size // 32):
            word = plus(base, 32 * k)
            read = ("idx", MSGDATA, word)
            slot = plus(pointer, 32 * k)
            stmt = c.peek()
            dynamic = _check(stmt, "<=") if stmt is not None else None
            if dynamic is not None and _is_u64(dynamic[1]) and c.same(dynamic[0], read):
                c.take()
                tail, data_pointer = _bytes_member(c, base, word, end)
                fields.append("bytes")
                lengths[k] = ("idx", MSGDATA, tail)
                pointers[data_pointer.name] = k
                stored = _store(c.take())
                expect(
                    stored is not None
                    and c.same(stored[0], slot)
                    and c.same(stored[1], t.canon(data_pointer))
                )
                continue
            kind = "uint256"
            validator = _check(stmt, "==") if stmt is not None else None
            if validator is not None:
                value, cleaned = validator
                expect(
                    isinstance(cleaned, Call)
                    and cleaned.name in VALIDATED
                    and len(cleaned.args) == 1
                    and c.same(value, read)
                    and c.same(cleaned.args[0], read)
                )
                assert isinstance(cleaned, Call)
                kind = cleaned.name
                c.take()
            stored = _store(c.take())
            expect(stored is not None and c.same(stored[0], slot) and c.same(stored[1], read))
            fields.append(kind)
            heads[k] = read
    except (NoMatch, IndexError):
        return None
    if "bytes" not in fields:
        # A static struct is encoded in place, without the offset word matched above.
        return None
    consumed = c.consumed()
    name = context.struct_name(fields)
    target_name = struct_var.name if struct_var is not None else context.fresh_local()
    target = Var(target_name, struct_var.ssa if struct_var is not None else f"abi:{target_name}")
    layout: tuple[tuple[str, object], ...] = (("solc", "0.8-yul-abi-decoder"),)
    if constant_struct is not None:
        layout += (("struct_pointer", constant_struct),)
    node = Assign(
        (target,),
        AbiCodec("decode", (source,), (f"{name}({','.join(fields)})",), layout),
        hidden=frozenset().union(*(statement_ids(s) for s in consumed)),
        rules=frozenset({"solc-abi-decode"}),
    )
    context.decoded_sources.add(source.name)
    expressions: dict[Form, Expr] = {}
    for k, form in heads.items():
        expressions[form] = Member(target, f"f{k}")
    for k, form in lengths.items():
        expressions[form] = Member(Member(target, f"f{k}"), "length")
    variables = {name: Member(target, f"f{k}") for name, k in pointers.items()}
    tracker.adopt(t)
    for name in pointers:
        tracker.env.pop(name, None)
    return Rewrite(c.index, [node], expressions, variables)


def _bytes_member(c: Cursor, base: Form, word: Form, end: Form) -> tuple[Form, Var]:
    """abi_decode_t_bytes_memory_ptr(base + offset, end); the offset check is consumed.

    if iszero(slt(add(offset, 0x1f), end)) revert;  length := calldataload(offset)
    array_allocation_size: if gt(length, 2**64-1) panic(0x41);  size := round(length) + 32
    array := allocate_memory(size);  mstore(array, length)
    if gt(add(src, length), end) revert;  calldatacopy(array + 32, src, length);
    mstore(array + 32 + length, 0)
    """
    t = c.t
    tail = add(base, ("idx", MSGDATA, word))
    bounds = _check(c.take(), "s<")
    expect(bounds is not None and c.same(bounds[0], plus(tail, 31)) and c.same(bounds[1], end))
    length = ("idx", MSGDATA, tail)
    limit = _check(c.take(), "<=", "0x41")
    expect(limit is not None and _is_u64(limit[1]) and c.same(limit[0], length))
    assert limit is not None
    length_expr = limit[0]
    stmt = c.take()
    array = _pointer_read(stmt)
    expect(array is not None)
    assert array is not None
    t.observe(stmt)
    pointer = t.canon(array)
    size = Binary("&", Binary("+", rounded(length_expr), Const(63)), Const(NOT31))
    check = c.take()
    expect(
        isinstance(check, Require)
        and _is_panic(check.payload, "0x41")
        and c.same(check.condition, t.canon(allocation_check(array, size)))
    )
    update = _pointer_update(c.take())
    expect(update is not None and c.same(update, add(pointer, t.canon(size))))
    assert update is not None
    t.fp = t.canon(update)
    stored = _store(c.take())
    expect(stored is not None and c.same(stored[0], pointer) and c.same(stored[1], length))
    overflow = _check(c.take(), "<=")
    expect(
        overflow is not None
        and c.same(overflow[0], add(plus(tail, 32), length))
        and c.same(overflow[1], end)
    )
    copied = _copy(c.take(), "CALLDATACOPY")
    expect(
        copied is not None
        and c.same(copied[0], plus(pointer, 32))
        and c.same(copied[1], plus(tail, 32))
        and c.same(copied[2], length)
    )
    cleanup = _store(c.take())
    expect(
        cleanup is not None
        and c.same(cleanup[0], add(plus(pointer, 32), length))
        and c.same(cleanup[1], ("const", 0))
    )
    return tail, array


def _is_u64(expr: Expr) -> bool:
    return isinstance(expr, Const) and expr.value == U64


def _is_calldata(expr: Index) -> bool:
    return isinstance(expr.base, Env) and expr.base.name == "msg.data"


# --- abi.encode of a struct literal (solc 0.8 legacy code generator) -------------------

MEMORY = ("env", "MEM")


def _value_type(expr: Expr, arguments: dict[str, str]) -> str:
    if isinstance(expr, Call) and expr.name in VALIDATED and len(expr.args) == 1:
        return expr.name
    if isinstance(expr, Var) and arguments.get(expr.name) in VALIDATED:
        return arguments[expr.name]
    return "uint256"


def match_struct_encode(
    statements: list[Stmt], index: int, tracker: Tracker, context: CodecContext
) -> Rewrite | None:
    """`abi.encode(S(m0, ..., mn))` for a struct literal with one `bytes` member.

    The struct is allocated without a check (`MEM[64] = MEM[64] + size`); a
    calldata `bytes` member is copied to memory first; then the encoding is
    written at the free pointer: the offset word 32, the member heads (the
    dynamic member's head is its offset in the struct), the bytes' length,
    data and a zero word, and finally the length word and the new free
    pointer (32 + the encoded size, a multiple of 32).
    """
    t = tracker.copy()
    c = Cursor(statements, index, t)
    try:
        update = _pointer_update(c.take())
        expect(update is not None)
        assert update is not None
        struct = t.current_fp()
        size = constant_of(add(t.canon(update), struct, -1))
        expect(size is not None and 0 < size <= 64 * 32 and size % 32 == 0)
        assert size is not None
        t.fp = plus(struct, size)
        copies: dict[Form, Var] = {}
        while True:
            saved = (c.index, t.copy())
            try:
                pointer, source = _calldata_copy(c, t)
            except (NoMatch, IndexError):
                c.index = saved[0]
                t.adopt(saved[1])
                break
            copies[pointer] = source
        stmt = c.take()
        buffer = _pointer_read(stmt)
        expect(buffer is not None)
        assert buffer is not None
        t.observe(stmt)
        start = t.canon(buffer)
        data = plus(start, 32)
        words: dict[int, Expr] = {}
        copied: dict[int, tuple[Form, Form]] = {}
        zeros: list[tuple[int, Form]] = []
        locals_read: set[str] = set()
        while True:
            stmt = c.peek()
            expect(stmt is not None)
            assert stmt is not None
            if _pointer_read(stmt) is not None:
                break
            c.take()
            stored = _store(stmt)
            moved = _copy(stmt, "MCOPY")
            if stored is not None:
                delta = add(t.canon(stored[0]), data, -1)
                offset = constant_of(delta)
                if offset is not None:
                    expect(offset not in words)
                    words[offset] = stored[1]
                    continue
                terms, const = _parts(delta)
                expect(len(terms) == 1 and c.same(stored[1], ("const", 0)))
                ((atom, coeff),) = terms.items()
                expect(coeff == 1)
                zeros.append((const, atom))
            elif moved is not None:
                offset = constant_of(add(t.canon(moved[0]), data, -1))
                expect(offset is not None and offset not in copied)
                assert offset is not None
                copied[offset] = (t.canon(moved[1]), t.canon(moved[2]))
            elif (
                isinstance(stmt, Assign)
                and len(stmt.targets) == 1
                and is_local(stmt.targets[0])
                and isinstance(stmt.value, Index)
                and isinstance(stmt.value.base, Env)
                and stmt.value.base.name == "MEM"
            ):
                # The bytes member's length, read back from its memory copy.
                t.env[stmt.targets[0].name] = ("idx", MEMORY, t.canon(stmt.value.key))
                locals_read.add(stmt.targets[0].name)
            else:
                raise NoMatch
        stmt = c.take()
        result = _pointer_read(stmt)
        expect(result is not None)
        assert result is not None
        t.observe(stmt)
        expect(t.canon(result) == start)
        count = size // 32
        expect(isinstance(words.get(0), Const) and words[0].value == 32)
        tail = 32 + size
        dynamic = [
            k
            for k in range(count)
            if isinstance(words.get(32 + 32 * k), Const) and words[32 + 32 * k].value == size
        ]
        expect(len(dynamic) == 1 and set(words) == {0, tail, *(32 + 32 * k for k in range(count))})
        member = dynamic[0]
        length_expr = words[tail]
        length = t.canon(length_expr)
        sources = [p for p in copies if length == ("idx", MEMORY, p)]
        expect(len(sources) == 1)
        pointer = sources[0]
        expect(copied == {tail + 32: (plus(pointer, 32), length)})
        expect(zeros == [(tail + 32, length)])
        total = plus(t.canon(rounded(length_expr)), tail + 32)
        stored = _store(c.take())
        expect(stored is not None and c.same(stored[0], start) and c.same(stored[1], total))
        update = _pointer_update(c.take())
        expect(update is not None and c.same(update, add(plus(start, 32), total)))
        assert update is not None
        t.fp = t.canon(update)
    except (NoMatch, IndexError):
        return None
    consumed = c.consumed()
    removed = {buffer.name, *locals_read} | {
        name for name, form in t.env.items() if form in copies and name not in {result.name}
    }
    if _read_after(statements[c.index :], removed - {result.name}):
        return None
    members: list[Expr] = []
    kinds: list[str] = []
    for k in range(count):
        if k == member:
            members.append(copies[pointer])
            kinds.append("bytes")
        else:
            value = words[32 + 32 * k]
            members.append(value)
            kinds.append(_value_type(value, context.arguments))
    name = context.struct_name(kinds)
    node = Assign(
        (result,),
        AbiCodec(
            "encode",
            (Call(name, tuple(members)),),
            (f"{name}({','.join(kinds)})",),
            (("solc", "0.8-legacy-struct-literal"), ("calldata_members", (member,))),
        ),
        hidden=frozenset().union(*(statement_ids(s) for s in consumed)),
        rules=frozenset({"solc-abi-encode"}),
    )
    tracker.adopt(t)
    variables: dict[str, Expr] = {}
    if buffer.name != result.name:
        variables[buffer.name] = result
    return Rewrite(c.index, [node], {}, variables)


def _calldata_copy(c: Cursor, t: Tracker) -> tuple[Form, Var]:
    """`q = MEM[64]; MEM[64] = q + (x.length + 31) / 32 * 32 + 32; MEM[q] = x.length;
    CALLDATACOPY(q + 32, x.data, x.length); MEM[q + 32 + x.length] = 0` (bytes calldata x)."""
    stmt = c.take()
    pointer_var = _pointer_read(stmt)
    expect(pointer_var is not None)
    assert pointer_var is not None
    t.observe(stmt)
    pointer = t.canon(pointer_var)
    update_stmt = c.take()
    length_stmt = c.peek()
    stored = _store(length_stmt) if length_stmt is not None else None
    expect(stored is not None)
    assert stored is not None
    length_expr = stored[1]
    expect(
        isinstance(length_expr, Member)
        and length_expr.name == "length"
        and isinstance(length_expr.base, Var)
        and length_expr.base.name in t.dynamic
    )
    assert isinstance(length_expr, Member) and isinstance(length_expr.base, Var)
    source = length_expr.base
    length = t.canon(length_expr)
    words = Binary("*", Binary("/", Binary("+", length_expr, Const(31)), Const(32)), Const(32))
    update = _pointer_update(update_stmt)
    expect(update is not None and c.same(update, plus(add(pointer, t.canon(words)), 32)))
    assert update is not None
    t.fp = t.canon(update)
    c.take()
    expect(c.same(stored[0], pointer))
    copied = _copy(c.take(), "CALLDATACOPY")
    expect(
        copied is not None
        and c.same(copied[0], plus(pointer, 32))
        and c.same(copied[1], t.canon(Member(source, "data")))
        and c.same(copied[2], length)
    )
    cleanup = _store(c.take())
    expect(
        cleanup is not None
        and c.same(cleanup[0], add(plus(pointer, 32), length))
        and c.same(cleanup[1], ("const", 0))
    )
    return pointer, source


def _read_after(statements: list[Stmt], names: set[str]) -> bool:
    if not names:
        return False
    for stmt in iter_statements(statements):
        exprs = [*stmt.expressions(), *stmt.meta.get("input", ()), *stmt.meta.get("output", ())]
        for expr in exprs:
            for node in _walk(expr):
                if isinstance(node, Var) and node.name in names:
                    return True
    return False


# --- ABI calls staged at the free pointer (solc 0.8 legacy code generator) -------------


def match_staged_call(
    statements: list[Stmt], index: int, tracker: Tracker, context: CodecContext
) -> Rewrite | None:
    """An ABI call whose input solc writes at the free pointer without moving it.

    `c = MEM[64]; MEM[c] = selector; MEM[c + 4 + 32i] = head_i; ...` with, for
    a `bytes memory b` argument, its offset as the head and then `L = MEM[b];
    MEM[c + 4 + o] = L; MCOPY(c + 4 + o + 32, b + 32, L); MEM[c + 4 + o + 32 + L]
    = 0`; then `d = MEM[64]` (the same pointer), an optional extcodesize check
    and the call with input MEM[d : end]. The printed arguments are checked
    against these heads; a `bytesAt(...)` marker becomes the bytes value `b`.
    """
    t = tracker.copy()
    c = Cursor(statements, index, t)
    try:
        stmt = c.take()
        pointer_var = _pointer_read(stmt)
        expect(pointer_var is not None)
        assert pointer_var is not None
        t.observe(stmt)
        start = t.canon(pointer_var)
        stored = _store(c.take())
        expect(stored is not None and c.same(stored[0], start) and isinstance(stored[1], Const))
        assert stored is not None and isinstance(stored[1], Const)
        selector = stored[1].value
        expect(selector >> 224 != 0 and selector & ((1 << 224) - 1) == 0)
        words: dict[int, Expr] = {}
        lengths: dict[str, Form] = {}
        copied: dict[int, tuple[Form, Form]] = {}
        zeros: list[tuple[int, Form]] = []
        while True:
            stmt = c.peek()
            expect(stmt is not None)
            assert stmt is not None
            if _pointer_read(stmt) is not None:
                break
            c.take()
            stored = _store(stmt)
            moved = _copy(stmt, "MCOPY")
            if stored is not None:
                delta = add(t.canon(stored[0]), start, -1)
                offset = constant_of(delta)
                if offset is not None:
                    expect(offset >= 4 and offset not in words)
                    words[offset] = stored[1]
                    continue
                terms, const = _parts(delta)
                expect(len(terms) == 1 and c.same(stored[1], ("const", 0)))
                ((atom, coeff),) = terms.items()
                expect(coeff == 1)
                zeros.append((const, atom))
            elif moved is not None:
                offset = constant_of(add(t.canon(moved[0]), start, -1))
                expect(offset is not None and offset not in copied)
                assert offset is not None
                copied[offset] = (t.canon(moved[1]), t.canon(moved[2]))
            elif (
                isinstance(stmt, Assign)
                and len(stmt.targets) == 1
                and is_local(stmt.targets[0])
                and isinstance(stmt.value, Index)
                and isinstance(stmt.value.base, Env)
                and stmt.value.base.name == "MEM"
            ):
                t.env[stmt.targets[0].name] = ("idx", MEMORY, t.canon(stmt.value.key))
                lengths[stmt.targets[0].name] = t.env[stmt.targets[0].name]
            else:
                raise NoMatch
        stmt = c.take()
        again = _pointer_read(stmt)
        expect(again is not None)
        assert again is not None
        t.observe(stmt)
        expect(t.canon(again) == start)
        checks: list[Stmt] = []
        while isinstance(c.peek(), Require) and _is_code_check(c.peek()):
            checks.append(c.take())
        call_stmt = c.take()
        expect(
            isinstance(call_stmt, Assign)
            and isinstance(call_stmt.value, ExternalCallExpr)
            and call_stmt.value.method is not None
            and call_stmt.value.raw_input is None
            and call_stmt.value.kind in {"call", "staticcall"}
            and "input" in call_stmt.meta
        )
        assert isinstance(call_stmt, Assign) and isinstance(call_stmt.value, ExternalCallExpr)
        call = call_stmt.value
        heads = 4 + 32 * len(call.args)
        expect({o for o in words if o < heads} == {4 + 32 * i for i in range(len(call.args))})
        end = plus(start, heads)
        arguments: list[Expr] = []
        tails = 0
        for i, arg in enumerate(call.args):
            head = words[4 + 32 * i]
            if isinstance(arg, Call) and arg.name in {"bytesAt", "dataAt"}:
                expect(isinstance(head, Const) and head.value == heads - 4 + tails)
                assert isinstance(head, Const)
                offset = 4 + head.value
                expect(c.same(arg.args[0], plus(start, offset)))
                length_expr = words.get(offset)
                expect(length_expr is not None)
                assert length_expr is not None
                length = t.canon(length_expr)
                expect(length[0] == "idx" and length[1] == MEMORY)
                data = length[2]
                expect(copied.get(offset + 32) == (plus(data, 32), length))
                expect((offset + 32, length) in zeros)
                expect(tails == 0)  # one dynamic argument: its tail ends the input
                end = add(plus(start, offset + 32), t.canon(rounded(length_expr)))
                tails = 1
                pointer = _expression_for(data, t, statements[: c.start])
                expect(pointer is not None)
                arguments.append(MemoryBytes(pointer, evidence=arg.all_evidence()))
            else:
                expect(c.same(arg, t.canon(head)))
                arguments.append(arg)
        expect(len(words) == len(call.args) + tails and len(copied) == tails == len(zeros))
        expect(
            c.same(call_stmt.meta["input"][0], start) and c.same(call_stmt.meta["input"][1], end)
        )
    except (NoMatch, IndexError):
        return None
    consumed = [s for s in c.consumed() if s is not call_stmt and s not in checks]
    removed = {pointer_var.name, again.name, *lengths}
    if _read_after(statements[c.index :], removed):
        return None
    fp = Index(Env("MEM"), Const(0x40))
    renamed = dict.fromkeys((pointer_var.name, again.name), fp)
    from .passes import substitute

    call_stmt.value = replace(call, args=tuple(arguments))
    call_stmt.meta = dict(call_stmt.meta)
    call_stmt.meta.pop("input")
    call_stmt.meta["selector"] = f"0x{selector >> 224:08x}"
    if "output" in call_stmt.meta:
        call_stmt.meta["output"] = tuple(substitute(e, renamed) for e in call_stmt.meta["output"])
    call_stmt.uncertain = None
    call_stmt.rules = call_stmt.rules | {"abi-input-verified", "staged-at-free-pointer"}
    call_stmt.hidden = call_stmt.hidden.union(*(statement_ids(s) for s in consumed))
    tracker.adopt(t)
    return Rewrite(c.index, [*checks, call_stmt])


def _is_code_check(stmt: Stmt | None) -> bool:
    return (
        isinstance(stmt, Require)
        and stmt.payload is None
        and isinstance(stmt.condition, Member)
        and stmt.condition.name == "length"
        and isinstance(stmt.condition.base, Member)
        and stmt.condition.base.name == "code"
    )


def _expression_for(form: Form, t: Tracker, before: list[Stmt]) -> Expr | None:
    """A printed local whose canonical value is `form` (the bytes value's pointer)."""
    for name, value in t.env.items():
        if value == form and any(
            isinstance(s, Assign) and any(isinstance(x, Var) and x.name == name for x in s.targets)
            for s in before
        ):
            return Var(name, f"abi:{name}")
    if form[0] == "var":
        return Var(form[1], f"abi:{form[1]}")
    return None


# --- keccak256(abi.encodePacked(...)) (legacy code generator) -------------------------


def _reads_pointer(expr: Expr) -> bool:
    return any(is_free_pointer_read(node) for node in _walk(expr))


def _packed_element(word: Expr, width: int) -> tuple[Expr, str] | None:
    """The value whose `width` bytes a left-aligned packed word holds, and its type."""
    shift = 256 - 8 * width
    if width == 32:
        return word, "bytes32"
    inner = word
    if isinstance(inner, Call) and inner.name == f"bytes{width}" and len(inner.args) == 1:
        inner = inner.args[0]
    if (
        isinstance(inner, Binary)
        and inner.op == "<<"
        and isinstance(inner.right, Const)
        and inner.right.value == shift
    ):
        if width == 20:
            return Call("address", (inner.left,)), "address"
        return Call(f"uint{8 * width}", (inner.left,)), f"uint{8 * width}"
    if isinstance(word, Const) and word.value & ((1 << shift) - 1) == 0:
        value = word.value >> shift
        if width == 20:
            return Const(value), "address"
        return Const(value), f"bytes{width}"
    return None


def match_packed_hash(
    statements: list[Stmt], index: int, tracker: Tracker, context: CodecContext
) -> Rewrite | None:
    """`h = keccak256(abi.encodePacked(e0, e1, ...))` for static elements.

    The legacy code generator writes each element as a left-aligned word at
    the free pointer + 32 + its offset (a later element overwrites the
    previous word's tail), then the length at the free pointer, moves the
    pointer to its end (not rounded) and hashes the data.
    """
    t = tracker.copy()
    c = Cursor(statements, index, t)
    try:
        data: list[tuple[Form, Expr]] = []
        while True:
            stmt = c.peek()
            stored = _store(stmt) if stmt is not None else None
            if stored is None or _reads_pointer(stored[0]) or _reads_pointer(stored[1]):
                break
            data.append((t.canon(stored[0]), stored[1]))
            c.take()
        expect(bool(data))
        stmt = c.peek()
        again = _pointer_read(stmt) if stmt is not None else None
        if again is not None:
            fresh = t.fp is None
            c.take()
            t.observe(stmt)
        else:
            fresh = t.fp is None
        stored = _store(c.take())
        expect(stored is not None)
        assert stored is not None
        buffer = t.canon(stored[0])
        expect(buffer == t.current_fp())
        total = constant_of(t.canon(stored[1]))
        expect(total is not None and 0 < total <= 32 * 32)
        assert total is not None
        update = _pointer_update(c.take())
        expect(update is not None)
        assert update is not None
        constant_buffer = None
        if fresh:
            # The data addresses were folded to constants: the buffer starts at
            # the new pointer minus the data, which the executed view checks.
            constant_buffer = constant_of(t.canon(update))
            expect(constant_buffer is not None)
            assert constant_buffer is not None
            constant_buffer -= 32 + total
            expect(constant_buffer >= 0x80)
            buffer = ("const", constant_buffer)
        else:
            expect(c.same(update, plus(buffer, 32 + total)))
        t.fp = plus(buffer, 32 + total)
        hashed = c.take()
        values = (
            [hashed.value]
            if isinstance(hashed, Assign) and len(hashed.targets) == 1
            else list(hashed.values)
            if isinstance(hashed, ParallelAssign)
            else []
        )
        hashes = [
            i
            for i, v in enumerate(values)
            if isinstance(v, Call)
            and v.name == "keccak256"
            and len(v.args) == 1
            and isinstance(v.args[0], Slice)
        ]
        expect(len(hashes) == 1 and all(is_local(x) for x in hashed.targets))
        position = hashes[0]
        digest = values[position]
        assert isinstance(digest, Call)
        region = digest.args[0]
        assert isinstance(region, Slice)
        start, end = t.canon(region.start), t.canon(region.end)
        if fresh:
            # The hashed range may itself read the (assumed) pointer.
            start = _rebase(start, t, buffer)
            end = _rebase(end, t, buffer)
        expect(start == plus(buffer, 32) and end == plus(buffer, 32 + total))
        offsets = [constant_of(add(address, plus(buffer, 32), -1)) for address, _ in data]
        expect(all(o is not None for o in offsets))
        expect(offsets[0] == 0 and all(a < b for a, b in pairwise(offsets)))
        widths = [b - a for a, b in zip(offsets, [*offsets[1:], total], strict=True)]
        expect(all(0 < w <= 32 for w in widths))
        elements: list[Expr] = []
        kinds: list[str] = []
        for (_, word), width in zip(data, widths, strict=True):
            element = _packed_element(word, width)
            expect(element is not None)
            assert element is not None
            elements.append(annotate(element[0], word.all_evidence()))
            kinds.append(element[1])
    except (NoMatch, IndexError):
        return None
    consumed = c.consumed()
    removed = {again.name} if again is not None else set()
    if _read_after(statements[c.index :], removed):
        return None
    layout: tuple[tuple[str, object], ...] = (("solc", "legacy-packed"),)
    if constant_buffer is not None:
        layout += (("buffer_pointer", constant_buffer),)
    packed = AbiCodec("encodePacked", tuple(elements), tuple(kinds), layout)
    value = Call("keccak256", (packed,), evidence=digest.evidence, rules=digest.rules)
    if isinstance(hashed, Assign):
        hashed.value = value
    else:
        assert isinstance(hashed, ParallelAssign)
        hashed.values = tuple(value if i == position else v for i, v in enumerate(values))
    hashed.hidden = hashed.hidden.union(*(statement_ids(s) for s in consumed if s is not hashed))
    hashed.rules = hashed.rules | {"solc-abi-encodePacked"}
    tracker.adopt(t)
    return Rewrite(c.index, [hashed])


def _rebase(form: Form, t: Tracker, buffer: Form) -> Form:
    """Replace fresh pointer atoms (reads assumed to see `buffer`) by the buffer."""
    terms, const = _parts(form)
    result: Form = ("const", const)
    for atom, coeff in terms.items():
        value = buffer if atom in t.bases and atom[0] == "fp" else atom
        result = add(result, _scale(value, coeff))
    return result


# --- driver -------------------------------------------------------------------------


@dataclass
class CodecContext:
    structs: dict[tuple[str, ...], str]
    used: set[str]
    arguments: dict[str, str] = field(default_factory=dict)
    decoded_sources: set[str] = field(default_factory=set)

    def struct_name(self, fields: list[str]) -> str:
        return self.structs.setdefault(tuple(fields), f"S{len(self.structs)}")

    def fresh_local(self) -> str:
        index = 0
        while f"v{index}" in self.used:
            index += 1
        self.used.add(f"v{index}")
        return f"v{index}"


RECOGNIZERS = (match_struct_decode, match_struct_encode, match_staged_call, match_packed_hash)


def recognize_abi_coders(
    state: FunctionState,
    dynamic: frozenset[str],
    structs: dict[tuple[str, ...], str],
    arguments: dict[str, str] | None = None,
) -> set[str]:
    """Replace recognized ABI coder sequences; returns the calldata arguments decoded as bytes."""
    used = {
        node.name
        for stmt in iter_statements(state.body)
        for expr in (*stmt.expressions(),)
        for node in _walk(expr)
        if isinstance(node, Var)
    }
    context = CodecContext(structs, used, dict(arguments or {}))

    def visit(statements: list[Stmt]) -> list[Stmt]:
        tracker = Tracker(dynamic)
        result: list[Stmt] = []
        index = 0
        while index < len(statements):
            rewrite = None
            for recognizer in RECOGNIZERS:
                rewrite = recognizer(statements, index, tracker, context)
                if rewrite is not None:
                    break
            if rewrite is None:
                tracker.observe(statements[index])
                result.append(statements[index])
                index += 1
                continue
            result.extend(rewrite.replacement)
            rest = statements[rewrite.end :]
            if rewrite.expressions or rewrite.variables:
                _rename(rest, rewrite, dynamic)
            statements = result + rest
            index = len(result)
        return statements

    state.body = map_bodies(state.body, visit)
    return context.decoded_sources


def _rename(statements: list[Stmt], rewrite: Rewrite, dynamic: frozenset[str]) -> None:
    """Express later reads through the recognized construct (e.g. calldata words as fields)."""
    from .types import map_expr, map_statement_exprs

    t = Tracker(dynamic)

    def fn(expr: Expr) -> Expr:
        if isinstance(expr, Var) and expr.name in rewrite.variables:
            return annotate(rewrite.variables[expr.name], expr.evidence)
        if isinstance(expr, Index) and isinstance(expr.base, Env) and expr.base.name == "msg.data":
            replacement = rewrite.expressions.get(t.canon(expr))
            if replacement is not None:
                return replace(replacement, evidence=expr.all_evidence())
        return expr

    for stmt in iter_statements(statements):
        map_statement_exprs(stmt, fn)
        for key in ("input", "output"):
            if key in stmt.meta:
                stmt.meta[key] = tuple(simplify(map_expr(e, fn)) for e in stmt.meta[key])
