"""Tree IR for the readable view.

Every node carries the IR statement ids it was built from (`evidence`). The
printer turns those into per-line bytecode offsets, so a simplification never
detaches a printed construct from the instructions that justify it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

Evidence = frozenset[str]
EMPTY: Evidence = frozenset()


@dataclass(frozen=True)
class Expr:
    evidence: Evidence = field(default=EMPTY, kw_only=True, compare=False)
    # Rewrite rules applied to produce this node; recorded in the line map.
    rules: frozenset[str] = field(default=frozenset(), kw_only=True, compare=False)

    def children(self) -> tuple[Expr, ...]:
        return ()

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return self

    def all_evidence(self) -> Evidence:
        result = set(self.evidence)
        for child in self.children():
            result |= child.all_evidence()
        return frozenset(result)

    def all_rules(self) -> frozenset[str]:
        result = set(self.rules)
        for child in self.children():
            result |= child.all_rules()
        return frozenset(result)

    def size(self) -> int:
        return 1 + sum(child.size() for child in self.children())

    def variables(self) -> set[str]:
        result: set[str] = set()
        for child in self.children():
            result |= child.variables()
        return result


def is_local(expr: Expr) -> bool:
    """A printed local/argument (bound to SSA), as opposed to a storage field root."""
    return isinstance(expr, Var) and (expr.ssa is not None or expr.name == "_")


def annotate(
    expr: Expr, evidence: Evidence = EMPTY, rules: frozenset[str] | set[str] = frozenset()
) -> Expr:
    if not evidence and not rules:
        return expr
    return replace(expr, evidence=expr.evidence | evidence, rules=expr.rules | frozenset(rules))


@dataclass(frozen=True)
class Const(Expr):
    value: int

    @property
    def text(self) -> str:
        return render_number(self.value)


@dataclass(frozen=True)
class Var(Expr):
    """A printed local, argument or other named value bound to SSA variables."""

    name: str
    ssa: str | None = None
    # Declared type once inferred (e.g. "address"); not part of identity.
    typed: str | None = field(default=None, compare=False)

    def variables(self) -> set[str]:
        return {self.ssa} if self.ssa else set()


@dataclass(frozen=True)
class Env(Expr):
    """Environment value such as msg.sender; `width` is its proven bit width."""

    name: str
    width: int = 256


@dataclass(frozen=True)
class Raw(Expr):
    """Pre-rendered text from an older analysis layer; treated as an atom."""

    text: str
    ssa_refs: frozenset[str] = frozenset()

    def variables(self) -> set[str]:
        return set(self.ssa_refs)


@dataclass(frozen=True)
class Unary(Expr):
    op: str  # "!", "~", "-"
    operand: Expr

    def children(self) -> tuple[Expr, ...]:
        return (self.operand,)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, operand=children[0])


@dataclass(frozen=True)
class Binary(Expr):
    op: str
    left: Expr
    right: Expr

    def children(self) -> tuple[Expr, ...]:
        return (self.left, self.right)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, left=children[0], right=children[1])


@dataclass(frozen=True)
class Call(Expr):
    """Builtin, cast or helper application: address(x), keccak256(...), MEM[...]."""

    name: str
    args: tuple[Expr, ...] = ()

    def children(self) -> tuple[Expr, ...]:
        return self.args

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, args=tuple(children))


@dataclass(frozen=True)
class Index(Expr):
    base: Expr
    key: Expr
    # Storage path kind from the native model: "mapping", "array", "static_array".
    kind: str | None = field(default=None, compare=False)

    def children(self) -> tuple[Expr, ...]:
        return (self.base, self.key)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, base=children[0], key=children[1])


@dataclass(frozen=True)
class Member(Expr):
    base: Expr
    name: str

    def children(self) -> tuple[Expr, ...]:
        return (self.base,)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, base=children[0])


@dataclass(frozen=True)
class Slice(Expr):
    """A byte range in memory/calldata: MEM[start:end]."""

    space: str
    start: Expr
    end: Expr

    def children(self) -> tuple[Expr, ...]:
        return (self.start, self.end)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        return replace(self, start=children[0], end=children[1])


@dataclass(frozen=True)
class ExternalCallExpr(Expr):
    """target.method(args){value: v, gas: g} with an optional kind (call/staticcall/delegatecall)."""

    kind: str
    target: Expr
    method: str | None
    args: tuple[Expr, ...]
    value: Expr | None = None
    gas: Expr | None = None
    raw_input: Expr | None = None

    def children(self) -> tuple[Expr, ...]:
        items = [self.target, *self.args]
        for extra in (self.value, self.gas, self.raw_input):
            if extra is not None:
                items.append(extra)
        return tuple(items)

    def with_children(self, children: tuple[Expr, ...]) -> Expr:
        items = list(children)
        target = items.pop(0)
        args = tuple(items[: len(self.args)])
        rest = items[len(self.args) :]
        value = rest.pop(0) if self.value is not None else None
        gas = rest.pop(0) if self.gas is not None else None
        raw_input = rest.pop(0) if self.raw_input is not None else None
        return replace(self, target=target, args=args, value=value, gas=gas, raw_input=raw_input)


def render_number(value: int) -> str:
    if value < 0:
        return "-" + render_number(-value)
    if value < 1024:
        return str(value)
    if value == (1 << 256) - 1:
        return "uint256.max"
    for bits in (8, 16, 32, 64, 96, 112, 128, 160, 224):
        if value == (1 << bits) - 1:
            return f"uint{bits}.max" if bits != 160 else "0x" + "ff" * 20
    return hex(value)


# --- statements -------------------------------------------------------------


@dataclass
class Stmt:
    evidence: Evidence = field(default=EMPTY, kw_only=True)
    # IR statements represented by this line but not printed as their own line.
    hidden: Evidence = field(default=EMPTY, kw_only=True)
    rules: frozenset[str] = field(default=frozenset(), kw_only=True)
    note: str | None = field(default=None, kw_only=True)
    # Unresolved/partial constructs; printed with an explicit marker.
    uncertain: str | None = field(default=None, kw_only=True)
    # The IR instruction this statement was lifted from, if any.
    origin: str | None = field(default=None, kw_only=True)
    # Facts passed between passes (e.g. a call's output buffer).
    meta: dict = field(default_factory=dict, kw_only=True)

    def expressions(self) -> tuple[Expr, ...]:
        return ()

    def blocks(self) -> tuple[list[Stmt], ...]:
        return ()


@dataclass
class Assign(Stmt):
    targets: tuple[Expr, ...]
    value: Expr
    declare: bool = False

    def expressions(self) -> tuple[Expr, ...]:
        return (*self.targets, self.value)


@dataclass
class ParallelAssign(Stmt):
    """Simultaneous SSA edge copies: (a, b) = (x, y)."""

    targets: tuple[Expr, ...]
    values: tuple[Expr, ...]

    def expressions(self) -> tuple[Expr, ...]:
        return (*self.targets, *self.values)


@dataclass
class ExprStmt(Stmt):
    expr: Expr

    def expressions(self) -> tuple[Expr, ...]:
        return (self.expr,)


@dataclass
class Require(Stmt):
    condition: Expr
    payload: Expr | None = None
    kind: str = "require"  # "require" or "assert"

    def expressions(self) -> tuple[Expr, ...]:
        return (self.condition,) + ((self.payload,) if self.payload else ())


@dataclass
class If(Stmt):
    condition: Expr
    then: list[Stmt]
    otherwise: list[Stmt] = field(default_factory=list)

    def expressions(self) -> tuple[Expr, ...]:
        return (self.condition,)

    def blocks(self) -> tuple[list[Stmt], ...]:
        return (self.then, self.otherwise)


@dataclass
class While(Stmt):
    body: list[Stmt]
    condition: Expr | None = None  # None: while (true)

    def expressions(self) -> tuple[Expr, ...]:
        return (self.condition,) if self.condition else ()

    def blocks(self) -> tuple[list[Stmt], ...]:
        return (self.body,)


@dataclass
class Jump(Stmt):
    kind: str  # "break" | "continue"


@dataclass
class Return(Stmt):
    values: tuple[Expr, ...]
    raw: Expr | None = None  # MEM slice when values are unknown

    def expressions(self) -> tuple[Expr, ...]:
        return self.values + ((self.raw,) if self.raw else ())


@dataclass
class Revert(Stmt):
    payload: Expr | None = None  # None: empty revert

    def expressions(self) -> tuple[Expr, ...]:
        return (self.payload,) if self.payload else ()


@dataclass
class Emit(Stmt):
    event: str
    args: tuple[Expr, ...]
    indexed: int = 0

    def expressions(self) -> tuple[Expr, ...]:
        return self.args


@dataclass
class Halt(Stmt):
    kind: str  # "stop" | "invalid" | "selfdestruct"
    operand: Expr | None = None

    def expressions(self) -> tuple[Expr, ...]:
        return (self.operand,) if self.operand else ()


@dataclass
class Comment(Stmt):
    text: str


@dataclass
class RawBlock(Stmt):
    """Unstructured fallback: label plus raw statements, retained verbatim."""

    label: str
    body: list[Stmt]

    def blocks(self) -> tuple[list[Stmt], ...]:
        return (self.body,)


def walk_statements(statements: list[Stmt]):
    for stmt in statements:
        yield stmt
        for block in stmt.blocks():
            yield from walk_statements(block)
