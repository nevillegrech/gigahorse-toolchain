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
from .simplify import simplify

# key: (base, offset) of a 32-byte word -> its stored value; (base, offset, SELECTOR)
# -> the 4 constant bytes at [offset, offset + 4) (survives writes from offset + 4 on).
Facts = dict[tuple, Expr]


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


SELECTOR = "selector"  # third key element: 4 constant bytes at [offset, offset + 4)
LOW_224 = (1 << 224) - 1


class Forwarder:
    def __init__(
        self,
        model: AddressModel,
        callees: frozenset[str],
        signatures: dict[str, str] | None = None,
    ):
        self.model = model
        self.callees = callees
        self.signatures = signatures or {}
        # Locals assigned once to a stable value (set by forward_memory): call
        # bounds are resolved through them, e.g. `v59 = v47 + 164`.
        self.definitions: dict[str, Expr] = {}
        self.forwarded = 0
        # Consumers (IR statement ids) whose raw memory input became printed words.
        self.decoded: set[str] = set()
        # The statement being processed writes only a selector into its target word.
        self.selector_merge: int | None = None

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

    def decode_call(self, stmt: Stmt, facts: Facts) -> None:
        """A low-level call whose input is a selector plus known ABI words in memory."""
        from .ir import Binary
        from .lift import dynamic_marker, head_params, is_static_abi, signature_params

        call = stmt.value if isinstance(stmt, Assign) else None
        if not (
            isinstance(call, ExternalCallExpr)
            and call.kind in {"call", "staticcall"}
            and call.method is None
            and isinstance(call.raw_input, Slice)
            and stmt.origin
        ):
            return
        start, end = call.raw_input.start, call.raw_input.end
        first = self.key(simplify(self.resolve(start)))
        size = self.constant(Binary("-", end, start))
        if first is None or first[0] is None or size is None:
            return
        base, offset = first
        selector_fact = facts.get((base, offset, SELECTOR))
        if not isinstance(selector_fact, Const) or size < 4 or (size - 4) % 32:
            return
        selector = f"0x{selector_fact.value:08x}"
        signature = self.signatures.get(selector)
        count = (size - 4) // 32
        params = head_params(signature_params(signature)) if signature else None
        if params is not None and len(params) > count:
            return
        args: list[Expr] = []
        dynamic = False
        empties = 0  # empty bytes/string values in the standard tail layout
        for index in range(len(params) if params is not None else count):
            word = facts.get((base, offset + 4 + 32 * index))
            if word is None:
                return
            if params is not None and not is_static_abi(params[index]):
                tail = word.value if isinstance(word, Const) else None
                if tail is None or tail % 32 or tail < 32 * len(params) or 4 + tail >= size:
                    return
                length = facts.get((base, offset + 4 + tail))
                if (
                    params[index] in {"bytes", "string"}
                    and isinstance(length, Const)
                    and length.value == 0
                    and tail == 32 * (len(params) + empties)
                ):
                    # Offset to a zero length word: the empty value "".
                    empties += 1
                    args.append(Call("emptyBytes", (), evidence=word.evidence | length.evidence))
                    continue
                dynamic = True
                word = Call(
                    dynamic_marker(params[index]),
                    (Binary("+", start, Const(4 + tail)),),
                    evidence=word.evidence,
                )
            args.append(word)
        complete = params is not None and not dynamic and len(params) + empties == count
        stmt.value = ExternalCallExpr(
            call.kind,
            call.target,
            signature.split("(", 1)[0] if signature else selector,
            tuple(args),
            value=call.value,
            gas=call.gas,
            evidence=call.all_evidence() | selector_fact.evidence,
            signature=signature,
        )
        stmt.meta["selector"] = selector
        stmt.meta["input"] = (start, end)
        stmt.meta["input_range"] = (base, offset, size)
        stmt.rules = stmt.rules | {"abi-call-from-memory-forwarding"}
        notes = ["staticcall"] if call.kind == "staticcall" else []
        notes += [f"{signature} [dict]"] if signature else []
        if stmt.note and stmt.note.startswith("output buffer"):
            notes.append(stmt.note)
        stmt.note = "; ".join(notes) or None
        if complete:
            # Selector and every word of the input are printed: the call represents them.
            self.decoded.add(stmt.origin)
        elif not dynamic:
            stmt.uncertain = (
                "selector not in the local dictionary; arguments are the input's raw ABI words"
                if params is None
                else "ABI input longer than the signature's head words"
            )

    def constant(self, expr: Expr) -> int | None:
        """Value of a size such as `p1 - p2 + 68` whose pointer terms cancel
        (p1 and p2 reads of the same free-pointer version)."""
        from .ir import Binary

        if isinstance(expr, Const):
            return expr.value
        terms: list[tuple[int, Expr]] = []

        def collect(node: Expr, sign: int) -> None:
            if isinstance(node, Binary) and node.op in {"+", "-"}:
                collect(node.left, sign)
                collect(node.right, sign if node.op == "+" else -sign)
            else:
                terms.append((sign, node))

        collect(simplify(self.resolve(expr)), 1)
        total, bases = 0, {}
        for sign, term in terms:
            if isinstance(term, Const):
                total += sign * term.value
                continue
            key = self.key(term)
            if key is None or key[0] is None:
                return None
            bases[key[0]] = bases.get(key[0], 0) + sign
            total += sign * key[1]
        if any(bases.values()) or not 0 <= total < 1 << 64:
            return None
        return total

    def resolve(self, expr: Expr, depth: int = 0) -> Expr:
        """Substitute once-assigned locals (not pointer reads) by their definitions."""
        if depth > 8:
            return expr
        if isinstance(expr, Var) and expr.name in self.definitions:
            return self.resolve(self.definitions[expr.name], depth + 1)
        children = expr.children()
        if not children:
            return expr
        return expr.with_children(tuple(self.resolve(c, depth + 1) for c in children))

    def decode_consumer(self, stmt: Stmt, facts: Facts) -> None:
        from .ir import Emit, Return

        self.decode_call(stmt, facts)
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
            base, offset = key[0], key[1]
            width = 4 if len(key) == 3 else 32
            if _overlaps(Range(base, offset, width), written):
                del facts[key]

    def copy_facts(self, facts: Facts, destination: Expr, source: Expr, size: int) -> None:
        """MCOPY of a constant size: facts inside the source move to the destination."""
        to, frm = self.key(destination), self.key(source)
        self.kill_range(facts, self.model.range(destination, size))
        if to is None or frm is None:
            return
        moved = {}
        for key, value in facts.items():
            width = 4 if len(key) == 3 else 32
            if key[0] == frm[0] and frm[1] <= key[1] and key[1] + width <= frm[1] + size:
                moved[(to[0], to[1] + key[1] - frm[1], *key[2:])] = value
        facts.update(moved)

    def kill_names(self, facts: Facts, names: set[str]) -> None:
        for key in list(facts):
            base = key[0]
            if base and base.split(":", 1)[-1] in names:
                del facts[key]
            elif _names(facts[key]) & names:
                del facts[key]

    def key(self, address: Expr) -> tuple[str | None, int] | None:
        base, offset = self.model.split(address)
        if base in {ANY, "at-least"} or (
            base and (base.startswith("heap:@") or base.endswith("+?"))
        ):
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
        self.selector_merge = self.merged_selector(stmt)
        self.rewrite_reads(stmt, facts)
        # Then apply its effects to the facts.
        self.apply_effects(stmt, facts)
        return facts

    def merged_selector(self, stmt: Stmt) -> int | None:
        """`MEM[a] = uint224(MEM[a]) | (sel << 224)`: only the 4 bytes at a change."""
        from .ir import Binary

        if not (
            isinstance(stmt, Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], Index)
            and isinstance(stmt.targets[0].base, Env)
            and stmt.targets[0].base.name == "MEM"
            and isinstance(stmt.value, Binary)
            and stmt.value.op == "|"
        ):
            return None
        address = stmt.targets[0].key
        for kept, constant in (
            (stmt.value.left, stmt.value.right),
            (stmt.value.right, stmt.value.left),
        ):
            if (
                isinstance(constant, Const)
                and constant.value >> 224
                and constant.value & LOW_224 == 0
                and isinstance(kept, Call)
                and kept.name == "uint224"
                and len(kept.args) == 1
                and isinstance(kept.args[0], Index)
                and isinstance(kept.args[0].base, Env)
                and kept.args[0].base.name == "MEM"
                and kept.args[0].key == address
            ):
                return constant.value >> 224
        return None

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
                    key = self.key(target.key)
                    if self.selector_merge is not None and width == 32:
                        # Bytes 4..31 keep their previous contents (and facts).
                        self.kill_range(facts, self.model.range(target.key, 4))
                        if key is not None:
                            facts[(*key, SELECTOR)] = Const(
                                self.selector_merge, evidence=stmt.evidence
                            )
                        continue
                    written = self.model.range(target.key, width)
                    self.kill_range(facts, written)
                    if key is not None and width == 32 and _stable(stmt.value):
                        facts[key] = stmt.value
                        word = stmt.value.value if isinstance(stmt.value, Const) else 0
                        if word >> 224 and not word & LOW_224:
                            facts[(*key, SELECTOR)] = Const(
                                stmt.value.value >> 224, evidence=stmt.evidence
                            )
        elif isinstance(stmt, ParallelAssign):
            self.kill_names(facts, {t.name for t in stmt.targets if isinstance(t, Var)})
        elif isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
            call = stmt.expr
            size = self.constant(call.args[2]) if len(call.args) == 3 else None
            if call.name == "MCOPY" and size is not None:
                self.copy_facts(facts, call.args[0], call.args[1], size)
            elif (
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


def forward_memory(
    state,
    callees: frozenset[str],
    signatures: dict[str, str] | None = None,
    consumer_writers: dict[str, set[str]] | None = None,
) -> set[str]:
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
    forwarder = Forwarder(AddressModel(free_pointer_vars, versions), callees, signatures)
    forwarder.definitions = {
        stmt.targets[0].name: stmt.value
        for stmt in iter_statements(state.body)
        if isinstance(stmt, Assign)
        and len(stmt.targets) == 1
        and is_local(stmt.targets[0])
        and assigned.get(stmt.targets[0].name) == 1
        and stmt.targets[0].name not in free_pointer_vars
        and _stable(stmt.value)
    }
    forwarder.block(state.body, {})
    if consumer_writers is not None and forwarder.decoded:
        link_decoded_inputs(state.body, forwarder, consumer_writers)
    _ = (HEAP_FLOOR, size_of)
    return forwarder.decoded


def link_decoded_inputs(
    statements: list[Stmt], forwarder: Forwarder, consumer_writers: dict[str, set[str]]
) -> None:
    """Record the earlier writes into a decoded call's input buffer as its writers.

    Like the native writer/consumer links, this lets write hiding treat them as
    ABI-encoding temporaries of a represented call (under the recorded discipline).
    An MCOPY into the buffer links the writes into its source range in turn
    (e.g. abi.encodeWithSelector's bytes copied into the call buffer). Only writes
    in the same statement list before the call are linked.
    """
    # (key, width, origin, source key of an MCOPY)
    writes: list[tuple[tuple | None, int, str, tuple | None]] = []
    for stmt in statements:
        for block in stmt.blocks():
            link_decoded_inputs(block, forwarder, consumer_writers)
        if isinstance(stmt, (If, While, RawBlock)):
            writes.clear()  # writes before a branch or loop are not linked across it
            continue
        target = stmt.targets[0] if isinstance(stmt, Assign) and stmt.targets else None
        if (
            isinstance(target, Index)
            and isinstance(target.base, Env)
            and target.base.name in {"MEM", "MEM8"}
            and stmt.origin
        ):
            width = 32 if target.base.name == "MEM" else 1
            writes.append((forwarder.key(target.key), width, stmt.origin, None))
        elif (
            isinstance(stmt, ExprStmt)
            and isinstance(stmt.expr, Call)
            and stmt.expr.name == "MCOPY"
            and len(stmt.expr.args) == 3
            and stmt.origin
        ):
            size = forwarder.constant(stmt.expr.args[2])
            if size is not None:
                destination, source = stmt.expr.args[0], stmt.expr.args[1]
                writes.append(
                    (forwarder.key(destination), size, stmt.origin, forwarder.key(source))
                )
        if stmt.origin in forwarder.decoded and "input_range" in stmt.meta:
            base, offset, size = stmt.meta["input_range"]
            ranges = [(base, offset, size)]
            for key, width, origin, source in reversed(writes):
                if key is None:
                    continue
                if any(
                    key[0] == b and o <= key[1] and key[1] + width <= o + n for b, o, n in ranges
                ):
                    consumer_writers.setdefault(stmt.origin, set()).add(origin)
                    if source is not None:
                        ranges.append((source[0], source[1], width))


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
