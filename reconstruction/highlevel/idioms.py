"""Compiler idioms recognized by *executing* the lifted code.

A candidate summary (e.g. "returns the string stored at slot S") replaces a
function body only when running the lifted body on a set of chosen states gives
exactly the summary's result on every one. The test states cover the encoding
branches (empty, short, 31/32/33-byte boundary, multi-slot). This is checked
behaviour on those states, not a proof; the rule and the number of states are
recorded on the printed line, and the replaced statements stay in the map.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..keccak import keccak256
from ..validation import UnsupportedExecution
from .ir import Assign, Emit, ExprStmt, ExternalCallExpr, Index, Member, Return, Slice, Stmt, Var
from .passes import Elision, iter_expr, iter_statements, read_expressions, statement_ids

STRING_LENGTHS = (0, 1, 5, 31, 32, 33, 63, 64, 65, 100)


def storage_string(slot: int, data: bytes) -> dict[int, int]:
    """Solidity's storage encoding of a string/bytes value at `slot`."""
    if len(data) < 32:
        word = int.from_bytes(data.ljust(31, b"\0"), "big") << 8 | (2 * len(data))
        return {slot: word}
    result = {slot: 2 * len(data) + 1}
    start = int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")
    for index in range(0, len(data), 32):
        result[start + index // 32] = int.from_bytes(
            data[index : index + 32].ljust(32, b"\0"), "big"
        )
    return result


def abi_bytes(data: bytes) -> bytes:
    padded = data + b"\0" * (-len(data) % 32)
    return (32).to_bytes(32, "big") + len(data).to_bytes(32, "big") + padded


def sample(length: int, salt: int) -> bytes:
    return bytes((i * 37 + length * 11 + salt) % 251 + 1 for i in range(length))


@dataclass
class Recognition:
    function: str
    rule: str
    states: int
    detail: str


def _roots(body: list[Stmt]) -> set[str]:
    roots = set()
    for stmt in iter_statements(body):
        exprs = list(read_expressions(stmt))
        if isinstance(stmt, Assign):
            exprs.extend(stmt.targets)
        for expr in exprs:
            for node in iter_expr(expr):
                if (
                    isinstance(node, Var)
                    and node.ssa is None
                    and node.name.startswith(("stor_", "tstor_"))
                ):
                    roots.add(node.name)
    return roots


def _helper_roots(body: list[Stmt]) -> set[str]:
    """Storage roots read through recognized copy_of_<root>() helpers."""
    roots = set()
    for stmt in iter_statements(body):
        for expr in read_expressions(stmt):
            for node in iter_expr(expr):
                if type(node).__name__ == "Call" and node.name.startswith("copy_of_"):
                    roots.add(node.name.removeprefix("copy_of_"))
    return roots


PURE_HELPERS = ("copy_of_", "toString", "_Safe")


def _has_effects(
    body: list[Stmt], memory_copies_allowed: bool = False, helpers: bool = False
) -> bool:
    for stmt in iter_statements(body):
        if isinstance(stmt, Emit):
            return True
        if isinstance(stmt, (Assign, ExprStmt)):
            exprs = [stmt.value] if isinstance(stmt, Assign) else [stmt.expr]
            for expr in exprs:
                for node in iter_expr(expr):
                    if isinstance(node, ExternalCallExpr):
                        return True
                    if type(node).__name__ == "Call" and (
                        node.name.startswith("fn_")
                        or (node.name in {"CALLDATACOPY", "CODECOPY"} and not memory_copies_allowed)
                        or (node.name.startswith(PURE_HELPERS) and not helpers)
                    ):
                        return True
        if isinstance(stmt, Assign):
            for target in stmt.targets:
                if isinstance(target, Var) and target.ssa is None:
                    return True
                if isinstance(target, Index) and isinstance(target.base, type(target.base)):
                    base = target.base
                    if getattr(base, "name", "") in {"STORAGE", "TSTORAGE"}:
                        return True
    return False


def recognize_string_getters(decompiled) -> list[Recognition]:
    """Replace bodies that return a storage string with `return root;`."""
    from .interpreter import DecompiledMachine

    results = []
    for view in decompiled.views:
        if not view.function.selectors or view.arguments or view.name == "fallback":
            continue
        returns = [s for s in iter_statements(view.body) if isinstance(s, Return)]
        if (
            not returns
            or any(r.raw is None for r in returns)
            or _has_effects(view.body, helpers=True)
        ):
            continue
        roots = _roots(view.body) | _helper_roots(view.body)
        if len(roots) != 1:
            continue
        root = next(iter(roots))
        location = decompiled.storage_root(root)
        if location is None or location[0] != "storage" or location[2:] != (0, 31):
            continue
        slot = int(location[1], 16)
        machine = DecompiledMachine(decompiled)
        selector = bytes.fromhex(view.function.selectors[0][2:])
        checked = 0
        try:
            for length in STRING_LENGTHS:
                data = sample(length, slot)
                storage = storage_string(slot, data)
                storage[slot + 1] = 0xA5  # an unrelated neighbour must not leak in
                # Through the real dispatcher: it sets up memory as the function expects.
                result = machine.execute(selector, storage=storage)
                if result.reverted or result.output != abi_bytes(data):
                    break
                checked += 1
        except UnsupportedExecution:
            continue
        if checked != len(STRING_LENGTHS):
            continue
        hidden = frozenset().union(*(statement_ids(s) for s in iter_statements(view.body)))
        root_var = Var(root, None)
        statement = Return(
            (Var(root_var.name, None),),
            evidence=frozenset(),
            hidden=hidden,
            rules=frozenset({"storage-string-getter"}),
            note=f"returns the string/bytes at STORAGE[{location[1]}]; checked by executing the lifted body on {checked} storage encodings",
        )
        view.body = [statement]
        view.state.body = view.body
        view.returns = ["string"]
        view.state.elided.append(
            Elision(frozenset(), f"string getter recognized ({checked} states)")
        )
        results.append(Recognition(view.name, "storage-string-getter", checked, root))
    return results


__all__ = ["Member", "Slice", "abi_bytes", "recognize_string_getters", "storage_string"]


WORD = (1 << 256) - 1
ARITH_VALUES = (
    0,
    1,
    2,
    3,
    7,
    10,
    1 << 64,
    (1 << 128) + 5,
    1 << 255,
    WORD - 1,
    WORD,
    0x1234567890ABCDEF,
)


def _checked(op: str, a: int, b: int) -> int | None:
    """Result of checked arithmetic, or None when it reverts."""
    if op == "add":
        return a + b if a + b <= WORD else None
    if op == "sub":
        return a - b if b <= a else None
    if op == "mul":
        return a * b if a * b <= WORD else None
    if op == "div":
        return a // b if b else None
    if op == "mod":
        return a % b if b else None
    raise ValueError(op)


HELPER_NAMES = {
    "add": "_SafeAdd",
    "sub": "_SafeSub",
    "mul": "_SafeMul",
    "div": "_SafeDiv",
    "mod": "_SafeMod",
}


def recognize_arithmetic_helpers(decompiled) -> list[Recognition]:
    """Name private two-argument helpers that behave exactly like checked arithmetic."""
    from .interpreter import DecompiledMachine, _cast
    from .ir import Call
    from .types import map_body

    results = []
    taken = {view.name for view in decompiled.views}
    for view in decompiled.views:
        if (
            view.function.selectors
            or len(view.arguments) != 2
            or view.name == "__function_selector__"
        ):
            continue
        if _has_effects(view.body) or _roots(view.body):
            continue
        machine = DecompiledMachine(decompiled)
        outcomes = {}
        # Parameters typed from masks are cleaned by the callee: compare within the
        # printed types (e.g. a uint224 / uint112 division).
        domains = [
            sorted({_cast(arg.type, v) for v in ARITH_VALUES})
            if arg.enforcement == "mask"
            else ARITH_VALUES
            for arg in view.arguments
        ]
        try:
            for a in domains[0]:
                for b in domains[1]:
                    outcomes[(a, b)] = machine.call_private(view, [a, b])
        except UnsupportedExecution:
            continue
        match = None
        for op in ("add", "sub", "mul", "div", "mod"):
            for swapped in (False, True):
                if all(
                    (result is None) == (_checked(op, *((b, a) if swapped else (a, b))) is None)
                    and (
                        result is None or result == [_checked(op, *((b, a) if swapped else (a, b)))]
                    )
                    for (a, b), result in outcomes.items()
                ):
                    match = (op, swapped)
                    break
            if match:
                break
        if match is None:
            continue
        op, swapped = match
        new = HELPER_NAMES[op]
        if new in taken:
            continue
        taken.add(new)
        old = view.name
        first, second = view.arguments[0].name, view.arguments[1].name
        if swapped:
            # Present the helper as new(x, y) = x op y: swap parameter names in the body
            # and argument order at every call site (positions stay consistent).
            def swap_names(expr, first=first, second=second):
                if isinstance(expr, Var) and expr.name in {first, second}:
                    return replace_name(expr, second if expr.name == first else first)
                return expr

            map_body(view.body, swap_names)

        def rename(expr, old=old, new=new, swapped=swapped):
            if isinstance(expr, Call) and expr.name == old:
                args = expr.args
                if swapped and len(args) == 2:
                    args = (args[1], args[0])
                return replace_call(expr, new, args)
            return expr

        for other in decompiled.views:
            map_body(other.body, rename)
        view.name = new
        decompiled.context.function_names[view.function.id] = new
        results.append(
            Recognition(
                new,
                f"checked-{op}",
                len(outcomes),
                f"{old}{' (operands swapped)' if swapped else ''}",
            )
        )
    return results


def replace_name(expr, name):
    from dataclasses import replace

    return replace(expr, name=name)


def replace_call(expr, name, args):
    from dataclasses import replace

    return replace(
        expr, name=name, args=tuple(args), rules=expr.rules | {"helper-recognized-by-execution"}
    )


def _memory_bytes(machine, pointer: int) -> bytes:
    length = int.from_bytes(machine.read(pointer, 32), "big")
    if length > 1 << 16:
        raise UnsupportedExecution("Implausible memory bytes length")
    return machine.read(pointer + 32, length)


TO_STRING_VALUES = (0, 1, 9, 10, 99, 100, 12345, 1 << 64, (1 << 256) - 1)


def recognize_memory_helpers(decompiled) -> list[Recognition]:
    """Rename private helpers by behaviour; their bodies stay printed and executed.

    - copy_of_<root>(): returns a memory copy of the string stored at <root>
      (checked on ten storage encodings);
    - toString(x): returns the decimal digits of x as a memory string (checked
      on values from 0 to 2**256 - 1).
    """
    from .interpreter import DecompiledMachine
    from .ir import Call
    from .types import map_body

    results = []
    taken = {view.name for view in decompiled.views}
    for view in decompiled.views:
        if (
            view.function.selectors
            or view.name == "__function_selector__"
            or not view.name.startswith("fn_")
        ):
            continue
        if _has_effects(view.body, memory_copies_allowed=True):
            continue
        roots = _roots(view.body)
        machine = DecompiledMachine(decompiled)
        new = None
        detail = ""
        states = 0
        try:
            if not view.arguments and len(roots) == 1:
                root = next(iter(roots))
                location = decompiled.storage_root(root)
                if location and location[0] == "storage" and location[2:] == (0, 31):
                    slot = int(location[1], 16)
                    for length in STRING_LENGTHS:
                        data = sample(length, slot)
                        machine.storage_seed = storage_string(slot, data)
                        result = machine.call_private(view, [], storage=storage_string(slot, data))
                        if (
                            result is None
                            or len(result) != 1
                            or _memory_bytes(machine, result[0]) != data
                        ):
                            break
                        states += 1
                    if states == len(STRING_LENGTHS):
                        new, detail = (
                            f"copy_of_{root}",
                            f"memory copy of the string at STORAGE[{location[1]}]",
                        )
            elif len(view.arguments) == 1 and not roots:
                for value in TO_STRING_VALUES:
                    result = machine.call_private(view, [value])
                    if (
                        result is None
                        or len(result) != 1
                        or _memory_bytes(machine, result[0]) != str(value).encode()
                    ):
                        break
                    states += 1
                if states == len(TO_STRING_VALUES):
                    new, detail = "toString", "decimal digits of the argument as a memory string"
        except UnsupportedExecution:
            continue
        if new is None or new in taken:
            continue
        taken.add(new)
        old = view.name

        def rename(expr, old=old, new=new):
            if isinstance(expr, Call) and expr.name == old:
                return replace_call(expr, new, expr.args)
            return expr

        for other in decompiled.views:
            map_body(other.body, rename)
        view.name = new
        decompiled.context.function_names[view.function.id] = new
        results.append(Recognition(new, "behaviour-named-helper", states, f"{old}: {detail}"))
    return results


BYTES_LENGTHS = (0, 1, 31, 32, 33, 64, 100)


def _free_locals(statements: list[Stmt]) -> set[str]:
    """Locals read by the statements but not assigned within them."""
    from .ir import ParallelAssign
    from .ir import is_local as local

    assigned: set[str] = set()
    read: set[str] = set()
    for stmt in iter_statements(statements):
        for expr in read_expressions(stmt):
            for node in iter_expr(expr):
                if isinstance(node, Var) and local(node) and not node.name.startswith("varg"):
                    read.add(node.name)
        if isinstance(stmt, (Assign, ParallelAssign)):
            assigned |= {t.name for t in stmt.targets if isinstance(t, Var)}
    return read - assigned


def recognize_bytes_returns(decompiled) -> list[Recognition]:
    """Summarize `<encode memory bytes at P>; return MEM[..]` tails as `return P;`.

    The candidate tail is the shortest suffix of a function's top-level body,
    starting at a free-pointer read, whose only free local is P and which ends in
    a raw RETURN with no other effects. It is accepted only if executing the
    tail with a bytes object at P returns exactly abi.encode(bytes) for several
    lengths (memory around the object is filled with junk).
    """
    from .interpreter import DecompiledMachine, _Frame, _Halt
    from .passes import is_free_pointer_read

    results = []
    for view in decompiled.views:
        body = view.body
        if not body or not isinstance(body[-1], Return) or body[-1].raw is None:
            continue
        for start in range(len(body) - 2, -1, -1):
            first = body[start]
            if not (
                isinstance(first, Assign)
                and len(first.targets) == 1
                and isinstance(first.targets[0], Var)
                and is_free_pointer_read(first.value)
            ):
                continue
            tail = body[start:]
            if _has_effects(tail, memory_copies_allowed=True):
                continue
            free = _free_locals(tail)
            if len(free) != 1:
                continue
            pointer = next(iter(free))
            machine = DecompiledMachine(decompiled)
            checked = 0
            try:
                for length in BYTES_LENGTHS:
                    data = sample(length, 77)
                    memory = bytearray((i * 13 + 5) % 256 for i in range(0x600))
                    memory[0x40:0x60] = (0x400).to_bytes(32, "big")
                    memory[0x100:0x120] = length.to_bytes(32, "big")
                    memory[0x120 : 0x120 + length] = data
                    machine.prepare_fragment(memory)
                    try:
                        machine.block(tail, _Frame({pointer: 0x100}))
                        break  # fell through without returning
                    except _Halt as halt:
                        if halt.reverted or halt.data != abi_bytes(data):
                            break
                    checked += 1
            except UnsupportedExecution:
                checked = 0
            if checked == len(BYTES_LENGTHS):
                hidden = frozenset().union(*(statement_ids(s) for s in iter_statements(tail)))
                view.body[start:] = [
                    Return(
                        (Var(pointer, f"bytes-return:{pointer}"),),
                        hidden=hidden,
                        rules=frozenset({"return-memory-bytes"}),
                        note="returns the bytes/string object at this pointer (ABI-encoded); "
                        f"checked by executing the encoder on {checked} lengths",
                        origin=body[-1].origin,
                    )
                ]
                view.state.body = view.body
                view.returns = ["string"]
                results.append(Recognition(view.name, "return-memory-bytes", checked, pointer))
                break
    return results
