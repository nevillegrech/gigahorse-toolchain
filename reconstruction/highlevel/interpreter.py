"""Execute the decompiled view itself.

The machine runs exactly the statement trees that `decompiled.sol.txt` prints.
Absorbed IR (hidden memory writes, elided reads) is *not* executed, so any
printed read that depended on a hidden write would produce a different result
than the EVM. Comparing this machine against Py-EVM therefore checks both the
expressions and the abstractions of the readable view on the tested inputs.

It is bounded validation, not a proof: unsupported constructs raise
UnsupportedExecution instead of being approximated.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..keccak import keccak256
from ..validation import (
    ExecutionResult,
    ExternalInvocation,
    ExternalOutcome,
    RecoveredLog,
    UnsupportedExecution,
    signed,
)
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
    Member,
    ParallelAssign,
    Raw,
    RawBlock,
    Require,
    Return,
    Revert,
    Slice,
    Stmt,
    Unary,
    Var,
    While,
    is_local,
)
from .view import DecompiledProgram, FunctionView

MASK = (1 << 256) - 1
ADDRESS = (1 << 160) - 1
# Printed environment names -> the opcode keys used by observed block values.
ENVIRONMENT_OPCODES = {
    "block.number": "NUMBER",
    "block.timestamp": "TIMESTAMP",
    "block.chainid": "CHAINID",
    "block.coinbase": "COINBASE",
    "block.basefee": "BASEFEE",
    "block.prevrandao": "PREVRANDAO",
    "block.gaslimit": "GASLIMIT",
    "block.blobbasefee": "BLOBBASEFEE",
    "tx.gasprice": "GASPRICE",
}


class _Halt(Exception):
    def __init__(self, data: bytes = b"", reverted: bool = False):
        self.data, self.reverted = data, reverted


class _Return(Exception):
    def __init__(self, values: list[int]):
        self.values = values


class _Loop(Exception):
    def __init__(self, kind: str):
        self.kind = kind


@dataclass
class _Frame:
    values: dict[str, int]


def _show(expr: Expr) -> str:
    from .printer import expression

    try:
        return expression(expr)
    except TypeError:
        return type(expr).__name__


def _cast(name: str, value: int) -> int:
    if name == "address":
        return value & ADDRESS
    if name == "bool":
        return int(value != 0)
    if name.startswith("uint") and name[4:].isdigit():
        return value & ((1 << int(name[4:])) - 1)
    if name.startswith("bytes") and name[5:].isdigit():
        size = int(name[5:])
        return value & (MASK ^ ((1 << (256 - 8 * size)) - 1))
    if name.startswith("int") and name[3:].isdigit():
        bits = int(name[3:])
        value &= (1 << bits) - 1
        if value >> (bits - 1):
            value |= MASK ^ ((1 << bits) - 1)
        return value
    raise UnsupportedExecution(f"Unknown cast {name}")


def encode_error(text: str) -> bytes:
    data = text.encode()
    padded = data + b"\0" * (-len(data) % 32)
    return (
        bytes.fromhex("08c379a0")
        + (32).to_bytes(32, "big")
        + len(data).to_bytes(32, "big")
        + padded
    )


class DecompiledMachine:
    def __init__(
        self,
        decompiled: DecompiledProgram,
        *,
        external_handler: Callable[[ExternalInvocation], ExternalOutcome] | None = None,
        max_steps: int = 200000,
        max_memory: int = 1 << 20,
    ):
        self.program = decompiled
        self.functions = {view.name: view for view in decompiled.views}
        self.external_handler = external_handler
        self.max_steps, self.max_memory = max_steps, max_memory
        self.covered_lines: set[int] = set()
        self.trace: list[Stmt] = []

    # --- entry ---------------------------------------------------------------

    def execute(
        self,
        calldata: bytes,
        *,
        storage: dict[int, int] | None = None,
        caller: int = 1,
        address: int = 2,
        value: int = 0,
        observed_balance_values: Iterable[tuple[str, int, int]] = (),
        code_sizes: dict[int, int] | None = None,
        block_environment: dict[str, int] | None = None,
        block_hashes: dict[int, int] | None = None,
    ) -> ExecutionResult:
        original = dict(storage or {})
        self.storage = dict(original)
        self.memory = bytearray()
        self.calldata = calldata
        self.caller, self.address, self.callvalue = caller, address, value
        self.returndata = b""
        self.logs: list[RecoveredLog] = []
        self.external_calls: list[ExternalInvocation] = []
        self.steps = 0
        self.trace = []
        self.uncertain_executed = 0
        self.balances = iter(observed_balance_values)
        self.code_sizes = dict(code_sizes or {})
        self.block_environment = dict(block_environment or {})
        self.block_hashes = dict(block_hashes or {})
        dispatcher = self.functions.get("__function_selector__")
        if dispatcher is None:
            raise UnsupportedExecution("No selector dispatch function in the view")
        try:
            self.run_function(dispatcher, [])
        except _Halt as halt:
            return ExecutionResult(
                halt.data,
                halt.reverted,
                original if halt.reverted else dict(self.storage),
                [],
                self.steps,
                list(self.external_calls),
                [] if halt.reverted else list(self.logs),
            )
        raise UnsupportedExecution("Decompiled execution ended without a halt")

    def run_public(
        self,
        view: FunctionView,
        calldata: bytes,
        *,
        storage: dict[int, int] | None = None,
        caller: int = 1,
        address: int = 2,
        value: int = 0,
    ) -> ExecutionResult:
        """Run one public function body as if dispatched to it."""
        original = dict(storage or {})
        self.storage = dict(original)
        self.memory = bytearray(b"\0" * 0x60) + (0x80).to_bytes(32, "big")
        self.memory[0x40:0x60] = (0x80).to_bytes(32, "big")
        self.calldata = calldata
        self.caller, self.address, self.callvalue = caller, address, value
        self.returndata = b""
        self.logs, self.external_calls = [], []
        self.steps, self.trace, self.uncertain_executed = 0, [], 0
        self.balances = iter(())
        self.code_sizes, self.block_environment, self.block_hashes = {}, {}, {}
        try:
            self.run_function(view, [])
        except _Halt as halt:
            return ExecutionResult(
                halt.data,
                halt.reverted,
                original if halt.reverted else dict(self.storage),
                [],
                self.steps,
                list(self.external_calls),
                [] if halt.reverted else list(self.logs),
            )
        raise UnsupportedExecution("Function ended without a halt")

    def storage_string(self, root: Var, frame: _Frame) -> bytes:
        slot, low, high = self.storage_slot(root, frame)
        word = self.storage.get(slot, 0)
        if word & 1 == 0:
            length = (word & 0xFF) // 2
            return word.to_bytes(32, "big")[:length]
        length = (word - 1) // 2
        if length > self.max_memory:
            raise UnsupportedExecution("Stored string too long")
        start = int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")
        data = b"".join(
            self.storage.get(start + i, 0).to_bytes(32, "big") for i in range((length + 31) // 32)
        )
        return data[:length]

    def run_function(self, view: FunctionView, args: list[int]) -> list[int]:
        frame = _Frame({a.name: v for a, v in zip(view.arguments, args, strict=False)})
        if view.nonpayable is not None and self.callvalue:
            # The printed `nonpayable` stands for the compiler's leading callvalue check.
            raise _Halt(b"", True)
        if view.function.selectors:
            # Public arguments are ABI head words, enforced as the bytecode does:
            # masked at every use (old solc) or rejected when dirty (ABI validator).
            for index, argument in enumerate(view.arguments):
                if argument.definition is not None:
                    word = self.eval(argument.definition, frame)
                else:
                    word = self.calldata_word(4 + 32 * index)
                if argument.enforcement == "mask":
                    word = _cast(argument.type, word)
                elif argument.enforcement == "revert" and _cast(argument.type, word) != word:
                    raise _Halt(b"", True)
                frame.values[argument.name] = word
        try:
            self.block(view.body, frame)
        except _Return as result:
            return result.values
        if view.function.selectors or view.name == "__function_selector__":
            raise _Halt()
        return []

    # --- statements ----------------------------------------------------------

    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise UnsupportedExecution("Decompiled execution step limit exceeded")

    def block(self, statements: list[Stmt], frame: _Frame) -> None:
        for stmt in statements:
            self.statement(stmt, frame)

    def statement(self, stmt: Stmt, frame: _Frame) -> None:
        self.tick()
        self.trace.append(stmt)
        if len(self.trace) > 64:
            del self.trace[:32]
        if stmt.uncertain and not isinstance(stmt, Comment):
            # Executed anyway: a wrong printed meaning shows up as a divergence.
            self.uncertain_executed += 1
        if isinstance(stmt, Comment):
            return
        if isinstance(stmt, Assign):
            if isinstance(stmt.value, ExternalCallExpr):
                results = self.external(stmt.value, frame, stmt)
                for target, value in zip(stmt.targets, results, strict=False):
                    self.assign(target, value, frame)
                return
            if isinstance(stmt.value, Call) and stmt.value.name in self.functions:
                results = self.private(stmt.value, frame)
                for target, value in zip(stmt.targets, results, strict=True):
                    self.assign(target, value, frame)
                return
            if len(stmt.targets) != 1:
                raise UnsupportedExecution("Multi-target assignment of a plain value")
            value = self.eval(stmt.value, frame)
            self.assign(stmt.targets[0], value, frame)
            return
        if isinstance(stmt, ParallelAssign):
            values = [self.eval(v, frame) for v in stmt.values]
            for target, value in zip(stmt.targets, values, strict=True):
                self.assign(target, value, frame)
            return
        if isinstance(stmt, ExprStmt):
            expr = stmt.expr
            if isinstance(expr, ExternalCallExpr):
                self.external(expr, frame, stmt)
            elif isinstance(expr, Call) and expr.name in self.functions:
                self.private(expr, frame)
            elif isinstance(expr, Call) and expr.name in {
                "CALLDATACOPY",
                "RETURNDATACOPY",
                "MCOPY",
                "CODECOPY",
            }:
                self.copy(expr, frame)
            else:
                self.eval(expr, frame)
            return
        if isinstance(stmt, Require):
            if self.truth(stmt.condition, frame):
                return
            if stmt.kind == "assert":
                raise _Halt(b"", True)
            raise _Halt(self.payload(stmt.payload, frame), True)
        if isinstance(stmt, If):
            branch = stmt.then if self.truth(stmt.condition, frame) else stmt.otherwise
            self.block(branch, frame)
            return
        if isinstance(stmt, While):
            while stmt.condition is None or self.truth(stmt.condition, frame):
                self.tick()
                try:
                    self.block(stmt.body, frame)
                except _Loop as action:
                    if action.kind == "break":
                        break
            return
        if isinstance(stmt, Jump):
            raise _Loop(stmt.kind)
        if isinstance(stmt, Return):
            if "storage-string-getter" in stmt.rules:
                (root,) = stmt.values
                assert isinstance(root, Var)
                data = self.storage_string(root, frame)
                padded = data + b"\0" * (-len(data) % 32)
                raise _Halt((32).to_bytes(32, "big") + len(data).to_bytes(32, "big") + padded)
            if "tail-call" in stmt.rules:
                (call,) = stmt.values
                assert isinstance(call, Call)
                self.private(call, frame)
                raise _Halt()
            if stmt.raw is not None:
                raise _Halt(self.slice(stmt.raw, frame))
            values = [self.eval(v, frame) for v in stmt.values]
            if "internal-return" in stmt.rules:
                raise _Return(values)
            raise _Halt(b"".join(v.to_bytes(32, "big") for v in values))
        if isinstance(stmt, Revert):
            raise _Halt(self.payload(stmt.payload, frame), True)
        if isinstance(stmt, Emit):
            self.emit(stmt, frame)
            return
        if isinstance(stmt, Halt):
            if stmt.kind == "stop":
                raise _Halt()
            if stmt.kind == "invalid":
                raise _Halt(b"", True)
            raise UnsupportedExecution("SELFDESTRUCT is not modelled")
        if isinstance(stmt, RawBlock):
            raise UnsupportedExecution("Unstructured control flow")
        raise UnsupportedExecution(f"Unsupported statement {type(stmt).__name__}")

    def assign(self, target: Expr, value: int, frame: _Frame) -> None:
        value &= MASK
        if is_local(target):
            frame.values[target.name] = value
            return
        if isinstance(target, Index) and isinstance(target.base, Env):
            if target.base.name == "MEM":
                self.write(self.eval(target.key, frame), value.to_bytes(32, "big"))
                return
            if target.base.name == "MEM8":
                self.write(self.eval(target.key, frame), bytes([value & 0xFF]))
                return
            if target.base.name == "STORAGE":
                self.storage[self.eval(target.key, frame)] = value
                return
        slot, low, high = self.storage_slot(target, frame)
        if (low, high) == (0, 31):
            self.storage[slot] = value
            return
        width = 8 * (high - low + 1)
        mask = ((1 << width) - 1) << (8 * low)
        old = self.storage.get(slot, 0)
        self.storage[slot] = (old & (MASK ^ mask)) | ((value << (8 * low)) & mask)

    # --- calls ---------------------------------------------------------------

    def private(self, call: Call, frame: _Frame) -> list[int]:
        view = self.functions[call.name]
        args = [self.eval(a, frame) for a in call.args]
        return self.run_function(view, args)

    def external(self, call: ExternalCallExpr, frame: _Frame, stmt: Stmt) -> list[int]:
        if self.external_handler is None:
            raise UnsupportedExecution("External calls need a replay handler")
        target = self.eval(call.target, frame) & ADDRESS
        value = self.eval(call.value, frame) if call.value is not None else 0
        if call.kind in {"eth-transfer", "eth-send"}:
            value = self.eval(call.args[0], frame)
            data = b""
        elif call.raw_input is not None:
            data = self.payload_bytes(call.raw_input, frame)
        else:
            selector = self.selector_of(stmt)
            data = selector + b"".join(self.eval(a, frame).to_bytes(32, "big") for a in call.args)
        opcode = {
            "call": "CALL",
            "staticcall": "STATICCALL",
            "delegatecall": "DELEGATECALL",
            "callcode": "CALLCODE",
            "eth-transfer": "CALL",
            "eth-send": "CALL",
        }[call.kind]
        invocation = ExternalInvocation(stmt.origin or "", opcode, target, value, data, -1, {})
        self.external_calls.append(invocation)
        outcome = self.external_handler(invocation)
        self.returndata = outcome.data
        output = stmt.meta.get("output")
        if output is not None:
            start, size = self.eval(output[0], frame), self.eval(output[1], frame)
            if size:
                self.write(start, outcome.data[:size])
        if call.kind == "eth-transfer":
            if not outcome.success:
                raise _Halt(outcome.data, True)
            return []
        results = [int(outcome.success)]
        targets = stmt.targets if isinstance(stmt, Assign) else ()
        for index in range(1, len(targets)):
            word = outcome.data[32 * (index - 1) : 32 * index].ljust(32, b"\0")
            results.append(int.from_bytes(word, "big"))
        return results

    def selector_of(self, stmt: Stmt) -> bytes:
        info = self.program.context.externals.get(stmt.origin or "")
        if info is None or len(info.selector_candidates) != 1:
            raise UnsupportedExecution("Call selector unknown")
        return bytes.fromhex(info.selector_candidates[0][2:])

    def emit(self, stmt: Emit, frame: _Frame) -> None:
        origin = self.program.context.statements.get(stmt.origin or "")
        if origin is None:
            raise UnsupportedExecution("Event without origin")
        topic0 = self.program.context.constants.get(origin.operands[2])
        if topic0 is None:
            raise UnsupportedExecution("Event topic is not constant")
        topics = (topic0, *(self.eval(a, frame) for a in stmt.args[: stmt.indexed]))
        rest = stmt.args[stmt.indexed :]
        if len(rest) == 1 and isinstance(rest[0], Slice):
            data = self.slice(rest[0], frame)
        else:
            data = b"".join(self.eval(a, frame).to_bytes(32, "big") for a in rest)
        self.logs.append(RecoveredLog(self.address, tuple(topics), data))

    # --- expressions ---------------------------------------------------------

    def truth(self, expr: Expr, frame: _Frame) -> bool:
        return self.eval(expr, frame) != 0

    def payload(self, payload: Expr | None, frame: _Frame) -> bytes:
        if payload is None:
            return b""
        return self.payload_bytes(payload, frame)

    def payload_bytes(self, payload: Expr, frame: _Frame) -> bytes:
        if isinstance(payload, Env) and payload.name == "returndata":
            return self.returndata
        if isinstance(payload, Slice):
            return self.slice(payload, frame)
        if (
            isinstance(payload, Call)
            and payload.name == "Error"
            and isinstance(payload.args[0], Raw)
        ):
            import json

            return encode_error(json.loads(payload.args[0].text))
        if isinstance(payload, Call) and payload.name == "Panic":
            code = self.eval(payload.args[0], frame)
            return bytes.fromhex("4e487b71") + code.to_bytes(32, "big")
        if isinstance(payload, Call) and payload.name == "abi.encodeWithSelector":
            selector_text = payload.args[0]
            assert isinstance(selector_text, Raw)
            selector = bytes.fromhex(selector_text.text.split()[0][2:])
            return selector + b"".join(
                self.eval(a, frame).to_bytes(32, "big") for a in payload.args[1:]
            )
        if isinstance(payload, Raw) and payload.text.startswith("0x"):
            return bytes.fromhex(payload.text[2:])
        raise UnsupportedExecution(f"Unsupported payload {payload!r}")

    def slice(self, expr: Slice, frame: _Frame) -> bytes:
        start, end = self.eval(expr.start, frame), self.eval(expr.end, frame)
        if expr.space != "MEM":
            raise UnsupportedExecution("Non-memory slice")
        if end < start:
            raise UnsupportedExecution("Negative memory range")
        return self.read(start, end - start)

    def read(self, start: int, size: int) -> bytes:
        if size == 0:
            return b""
        if start + size > self.max_memory:
            raise UnsupportedExecution("Memory limit exceeded")
        if len(self.memory) < start + size:
            self.memory.extend(b"\0" * (start + size - len(self.memory)))
        return bytes(self.memory[start : start + size])

    def write(self, start: int, data: bytes) -> None:
        if not data:
            return
        self.read(start, len(data))
        self.memory[start : start + len(data)] = data

    def calldata_word(self, offset: int) -> int:
        if offset >= len(self.calldata):
            return 0
        return int.from_bytes(self.calldata[offset : offset + 32].ljust(32, b"\0"), "big")

    def copy(self, call: Call, frame: _Frame) -> None:
        args = [self.eval(a, frame) for a in call.args]
        destination, source, size = args
        if size > self.max_memory:
            raise UnsupportedExecution("Copy limit exceeded")
        if call.name == "CALLDATACOPY":
            data = self.calldata[source : source + size].ljust(size, b"\0")
        elif call.name == "RETURNDATACOPY":
            if source + size > len(self.returndata):
                raise _Halt(b"", True)
            data = self.returndata[source : source + size]
        elif call.name == "MCOPY":
            data = self.read(source, size)
        else:
            code = self.program.context.program.runtime_bytecode
            if code is None:
                raise UnsupportedExecution("CODECOPY requires the exact executed code input")
            runtime = bytes.fromhex(code)
            data = runtime[source : source + size].ljust(size, b"\0")
        self.write(destination, data)

    def storage_slot(self, expr: Expr, frame: _Frame) -> tuple[int, int, int]:
        if isinstance(expr, Var) and expr.ssa is None:
            root = self.program.storage_root(expr.name)
            if root is None:
                raise UnsupportedExecution(f"Unknown storage root {expr.name}")
            location, slot, low, high = root
            if location != "storage":
                raise UnsupportedExecution("Transient storage is not modelled")
            return int(slot, 16), low, high
        if isinstance(expr, Index) and expr.kind == "mapping":
            parent, _, _ = self.storage_slot(expr.base, frame)
            key = self.eval(expr.key, frame)
            return (
                int.from_bytes(
                    keccak256(key.to_bytes(32, "big") + parent.to_bytes(32, "big")), "big"
                ),
                0,
                31,
            )
        if isinstance(expr, Call) and expr.name.startswith("packed_bytes_") and len(expr.args) == 1:
            parent, _, _ = self.storage_slot(expr.args[0], frame)
            low, high = (int(x) for x in expr.name.removeprefix("packed_bytes_").split("_"))
            return parent, low, high
        if isinstance(expr, Index) and expr.kind and ":" in expr.kind:
            kind, stride = expr.kind.split(":")
            parent, _, _ = self.storage_slot(expr.base, frame)
            key = self.eval(expr.key, frame)
            if kind == "array":
                start = int.from_bytes(keccak256(parent.to_bytes(32, "big")), "big")
            else:
                start = parent
            return (start + key * int(stride)) & MASK, 0, 31
        if isinstance(expr, Member) and expr.name == "data":
            parent, _, _ = self.storage_slot(expr.base, frame)
            return int.from_bytes(keccak256(parent.to_bytes(32, "big")), "big"), 0, 31
        if isinstance(expr, Member) and expr.name.startswith("field"):
            parent, _, _ = self.storage_slot(expr.base, frame)
            return (parent + int(expr.name[5:])) & MASK, 0, 31
        raise UnsupportedExecution("Storage path not executable: " + _show(expr))

    def eval(self, expr: Expr, frame: _Frame) -> int:
        if isinstance(expr, Const):
            return expr.value & MASK
        if isinstance(expr, Var):
            if expr.name in frame.values:
                return frame.values[expr.name]
            if expr.ssa is None:
                slot, low, high = self.storage_slot(expr, frame)
                word = self.storage.get(slot, 0)
                return (word >> (8 * low)) & ((1 << (8 * (high - low + 1))) - 1)
            raise UnsupportedExecution(f"Unassigned local {expr.name}")
        if isinstance(expr, Env):
            return self.environment(expr.name)
        if isinstance(expr, Unary):
            value = self.eval(expr.operand, frame)
            if expr.op == "!":
                return int(value == 0)
            if expr.op == "~":
                return MASK ^ value
            if expr.op == "-":
                return (-value) & MASK
        if isinstance(expr, Binary):
            return self.binary(expr, frame)
        if isinstance(expr, Call):
            return self.call_value(expr, frame)
        if isinstance(expr, Index):
            if isinstance(expr.base, Env) and expr.base.name == "msg.data":
                return self.calldata_word(self.eval(expr.key, frame))
            if isinstance(expr.base, Env) and expr.base.name == "MEM":
                return int.from_bytes(self.read(self.eval(expr.key, frame), 32), "big")
            if isinstance(expr.base, Env) and expr.base.name == "STORAGE":
                return self.storage.get(self.eval(expr.key, frame), 0)
            slot, _, _ = self.storage_slot(expr, frame)
            return self.storage.get(slot, 0)
        if isinstance(expr, Member):
            if (
                expr.name == "length"
                and isinstance(expr.base, Env)
                and expr.base.name == "returndata"
            ):
                return len(self.returndata)
            if expr.name == "length" and isinstance(expr.base, Member) and expr.base.name == "code":
                target = self.eval(expr.base.base, frame) & ADDRESS
                runtime = self.program.context.program.runtime_bytecode
                if target == self.address and runtime:
                    return len(bytes.fromhex(runtime))
                if target not in self.code_sizes:
                    raise UnsupportedExecution("Code size requires an observed value")
                return self.code_sizes[target]
            if expr.name.startswith("field") or expr.name == "data":
                slot, _, _ = self.storage_slot(expr, frame)
                return self.storage.get(slot, 0)
            if expr.name == "length" and isinstance(expr.base, (Var, Index, Member)):
                slot, _, _ = self.storage_slot(expr.base, frame)
                return self.storage.get(slot, 0)
            if expr.name == "balance":
                return self.balance(expr.base, frame)
            if expr.name == "length" and isinstance(expr.base, Member) and expr.base.name == "code":
                target = self.eval(expr.base.base, frame) & ADDRESS
                if target not in self.code_sizes:
                    raise UnsupportedExecution("Code size requires an observed value")
                return self.code_sizes[target]
        raise UnsupportedExecution("Unsupported expression: " + _show(expr))

    def balance(self, base: Expr, frame: _Frame) -> int:
        target = self.eval(base, frame) & ADDRESS
        try:
            _op, observed_target, value = next(self.balances)
        except StopIteration as exc:
            raise UnsupportedExecution("Balance requires an observed value") from exc
        if observed_target != target:
            raise UnsupportedExecution("Observed balance target disagrees")
        return value

    def environment(self, name: str) -> int:
        if name == "msg.sender":
            return self.caller
        if name == "msg.value":
            return self.callvalue
        if name == "address(this)":
            return self.address
        if name == "msg.data.length":
            return len(self.calldata)
        if name == "msg.sig":
            return self.calldata_word(0) >> 224
        if name == "true":
            return 1
        if name == "false":
            return 0
        if name == "tx.origin":
            # As in the IR harness: the external caller originates the transaction.
            return self.caller
        if name in self.block_environment:
            return self.block_environment[name]
        opcode = ENVIRONMENT_OPCODES.get(name)
        if opcode is not None and opcode in self.block_environment:
            return self.block_environment[opcode] & MASK
        if name == "block.prevrandao" and "DIFFICULTY" in self.block_environment:
            return self.block_environment["DIFFICULTY"] & MASK
        raise UnsupportedExecution(f"Environment value {name} needs an observation")

    def call_value(self, expr: Call, frame: _Frame) -> int:
        name = expr.name
        if name == "keccak256":
            (data,) = expr.args
            assert isinstance(data, Slice)
            return int.from_bytes(keccak256(self.slice(data, frame)), "big")
        if name.startswith("packed_bytes_") and len(expr.args) == 1:
            slot, low, high = self.storage_slot(expr, frame)
            word = self.storage.get(slot, 0)
            return (word >> (8 * low)) & ((1 << (8 * (high - low + 1))) - 1)
        if name in self.functions:
            results = self.private(expr, frame)
            if len(results) != 1:
                raise UnsupportedExecution("Private call used as a single value")
            return results[0]
        if name == "phi":
            raise UnsupportedExecution("PHI inputs are not associated with predecessors")
        if name == "blockhash":
            number = self.eval(expr.args[0], frame)
            if number not in self.block_hashes:
                raise UnsupportedExecution("BLOCKHASH requires an observed value")
            return self.block_hashes[number] & MASK
        if name == "gasleft":
            raise UnsupportedExecution("gasleft() needs an observed value")
        args = [self.eval(a, frame) for a in expr.args]
        if name == "byte":
            index, word = args
            return (word >> (8 * (31 - index))) & 0xFF if index < 32 else 0
        if name == "signextend":
            from ..validation import arithmetic

            return arithmetic("SIGNEXTEND", args)
        if name == "addmod":
            return (args[0] + args[1]) % args[2] if args[2] else 0
        if name == "mulmod":
            return (args[0] * args[1]) % args[2] if args[2] else 0
        if len(args) == 1:
            return _cast(name, args[0])
        raise UnsupportedExecution(f"Unsupported call {name}")

    def binary(self, expr: Binary, frame: _Frame) -> int:
        op = expr.op
        if op == "&&":
            return int(self.truth(expr.left, frame) and self.truth(expr.right, frame))
        if op == "||":
            return int(self.truth(expr.left, frame) or self.truth(expr.right, frame))
        a, b = self.eval(expr.left, frame), self.eval(expr.right, frame)
        if op == "+":
            return (a + b) & MASK
        if op == "-":
            return (a - b) & MASK
        if op == "*":
            return (a * b) & MASK
        if op == "/":
            return a // b if b else 0
        if op == "%":
            return a % b if b else 0
        if op == "**":
            return pow(a, b, 1 << 256)
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "<<":
            return (a << b) & MASK if b < 256 else 0
        if op == ">>":
            return a >> b if b < 256 else 0
        if op == "s>>":
            return (signed(a) >> min(b, 255)) & MASK
        if op == "==":
            return int(a == b)
        if op == "!=":
            return int(a != b)
        if op == "<":
            return int(a < b)
        if op == ">":
            return int(a > b)
        if op == "<=":
            return int(a <= b)
        if op == ">=":
            return int(a >= b)
        if op == "s<":
            return int(signed(a) < signed(b))
        if op == "s>":
            return int(signed(a) > signed(b))
        if op == "s<=":
            return int(signed(a) <= signed(b))
        if op == "s>=":
            return int(signed(a) >= signed(b))
        if op == "s/":
            if b == 0:
                return 0
            quotient = abs(signed(a)) // abs(signed(b))
            return (quotient if (signed(a) < 0) == (signed(b) < 0) else -quotient) & MASK
        if op == "s%":
            if b == 0:
                return 0
            remainder = abs(signed(a)) % abs(signed(b))
            return (remainder if signed(a) >= 0 else -remainder) & MASK
        raise UnsupportedExecution(f"Unsupported operator {op}")


def describe_trace(statements: list[Stmt], limit: int = 12) -> str:
    """Last executed statements, printed as in the view (for divergence reports)."""
    from .printer import Printed, print_statement

    lines = []
    for stmt in statements[-limit:]:
        out = Printed()
        if isinstance(stmt, (If, While)):
            from .printer import expression

            head = "if" if isinstance(stmt, If) else "while"
            condition = expression(stmt.condition) if stmt.condition is not None else "true"
            lines.append(f"{head} ({condition}) [origin {stmt.origin}]")
            continue
        print_statement(out, stmt, 0)
        lines.append(out.lines[0].strip() + f" [origin {stmt.origin}]")
    return "\n".join(lines)
