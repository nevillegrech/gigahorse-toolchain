"""Bounded execution of recovered IR/regions for differential validation.

This is a validation harness, not an EVM replacement: unsupported instructions,
ambiguous PHIs and unresolved flow fail explicitly. Gas equivalence is not tested.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

from .bytecode import executed_code
from .controlflow import FlowPlan, Region, structure_function
from .model import Function, Instruction, Program

MODULUS = 1 << 256
MASK = MODULUS - 1


class UnsupportedExecution(ValueError):
    pass


class _Halt(Exception):
    def __init__(self, data: bytes = b"", reverted: bool = False):
        self.data, self.reverted = data, reverted


class _PrivateReturn(Exception):
    def __init__(self, values: list[int]):
        self.values = values


class _LoopAction(Exception):
    def __init__(self, action: str):
        self.action = action


@dataclass
class ExecutionResult:
    output: bytes
    reverted: bool
    storage: dict[int, int]
    blocks: list[str]
    steps: int
    external_calls: list[ExternalInvocation] = field(default_factory=list)
    logs: list[RecoveredLog] = field(default_factory=list)
    return_word_checks: int = 0


@dataclass
class RecoveredLog:
    address: int
    topics: tuple[int, ...]
    data: bytes


@dataclass
class ExternalInvocation:
    statement: str
    opcode: str
    target: int
    value: int
    calldata: bytes
    requested_gas: int
    inferred_words: dict[int, list[int]]


@dataclass
class ExternalOutcome:
    data: bytes
    success: bool


def signed(value: int) -> int:
    return value - MODULUS if value & (1 << 255) else value


def arithmetic(op: str, args: list[int]) -> int:
    a = args[0] if args else 0
    b = args[1] if len(args) > 1 else 0
    if op == "ADD":
        result = a + b
    elif op == "SUB":
        result = a - b
    elif op == "MUL":
        result = a * b
    elif op == "DIV":
        result = a // b if b else 0
    elif op == "MOD":
        result = a % b if b else 0
    elif op == "SDIV":
        result = (
            (abs(signed(a)) // abs(signed(b))) * (-1 if (signed(a) < 0) != (signed(b) < 0) else 1)
            if b
            else 0
        )
    elif op == "SMOD":
        result = (abs(signed(a)) % abs(signed(b))) * (-1 if signed(a) < 0 else 1) if b else 0
    elif op == "ADDMOD":
        result = (a + b) % args[2] if args[2] else 0
    elif op == "MULMOD":
        result = (a * b) % args[2] if args[2] else 0
    elif op == "EXP":
        result = pow(a, b, MODULUS)
    elif op == "LT":
        result = int(a < b)
    elif op == "GT":
        result = int(a > b)
    elif op == "SLT":
        result = int(signed(a) < signed(b))
    elif op == "SGT":
        result = int(signed(a) > signed(b))
    elif op == "EQ":
        result = int(a == b)
    elif op == "ISZERO":
        result = int(a == 0)
    elif op == "AND":
        result = a & b
    elif op == "OR":
        result = a | b
    elif op == "XOR":
        result = a ^ b
    elif op == "NOT":
        result = ~a
    elif op == "BYTE":
        result = (b >> (8 * (31 - a))) & 255 if a < 32 else 0
    elif op == "SHL":
        result = b << a if a < 256 else 0
    elif op == "SHR":
        result = b >> a if a < 256 else 0
    elif op == "SAR":
        result = signed(b) >> min(a, 256)
    elif op == "SIGNEXTEND":
        bits = 8 * (a + 1)
        result = (
            b
            if bits >= 256
            else b | (MASK ^ ((1 << bits) - 1))
            if b & (1 << (bits - 1))
            else b & ((1 << bits) - 1)
        )
    elif op == "CLZ":
        result = 256 - a.bit_length()
    else:
        raise UnsupportedExecution(f"Unsupported arithmetic: {op}")
    return result & MASK


ARITHMETIC = {
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "SDIV",
    "MOD",
    "SMOD",
    "ADDMOD",
    "MULMOD",
    "EXP",
    "LT",
    "GT",
    "SLT",
    "SGT",
    "EQ",
    "ISZERO",
    "AND",
    "OR",
    "XOR",
    "NOT",
    "BYTE",
    "SHL",
    "SHR",
    "SAR",
    "SIGNEXTEND",
    "CLZ",
}

BLOCK_ENVIRONMENT = {
    "NUMBER",
    "TIMESTAMP",
    "COINBASE",
    "DIFFICULTY",
    "BASEFEE",
    "GASLIMIT",
    "CHAINID",
}


class RecoveredMachine:
    def __init__(
        self,
        program: Program,
        *,
        structured: bool,
        max_steps: int = 100000,
        max_memory: int = 1 << 20,
        external_handler: Callable[[ExternalInvocation], ExternalOutcome] | None = None,
    ):
        self.program = program
        self.code = executed_code(program)
        self.structured = structured
        self.max_steps, self.max_memory = max_steps, max_memory
        self.external_handler = external_handler
        self.functions = {f.id: f for f in program.functions}
        self.blocks = {b.id: b for b in program.blocks}
        self.plans = {f.id: structure_function(program, f) for f in program.functions}
        constants = program.semantics.constants if program.semantics else program.constants
        self.constants = {v: int(value, 16) for v, value in constants.items()}
        self.variables: dict[str, int] = {}
        self.storage: dict[int, int] = {}
        self.transient: dict[int, int] = {}
        self.memory = bytearray()
        self.calldata = b""
        self.trace: list[str] = []
        self.steps = 0
        self.caller = 0
        self.address = 0
        self.callvalue = 0
        self.call_depth = 0
        self.external_calls: list[ExternalInvocation] = []
        self.returndata = b""
        self.observed_gas: Iterator[int] = iter(())
        self.observed_balances: Iterator[tuple[str, int, int]] = iter(())
        self.code_sizes: dict[int, int] = {}
        self.block_environment: dict[str, int] = {}
        self.block_hashes: dict[int, int] = {}
        self.logs: list[RecoveredLog] = []
        self.return_word_checks = 0
        self.revert_snapshot_checks = self.revert_byte_checks = 0
        self.last_revert_statement: str | None = None

    def execute(
        self,
        calldata: bytes,
        *,
        storage: dict[int, int] | None = None,
        caller: int = 1,
        address: int = 2,
        value: int = 0,
        observed_gas_values: Iterable[int] = (),
        observed_balance_values: Iterable[tuple[str, int, int]] = (),
        code_sizes: dict[int, int] | None = None,
        block_environment: dict[str, int] | None = None,
        block_hashes: dict[int, int] | None = None,
    ) -> ExecutionResult:
        original = dict(storage or {})
        self.storage = dict(original)
        self.variables, self.transient = {}, {}
        self.memory, self.calldata = bytearray(), calldata
        self.trace, self.steps, self.call_depth = [], 0, 0
        self.caller, self.address, self.callvalue = caller, address, value
        self.external_calls, self.returndata = [], b""
        self.logs = []
        self.return_word_checks = 0
        self.revert_snapshot_checks = self.revert_byte_checks = 0
        self.last_revert_statement = None
        self.observed_gas = iter(observed_gas_values)
        self.observed_balances = iter(observed_balance_values)
        self.code_sizes = dict(code_sizes or {})
        self.block_environment = dict(block_environment or {})
        self.block_hashes = dict(block_hashes or {})
        roots = [f for f in self.program.functions if "0x0" in f.entries]
        if len(roots) != 1:
            raise UnsupportedExecution("Expected one global dispatch entry")
        try:
            self._function(roots[0], [])
        except _Halt as halt:
            return ExecutionResult(
                halt.data,
                halt.reverted,
                original if halt.reverted else dict(self.storage),
                self.trace,
                self.steps,
                list(self.external_calls),
                [] if halt.reverted else list(self.logs),
                self.return_word_checks,
            )
        raise UnsupportedExecution("Execution ended without a contract halt")

    def _value(self, variable: str) -> int:
        if variable in self.variables:
            return self.variables[variable]
        if variable in self.constants:
            return self.constants[variable]
        raise UnsupportedExecution(f"Uninitialized recovered variable: {variable}")

    def _tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise UnsupportedExecution("Recovered execution step limit exceeded")

    def _range(self, start: int, size: int) -> bytes:
        if size == 0:
            return b""
        if start + size > self.max_memory:
            raise UnsupportedExecution("Recovered memory limit exceeded")
        if len(self.memory) < start + size:
            self.memory.extend(b"\0" * (start + size - len(self.memory)))
        return bytes(self.memory[start : start + size])

    def _write(self, start: int, data: bytes):
        self._range(start, len(data))
        self.memory[start : start + len(data)] = data

    def _function(self, function: Function, args: list[int]) -> list[int]:
        if self.call_depth >= 64 or len(args) != len(function.formal_variables):
            raise UnsupportedExecution(f"Unresolved argument frame for {function.id}")
        previous = self.variables
        self.variables = dict(previous)
        self.variables.update(zip(function.formal_variables, args, strict=True))
        self.call_depth += 1
        plan = self.plans[function.id]
        try:
            if plan.region is None or plan.unresolved_phis:
                raise UnsupportedExecution(
                    f"Unresolved recovered function {function.id}: {plan.warnings}"
                )
            self._copies(plan.entry_copies)
            if self.structured:
                self._region(plan.region, plan)
            else:
                current = function.entries[0]
                while True:
                    self._block(current, plan)
                    transfer = plan.transfers[current]
                    if transfer.kind == "end":
                        raise UnsupportedExecution(f"Opaque terminal at {current}")
                    target = (
                        transfer.targets[0]
                        if transfer.kind == "goto" or self._value(transfer.predicate or "")
                        else transfer.targets[1]
                    )
                    self._edge(current, target, plan)
                    current = target
        except _PrivateReturn as returned:
            return returned.values
        finally:
            self.call_depth -= 1
            self.variables = previous
        raise UnsupportedExecution(f"Recovered function {function.id} fell through")

    def _edge(self, source: str, target: str, plan: FlowPlan):
        self._copies(plan.copies.get((source, target), []))

    def _copies(self, copies):
        values = [self._value(copy.source) for copy in copies]
        self.variables.update(
            (copy.destination, value) for copy, value in zip(copies, values, strict=True)
        )

    def _region(self, region: Region, plan: FlowPlan):
        if region.kind == "sequence":
            for nested in region.children:
                self._region(nested, plan)
        elif region.kind == "block":
            assert region.block is not None
            self._block(region.block, plan)
        elif region.kind == "edge":
            assert region.source is not None and region.target is not None
            self._edge(region.source, region.target, plan)
        elif region.kind == "if":
            assert region.block is not None
            self._tick()
            predicate = plan.transfers[region.block].predicate
            condition = bool(self._value(predicate or "")) != region.inverted
            self._region(region.children[0 if condition else 1], plan)
        elif region.kind == "loop":
            while True:
                self._tick()
                try:
                    self._region(region.children[0], plan)
                except _LoopAction as action:
                    if action.action == "break":
                        break
        elif region.kind in {"continue", "break"}:
            raise _LoopAction(region.kind)
        else:
            raise UnsupportedExecution(f"Unknown region {region.kind}")

    def _block(self, block_id: str, plan: FlowPlan):
        self._tick()
        self.trace.append(block_id)
        for stmt in self.blocks[block_id].instructions:
            if stmt.id in plan.resolved_phis or stmt.opcode in {"JUMP", "JUMPI"}:
                continue
            self._instruction(stmt, block_id)

    def _instruction(self, stmt: Instruction, block_id: str):
        self._tick()
        op = stmt.opcode
        args = [self._value(variable) for variable in stmt.operands]
        results: list[int]
        if op == "CONST":
            results = [self.constants[variable] for variable in stmt.definitions]
        elif op in ARITHMETIC:
            results = [arithmetic(op, args)]
        elif op in {"MOV", "MOV2"}:
            results = args
        elif op == "CALLER" or op == "ORIGIN":
            results = [self.caller]
        elif op == "ADDRESS":
            results = [self.address]
        elif op == "CALLVALUE":
            results = [self.callvalue]
        elif op in BLOCK_ENVIRONMENT:
            if op not in self.block_environment:
                raise UnsupportedExecution(f"{op} requires an independent observed block value")
            results = [self.block_environment[op] & MASK]
        elif op == "BLOCKHASH":
            if args[0] not in self.block_hashes:
                raise UnsupportedExecution("BLOCKHASH requires an independent observed value")
            results = [self.block_hashes[args[0]] & MASK]
        elif op == "GAS":
            try:
                results = [next(self.observed_gas)]
            except StopIteration as exc:
                raise UnsupportedExecution("GAS requires an independent observed value") from exc
        elif op in {"SELFBALANCE", "BALANCE"}:
            target = self.address if op == "SELFBALANCE" else args[0] & ((1 << 160) - 1)
            try:
                observed_op, observed_target, balance = next(self.observed_balances)
            except StopIteration as exc:
                raise UnsupportedExecution(
                    f"{op} requires an independent observed balance"
                ) from exc
            if (observed_op, observed_target) != (op, target):
                raise UnsupportedExecution(
                    f"Observed balance operation/target disagrees at {stmt.id}"
                )
            results = [balance & MASK]
        elif op == "EXTCODESIZE":
            target = args[0] & ((1 << 160) - 1)
            if target not in self.code_sizes:
                raise UnsupportedExecution("EXTCODESIZE requires an observed account code size")
            results = [self.code_sizes[target]]
        elif op == "CALLDATASIZE":
            results = [len(self.calldata)]
        elif op == "CALLDATALOAD":
            results = [int.from_bytes(self.calldata[args[0] : args[0] + 32].ljust(32, b"\0"))]
        elif op == "CALLDATACOPY":
            if args[2] > self.max_memory:
                raise UnsupportedExecution("Calldata copy limit exceeded")
            self._write(args[0], self.calldata[args[1] : args[1] + args[2]].ljust(args[2], b"\0"))
            results = []
        elif op == "CODESIZE":
            if self.code is None:
                raise UnsupportedExecution("CODESIZE requires the exact executed code input")
            results = [len(self.code)]
        elif op == "CODECOPY":
            if len(args) != 3:
                raise UnsupportedExecution("Malformed CODECOPY operands")
            if args[2]:
                if self.code is None:
                    raise UnsupportedExecution("CODECOPY requires the exact executed code input")
                if args[2] > self.max_memory:
                    raise UnsupportedExecution("Code copy limit exceeded")
                self._write(args[0], self.code[args[1] : args[1] + args[2]].ljust(args[2], b"\0"))
            results = []
        elif op == "MLOAD":
            results = [int.from_bytes(self._range(args[0], 32))]
        elif op == "MSTORE":
            self._write(args[0], args[1].to_bytes(32))
            results = []
        elif op == "MSTORE8":
            self._write(args[0], bytes([args[1] & 255]))
            results = []
        elif op in {"LOG0", "LOG1", "LOG2", "LOG3", "LOG4"}:
            if len(args) != 2 + int(op[-1]):
                raise UnsupportedExecution("Malformed LOG operands")
            self.logs.append(
                RecoveredLog(self.address, tuple(args[2:]), bytes(self._range(args[0], args[1])))
            )
            results = []
        elif op == "MCOPY":
            self._write(args[0], self._range(args[1], args[2]))
            results = []
        elif op == "RETURNDATASIZE":
            results = [len(self.returndata)]
        elif op == "RETURNDATACOPY":
            if args[1] + args[2] > len(self.returndata):
                raise _Halt(reverted=True)
            self._write(args[0], self.returndata[args[1] : args[1] + args[2]])
            results = []
        elif op == "MSIZE":
            results = [(len(self.memory) + 31) // 32 * 32]
        elif op == "SHA3":
            from eth_hash.auto import keccak

            results = [int.from_bytes(keccak(self._range(args[0], args[1])))]
        elif op in {"SLOAD", "TLOAD"}:
            results = [(self.storage if op == "SLOAD" else self.transient).get(args[0], 0)]
        elif op in {"SSTORE", "TSTORE"}:
            (self.storage if op == "SSTORE" else self.transient)[args[0]] = args[1]
            results = []
        elif op == "RETURN":
            data = self._range(args[0], args[1])
            layout = next(
                (
                    r
                    for r in self.program.return_layouts
                    if r.statement == stmt.id and r.status == "raw_words"
                ),
                None,
            )
            if layout:
                encoded = b"".join(self._value(v).to_bytes(32) for v in layout.words)
                if encoded != data:
                    raise UnsupportedExecution(
                        f"Return-word annotation disagrees with memory at {stmt.id}"
                    )
                self.return_word_checks += len(layout.words)
            raise _Halt(data)
        elif op == "REVERT":
            self.last_revert_statement = stmt.id
            data = self._range(args[0], args[1])
            snapshot = self.program.revert_memory.get(stmt.id)
            if snapshot is not None:
                if snapshot["byte_length"] is not None and len(data) != snapshot["byte_length"]:
                    raise UnsupportedExecution(f"Revert snapshot length disagrees at {stmt.id}")
                for fragment in snapshot["known_ranges"]:
                    start, expected = fragment["offset"], bytes.fromhex(fragment["data"])
                    if data[start : start + len(expected)] != expected:
                        raise UnsupportedExecution(f"Revert snapshot bytes disagree at {stmt.id}")
                    self.revert_byte_checks += len(expected)
                self.revert_snapshot_checks += 1
            raise _Halt(data, True)
        elif op == "STOP":
            raise _Halt()
        elif op == "RETURNPRIVATE":
            raise _PrivateReturn(args[1:])
        elif op == "CALLPRIVATE":
            candidates = (
                {callee for caller, callee in self.program.semantics.calls if caller == block_id}
                if self.program.semantics
                else set()
            )
            if len(candidates) != 1:
                raise UnsupportedExecution(f"Ambiguous private call at {stmt.id}")
            callee = self.functions[next(iter(candidates))]
            results = self._function(callee, args[1:])
        elif op in {"CALL", "CALLCODE", "STATICCALL", "DELEGATECALL"}:
            if self.external_handler is None:
                raise UnsupportedExecution("External execution requires an explicit call handler")
            has_value = op in {"CALL", "CALLCODE"}
            start = 3 if has_value else 2
            external = (
                next(
                    (c for c in self.program.semantics.external_calls if c.statement == stmt.id),
                    None,
                )
                if self.program.semantics
                else None
            )
            invocation = ExternalInvocation(
                stmt.id,
                op,
                args[1] & ((1 << 160) - 1),
                args[2] if has_value else self.callvalue if op == "DELEGATECALL" else 0,
                self._range(args[start], args[start + 1]),
                args[0],
                {
                    a.index: [self._value(v) for v in a.variables]
                    for a in external.arguments
                    if len(a.variables) == 1
                }
                if external
                else {},
            )
            self.external_calls.append(invocation)
            outcome = self.external_handler(invocation)
            if len(outcome.data) > self.max_memory:
                raise UnsupportedExecution("External return data limit exceeded")
            self.returndata = outcome.data
            self._range(args[start + 2], args[start + 3])
            self._write(args[start + 2], outcome.data[: args[start + 3]])
            results = [int(outcome.success)]
        else:
            raise UnsupportedExecution(f"Opcode {op} is not supported by the validation harness")
        if len(results) != len(stmt.definitions):
            raise UnsupportedExecution(f"Definition arity mismatch at {stmt.id}")
        self.variables.update(zip(stmt.definitions, results, strict=True))
