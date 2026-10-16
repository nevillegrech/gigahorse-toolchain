"""Tiny one-block programs: real bytecode and the matching IR from one op list."""

from reconstruction.constants import resolve_constants
from reconstruction.model import Block, Function, Instruction, Program
from reconstruction.semantics import SemanticInfo

OPCODES = {
    "ADD": 0x01,
    "MUL": 0x02,
    "SUB": 0x03,
    "AND": 0x16,
    "CALLDATALOAD": 0x35,
    "CALLDATASIZE": 0x36,
    "CALLDATACOPY": 0x37,
    "MLOAD": 0x51,
    "MSTORE": 0x52,
    "DUP1": 0x80,
    "DUP2": 0x81,
    "DUP3": 0x82,
    "DUP4": 0x83,
    "RETURN": 0xF3,
    "REVERT": 0xFD,
}


def assemble(ops: list) -> tuple[bytes, list[Instruction]]:
    """An op is ("PUSH", value), a mnemonic, or (mnemonic, ir_name, definitions,
    operands) for an instruction that is also an IR statement at its pc."""
    code = bytearray()
    instructions = []
    for op in ops:
        if isinstance(op, tuple) and op[0] == "PUSH":
            value = op[1]
            width = max(1, (value.bit_length() + 7) // 8)
            code += bytes([0x5F + width]) + value.to_bytes(width, "big")
            continue
        mnemonic = op if isinstance(op, str) else op[0]
        if not isinstance(op, str):
            _, name, defs, uses = op
            instructions.append(
                Instruction(name, mnemonic, list(defs), list(uses), [hex(len(code))])
            )
        code.append(OPCODES[mnemonic])
    return bytes(code), instructions


def one_block_program(ops: list, constants: dict[str, str]) -> tuple[Program, bytes]:
    runtime, instructions = assemble(ops)
    program = Program(
        dict(constants),
        {},
        [Function("root", ["0x0"], [], None, [], ["0x0"])],
        [Block("0x0", instructions, [], [])],
        [],
        [],
        runtime_bytecode=runtime.hex(),
    )
    program.constants = resolve_constants(program, constants, [], [])
    program.semantics = SemanticInfo(3, [], [], [], {}, program.constants, [], [], [], [])
    return program, runtime
