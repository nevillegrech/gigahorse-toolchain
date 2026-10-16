"""Conservative pseudocode: keep block structure and EVM-specific operations."""

from __future__ import annotations

import json

from .model import Instruction, Program, sort_key


def identifier(value: str, prefix: str) -> str:
    # Escape underscores too, making this encoding injective for arbitrary upstream IDs.
    return prefix + "".join(c if c.isascii() and c.isalnum() else f"_{ord(c):x}_" for c in value)


ENVIRONMENT = {
    "CALLER": "msg.sender",
    "CALLVALUE": "msg.value",
    "ORIGIN": "tx.origin",
    "ADDRESS": "address(this)",
    "NUMBER": "block.number",
    "TIMESTAMP": "block.timestamp",
    "CHAINID": "block.chainid",
    "CALLDATASIZE": "msg.data.length",
    "RETURNDATASIZE": "returndata.length",
}
INFIX = {"ADD": "+", "MUL": "*", "SUB": "-", "AND": "&", "OR": "|", "XOR": "^"}

# Only these operations can be re-evaluated from their captured SSA operands.
# RETURNDATASIZE and other mutable environment/memory reads stay assignments.
PURE = (
    set(INFIX)
    | (set(ENVIRONMENT) - {"RETURNDATASIZE"})
    | {"EQ", "LT", "GT"}
    | {
        "CONST",
        "ISZERO",
        "SHL",
        "SHR",
        "SAR",
        "NOT",
        "DIV",
        "SDIV",
        "MOD",
        "SMOD",
        "ADDMOD",
        "MULMOD",
        "EXP",
        "BYTE",
        "SIGNEXTEND",
        "SLT",
        "SGT",
        "CALLDATALOAD",
        "MOV",
    }
)


def render_instruction(
    stmt: Instruction, program: Program, *, variable_names: dict[str, str] | None = None
) -> str:
    def name(variable: str) -> str:
        return (variable_names or {}).get(variable, identifier(variable, "v_"))

    def operand(variable: str) -> str:
        return program.constants.get(variable, name(variable))

    def target(variable: str) -> str:
        block_id = program.block_targets.get(variable, program.constants.get(variable))
        if block_id in {b.id for b in program.blocks}:
            return identifier(block_id, "block_")
        return f"unresolved_target({operand(variable)})"

    args = [operand(variable) for variable in stmt.operands]
    op = stmt.opcode
    rhs: str
    if op == "CONST" and len(stmt.definitions) == 1:
        rhs = program.constants.get(stmt.definitions[0], "unresolved_constant()")
    elif op in INFIX and len(args) == 2:
        rhs = f"u256({args[0]} {INFIX[op]} {args[1]})"
    elif op == "SHL" and len(args) == 2:
        rhs = f"u256({args[1]} << {args[0]})"
    elif op == "SHR" and len(args) == 2:
        rhs = f"({args[1]} >> {args[0]})"
    elif op in ENVIRONMENT and not args:
        rhs = ENVIRONMENT[op]
    elif op in {"SLOAD", "TLOAD"} and len(args) == 1:
        rhs = f"{'storage' if op == 'SLOAD' else 'transient'}[{args[0]}]"
    elif op in {"SSTORE", "TSTORE"} and len(args) == 2 and not stmt.definitions:
        return f"{'storage' if op == 'SSTORE' else 'transient'}[{args[0]}] = {args[1]};"
    elif op == "JUMP" and len(args) == 1 and not stmt.definitions:
        return f"goto {target(stmt.operands[0])};"
    elif op == "JUMPI" and len(args) == 2 and not stmt.definitions:
        return f"if ({args[1]} != 0) goto {target(stmt.operands[0])};"
    elif op == "PHI":
        rhs = f"phi_unordered({', '.join(args)})"
    else:
        # Includes signed arithmetic, zero-divisor semantics, memory, logs and calls.
        # EVM helpers preserve opcode operand order and do not claim Solidity semantics.
        rhs = (
            f"evm.{op.lower()}({', '.join(args)})"
            if op.isidentifier()
            else (f"evm.opcode({json.dumps(op)}{', ' if args else ''}{', '.join(args)})")
        )
    if stmt.definitions:
        lhs = ", ".join(name(v) for v in stmt.definitions)
        return f"{lhs} = {rhs};"
    return f"{rhs};"


def render_program(program: Program) -> str:
    lines = [
        "// Gigahorse reconstruction: low-level pseudocode, NOT compilable Solidity.",
        "// u256(x) reduces modulo 2**256; shifts use unsigned 256-bit EVM words.",
        "// evm.* helpers use EVM semantics and the original stack operand order.",
        "// Labels/CFG edges are preserved; types, ABI and structured loops are not inferred.",
    ]
    lines.extend(f"// WARNING: {warning}" for warning in program.warnings)
    if program.unmapped_statements:
        lines.append("// Unmapped statements: " + json.dumps(program.unmapped_statements))
    lines.extend(["", "contract Decompiled {"])
    block_by_id = {b.id: b for b in program.blocks}

    def emit_block(block_id: str):
        block = block_by_id[block_id]
        lines.append(f"    {identifier(block_id, 'block_')}: // IR block {json.dumps(block_id)}")
        for stmt in block.instructions:
            provenance = f" // IR {json.dumps(stmt.id)}"
            if stmt.original_statements:
                provenance += "; bytecode " + json.dumps(stmt.original_statements)
            lines.append("        " + render_instruction(stmt, program) + provenance)
        lines.append("        // CFG successors: " + json.dumps(block.successors))
        lines.append("        // Fallthrough: " + json.dumps(block.fallthrough))

    covered = set()
    for function in program.functions:
        lines.append("")
        if function.name_hint:
            lines.append("    // Upstream name hint: " + json.dumps(function.name_hint))
        lines.append("    // Selectors: " + json.dumps(function.selectors))
        if program.signature_info:
            for selector in function.selectors:
                hints = program.signature_info.candidates.get(selector, [])
                if hints:
                    lines.append(
                        "    // Candidate signatures (external hints, collisions possible): "
                        + json.dumps(hints)
                    )
        lines.append("    // Entry blocks: " + json.dumps(function.entries))
        args = ", ".join(identifier(v, "v_") for v in function.formal_variables)
        lines.append(f"    function {identifier(function.id, 'fn_')}({args}) {{")
        order = function.entries + [b for b in function.blocks if b not in function.entries]
        for block_id in order:
            emit_block(block_id)
            covered.add(block_id)
        lines.append("    }")
    for block_id in sorted(block_by_id.keys() - covered, key=sort_key):
        lines.append("    // Block without function membership")
        emit_block(block_id)
    lines.append("}")
    return "\n".join(lines) + "\n"
