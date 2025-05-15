#!/usr/bin/env python3
from typing import TextIO

import os
import sys

# IT: Ugly hack; this can be avoided if we pull the script at the top level
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from clientlib.facts_to_cfg import Statement, Block, Function, construct_cfg, load_csv_map # type: ignore

sys.setrecursionlimit(3000)

def emit(s: str, out: TextIO, indent: int=0):
    # 4 spaces
    INDENT_BASE = '    '

    print(f'{indent*INDENT_BASE}{s}', file=out)


def render_var(var: str, var_val: dict[str, str]):
    if var in var_val:
        return f"v{var.replace('0x', '')}({var_val[var]})"
    else:
        return f"v{var.replace('0x', '')}"


def emit_stmt(stmt: Statement, var_val: dict[str, str], out: TextIO):
    defs = [render_var(v, var_val) for v in stmt.defs]
    uses = [render_var(v, var_val) for v in stmt.operands]

    if defs:
        emit(f"{stmt.ident}: {', '.join(defs)} = {stmt.op} {', '.join(uses)}", out, 1)
    else:
        emit(f"{stmt.ident}: {stmt.op} {', '.join(uses)}", out, 1)


def pretty_print_block(block: Block, visited: set[str], var_val: dict[str, str], out: TextIO):
    emit(f"Begin block {block.ident}", out, 1)

    prev = [p.ident for p in block.predecessors]
    succ = [s.ident for s in block.successors]

    emit(f"prev=[{', '.join(prev)}], succ=[{', '.join(succ)}]", out, 1)
    emit(f"=================================", out, 1)

    for stmt in block.statements:
        emit_stmt(stmt, var_val, out)

    emit('', out)

    for block in block.successors:
        if block.ident not in visited:
            visited.add(block.ident)
            pretty_print_block(block, visited, var_val, out)


def pretty_print_tac(functions: dict[str, Function], var_val: dict[str, str], out: TextIO):
    for function in sorted(functions.values(), key=lambda x: x.ident):
        visibility = 'public' if function.is_public else 'private'
        formals = [render_var(v, var_val) for v in function.formals]
        emit(f"function {function.name}({', '.join(formals)}) {visibility} {{", out)
        pretty_print_block(function.head_block, set(), var_val, out)

        emit("}", out)
        emit("", out)


def main():
    tac_var_val = load_csv_map('TAC_Variable_Value.csv')

    _, functions,  = construct_cfg()

    with open('contract.tac', 'w') as f:
        pretty_print_tac(functions, tac_var_val, f)


if __name__ == "__main__":
    main()
