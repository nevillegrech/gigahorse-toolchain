#!/usr/bin/env python3
"""
out_of_ssa.py — Replace PHI statements in Gigahorse TAC with MOV copies.

Cytron-style copy insertion, with one intermediate variable per PHI
(Sreedhar et al., "Method I") so that no critical-edge splitting or
parallel-copy sequentialization is needed. For each

    B:  x = PHI(v1 from P1, ..., vn from Pn)

we emit

    Pi: x_in = MOV vi      (at the end of each predecessor Pi)
    B:  x    = MOV x_in    (at the head of B; reuses the PHI's statement id)

A predecessor ending in CALLPRIVATE cannot hold the copies: the call defines
the return values they may read, and nothing may follow it in its block. Such
an edge Pi -> B gets a new block N holding only the copies and a JUMP to B,
Pi -> N -> B.

New statements are spliced into TAC_Statement_Next after/before their anchor
statement; those of a block that had no statements are appended to the end of
its function's chain (see `_StatementOrder`).

New statement and block ids are concatenations of hex values, like the ids
Gigahorse produces for cloned blocks (see `_FreshIds`).

`x` stays single-assignment; only the fresh `x_in` has multiple definitions.
Copying straight into `x` would be wrong in two cases:
  * swap problem: x = PHI(.., y), y = PHI(.., x) in the same block, where
    sequential copies in the predecessor clobber each other;
  * lost-copy problem: x is live out of a predecessor that has another
    successor besides B (a critical edge), so the copy overwrites a live x.
Since every `x_in` is fresh and read only at the head of B, neither can occur.

Requires the `TAC_PhiOperand` relation, which the decompiler emits only when
precise SSA recovery computed `PHIVar_Pred`. The pass refuses to run if any PHI
lacks exactly one operand per CFG predecessor.

    from src.tac_schema import TACRelations
    from src.out_of_ssa import out_of_ssa

    tac = TACRelations.from_dir(".temp/my_contract/out")
    out_of_ssa(tac)
    tac.write_dir("out_no_ssa")

As a script it rewrites a decompiler output directory in place (default: the
current directory):

    src/out_of_ssa.py [OUT_DIR]
"""

from __future__ import annotations

from collections import defaultdict
from itertools import pairwise

try:
    from .tac_schema import (
        TACRelations,
        in_function,
        ir_function_call_return,
        local_block_edge,
        tac_block,
        tac_block_head,
        tac_def,
        tac_op,
        tac_phi_operand,
        tac_statement_next,
        tac_stmt,
        tac_use,
        tac_variable_block_value,
        tac_variable_value,
    )
except ImportError:  # run as a script
    from tac_schema import (  # type: ignore[no-redef]
        TACRelations,
        in_function,
        ir_function_call_return,
        local_block_edge,
        tac_block,
        tac_block_head,
        tac_def,
        tac_op,
        tac_phi_operand,
        tac_statement_next,
        tac_stmt,
        tac_use,
        tac_variable_block_value,
        tac_variable_value,
    )

# Copies must be placed before these; any other last statement (other than
# CALLPRIVATE, see module docstring) falls through, so copies go after it.
_BRANCH_OPS = frozenset({"JUMP", "JUMPI"})


Row = tuple[str, ...]


def _as_map(rows: list[Row]) -> dict[str, str]:
    """Index a binary relation by its first column."""
    return {r[0]: r[1] for r in rows}


class OutOfSSAError(ValueError):
    """The TAC cannot be translated out of SSA (e.g. missing PHI operands)."""


def phi_input_var(phi_var: str) -> str:
    """Name of the intermediate variable carrying `phi_var`'s incoming value."""
    return f"{phi_var}_in"


class _FreshIds:
    """Generates statement/block ids of the form `<base>0x<k>`.

    `base` is the (hex) id of the block the new entity belongs to, and `k` is
    the smallest positive number making the id distinct from every identifier
    already in the TAC or previously generated.
    """

    def __init__(self, tac: TACRelations):
        self.taken: set[str] = set()
        for rel in tac.loaded_relations:
            cols = rel.id_column_indices
            for row in tac[rel]:
                self.taken.update(row[i] for i in cols if i < len(row))

    def __call__(self, base: str) -> str:
        k = 1
        while (candidate := f"{base}0x{k:x}") in self.taken:
            k += 1
        self.taken.add(candidate)
        return candidate


def out_of_ssa(tac: TACRelations) -> None:
    """Replace every PHI in `tac` with MOV copies, in-place.

    Raises OutOfSSAError (before modifying anything) if some PHI's operands
    do not map one-to-one onto its block's CFG predecessors.
    """
    ops = _as_map(tac[tac_op])
    phis = [s for s, op in ops.items() if op == "PHI"]
    if not phis:
        return

    block_of = _as_map(tac[tac_block])
    preds: dict[str, set[str]] = defaultdict(set)
    for frm, to in tac[local_block_edge]:
        preds[to].add(frm)

    phi_var: dict[str, str] = {s: v for s, v, _ in tac[tac_def] if ops.get(s) == "PHI"}
    operands: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for phi, var, pred in tac[tac_phi_operand]:
        operands[phi][pred].append(var)

    _check_operands(phis, block_of, preds, phi_var, operands)

    order = _StatementOrder(tac, block_of, ops)

    new_stmts: list[str] = []
    new_ops: dict[str, str] = {}
    new_defs: list[Row] = []
    new_uses: list[Row] = []
    new_blocks: list[Row] = []

    fresh = _FreshIds(tac)
    copies_per_edge: dict[tuple[str, str], list[str]] = defaultdict(list)
    heads_per_block: dict[str, list[str]] = defaultdict(list)
    # Edge (pred, block) -> id of the block inserted on it.
    split_edges = {
        edge: fresh(edge[0])
        for edge in sorted(
            {
                (pred, block_of[phi])
                for phi in phis
                for pred in operands[phi]
                if ops.get(order.last(pred) or "") == "CALLPRIVATE"
            }
        )
    }

    for phi in sorted(phis):
        tmp = phi_input_var(phi_var[phi])
        block = block_of[phi]
        for pred, (var,) in sorted(operands[phi].items()):
            in_block = split_edges.get((pred, block), pred)
            mov = fresh(in_block)
            new_stmts.append(mov)
            new_ops[mov] = "MOV"
            new_defs.append((mov, tmp, "0"))
            new_uses.append((mov, var, "0"))
            new_blocks.append((mov, in_block))
            copies_per_edge[pred, block].append(mov)
        # The PHI statement itself becomes `x = MOV x_in` at the head of its block.
        new_ops[phi] = "MOV"
        new_uses.append((phi, tmp, "0"))
        heads_per_block[block_of[phi]].append(phi)

    # Split edges: the new block ends in `JUMP <const B>`, like any other jump.
    new_values: list[Row] = []
    new_block_values: list[Row] = []
    address_of = _block_addresses(tac)
    for (pred, block), new_block in split_edges.items():
        target, jump = fresh(new_block), fresh(new_block)
        new_stmts += [target, jump]
        new_ops[target], new_ops[jump] = "CONST", "JUMP"
        new_defs.append((target, target, "0"))
        new_uses.append((jump, target, "0"))
        new_blocks += [(target, new_block), (jump, new_block)]
        new_block_values.append((target, block))
        if block in address_of:
            new_values.append((target, address_of[block]))
        copies_per_edge[pred, block] += [target, jump]

    for (pred, block), movs in copies_per_edge.items():
        if (pred, block) in split_edges:
            order.insert_block_after(pred, split_edges[pred, block], movs)
        else:
            order.insert_at_end(pred, movs)
    for block, movs in heads_per_block.items():
        order.insert_at_head(block, movs)

    phi_set = set(phis)
    tac[tac_stmt] = tac[tac_stmt] + [(s,) for s in new_stmts]
    op_rows: list[Row] = [(s, new_ops.get(s, op)) for s, op in tac[tac_op]]
    tac[tac_op] = op_rows + [(s, new_ops[s]) for s in new_stmts]
    tac[tac_def] = tac[tac_def] + new_defs
    tac[tac_use] = [r for r in tac[tac_use] if r[0] not in phi_set] + new_uses
    tac[tac_block] = tac[tac_block] + new_blocks
    tac[tac_variable_value] = tac[tac_variable_value] + new_values
    tac[tac_variable_block_value] = tac[tac_variable_block_value] + new_block_values
    tac[tac_phi_operand] = []
    order.write_back(tac)
    _split_edges(tac, split_edges)


def _block_addresses(tac: TACRelations) -> dict[str, str]:
    """Bytecode address of each IR block that some constant jumps to.

    Taken from the constants Gigahorse emitted rather than derived from the block
    id, which may carry a cloning-context suffix (e.g. `0x3830x519`).
    """
    value = _as_map(tac[tac_variable_value])
    return {block: value[var] for var, block in tac[tac_variable_block_value] if var in value}


def _split_edges(tac: TACRelations, edges: dict[tuple[str, str], str]) -> None:
    """Insert block `edges[p, b]` on each CFG edge p -> b (p ends in CALLPRIVATE)."""
    if not edges:
        return
    func_of = _as_map(tac[in_function])
    tac[local_block_edge] = [r for r in tac[local_block_edge] if (r[0], r[1]) not in edges] + [
        e for (p, b), n in edges.items() for e in ((p, n), (n, b))
    ]
    tac[ir_function_call_return] = [
        (c, f, edges.get((c, r), r)) for c, f, r in tac[ir_function_call_return]
    ]
    tac[in_function] = tac[in_function] + [
        (n, func_of[p]) for (p, _), n in edges.items() if p in func_of
    ]


def _check_operands(
    phis: list[str],
    block_of: dict[str, str],
    preds: dict[str, set[str]],
    phi_var: dict[str, str],
    operands: dict[str, dict[str, list[str]]],
) -> None:
    problems: list[str] = []
    for phi in sorted(phis):
        block = block_of.get(phi)
        if block is None:
            problems.append(f"{phi}: not in any block")
            continue
        if phi not in phi_var:
            problems.append(f"{phi}: defines no variable")
        if phi not in operands:
            problems.append(f"{phi}: no TAC_PhiOperand facts (PHIVar_Pred not computed?)")
            continue
        got = set(operands[phi])
        if got != preds[block]:
            problems.append(
                f"{phi}: operand predecessors {sorted(got)} != CFG predecessors {sorted(preds[block])} of {block}"
            )
        for pred, vars_ in operands[phi].items():
            if len(vars_) != 1:
                problems.append(f"{phi}: {len(vars_)} operands from {pred}: {sorted(vars_)}")
    if problems:
        raise OutOfSSAError(
            f"cannot translate out of SSA ({len(problems)} problems):\n  " + "\n  ".join(problems)
        )


def _address(stmt: str) -> tuple[int, ...]:
    """Hex components of an id, e.g. `0x3830x519` -> (0x383, 0x519); () if not hex.

    Splitting on "0x" is unambiguous since hex digits never contain an `x`.
    """
    try:
        return tuple(int(part, 16) for part in stmt.split("0x")[1:])
    except ValueError:
        return ()


class _StatementOrder:
    """Mutable view of TAC_Statement_Next / TAC_Block_Head.

    The `next` chain follows bytecode order, also across blocks (last statement
    of a block -> first statement of the block after it), and excludes PHIs.
    It only links statements of the same function, and since a function's code
    need not be contiguous, a function usually has several chains.
    """

    def __init__(self, tac: TACRelations, block_of: dict[str, str], ops: dict[str, str]):
        self.block_of = dict(block_of)
        self.ops = ops
        self.next = _as_map(tac[tac_statement_next])
        self.prev: dict[str, str] = {n: s for s, n in self.next.items()}
        self.head = _as_map(tac[tac_block_head])
        self.touched: set[str] = set()
        self.func_of = _as_map(tac[in_function])

        # Where statements of an empty block are appended: per function, the end
        # of its last chain in bytecode order (the successor-less statement at the
        # highest address). Appending moves the end to the appended statements.
        self.tail: dict[str, str] = {}
        for stmt, block in block_of.items():
            func = self.func_of.get(block)
            if func is None or stmt in self.next or ops.get(stmt) == "PHI":
                continue
            if func not in self.tail or _address(stmt) > _address(self.tail[func]):
                self.tail[func] = stmt

        # TAC_Block_Head is missing when a block's first EVM statement is a TAC
        # no-op; recover it as the (non-PHI) statement with no in-block predecessor.
        for stmt, block in block_of.items():
            if block in self.head or ops.get(stmt) == "PHI":
                continue
            p = self.prev.get(stmt)
            if p is None or block_of.get(p) != block:
                self.head[block] = stmt

    def last(self, block: str) -> str | None:
        """Last statement of `block`, or None if it has none."""
        stmt = self.head.get(block)
        if stmt is None:
            return None
        while (n := self.next.get(stmt)) is not None and self.block_of.get(n) == block:
            stmt = n
        return stmt

    def _link(self, a: str, b: str) -> None:
        self.next[a] = b
        self.prev[b] = a

    def _chain(self, block: str, stmts: list[str]) -> None:
        for stmt in stmts:
            self.block_of[stmt] = block
        for a, b in pairwise(stmts):
            self._link(a, b)

    def _splice_after(self, anchor: str, stmts: list[str]) -> None:
        """anchor -> old_next  becomes  anchor -> stmts... -> old_next."""
        after = self.next.get(anchor)
        self._link(anchor, stmts[0])
        if after is not None:
            self._link(stmts[-1], after)
            return
        func = self.func_of.get(self.block_of.get(anchor, ""))
        if func is not None and self.tail.get(func) == anchor:
            self.tail[func] = stmts[-1]

    def _fill_empty(self, block: str, stmts: list[str]) -> None:
        """Make `stmts` the contents of empty `block`, appended to its function's chain."""
        self.head[block] = stmts[0]
        self._chain(block, stmts)
        func = self.func_of.get(block)
        if func is None:
            return
        if (tail := self.tail.get(func)) is not None:
            self._link(tail, stmts[0])
        self.tail[func] = stmts[-1]

    def insert_at_end(self, block: str, stmts: list[str]) -> None:
        """Place `stmts` at the end of `block`, before a JUMP/JUMPI terminator."""
        self.touched.add(block)
        last = self.last(block)
        if last is None:
            self._fill_empty(block, stmts)
        elif self.ops.get(last) in _BRANCH_OPS:
            self._insert_before(block, last, stmts)
        else:
            self._chain(block, stmts)
            self._splice_after(last, stmts)

    def insert_block_after(self, block: str, new_block: str, stmts: list[str]) -> None:
        """Place `stmts` as the contents of `new_block`, right after `block` in statement order."""
        self.touched.add(new_block)
        if block in self.func_of:
            self.func_of[new_block] = self.func_of[block]
        last = self.last(block)
        if last is None:
            self._fill_empty(new_block, stmts)
            return
        self.head[new_block] = stmts[0]
        self._chain(new_block, stmts)
        self._splice_after(last, stmts)

    def insert_at_head(self, block: str, stmts: list[str]) -> None:
        """Place `stmts` at the start of `block`."""
        self.touched.add(block)
        first = self.head.get(block)
        if first is None:
            self._fill_empty(block, stmts)
        else:
            self._insert_before(block, first, stmts)

    def _insert_before(self, block: str, anchor: str, stmts: list[str]) -> None:
        before = self.prev.get(anchor)
        if before is not None:
            self._link(before, stmts[0])
        self._chain(block, stmts)
        self._link(stmts[-1], anchor)
        if self.head.get(block) == anchor:
            self.head[block] = stmts[0]

    def write_back(self, tac: TACRelations) -> None:
        heads: list[Row] = [r for r in tac[tac_block_head] if r[0] not in self.touched]
        tac[tac_statement_next] = [(s, n) for s, n in self.next.items()]
        tac[tac_block_head] = heads + [(b, self.head[b]) for b in sorted(self.touched)]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Replace PHIs with MOVs in a decompiler output directory, in place."
    )
    parser.add_argument(
        "out_dir", nargs="?", default=".", help="decompiler output directory (default: current)"
    )
    args = parser.parse_args(argv)

    try:
        tac = TACRelations.from_dir(args.out_dir)
        phis = sum(op == "PHI" for _, op in tac[tac_op])
        blocks = {b for e in tac[local_block_edge] for b in e}
        out_of_ssa(tac)
    except (FileNotFoundError, OutOfSSAError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    tac.write_dir(args.out_dir)
    new_blocks = len({b for e in tac[local_block_edge] for b in e} - blocks)
    print(f"{args.out_dir}: replaced {phis} PHIs, added {new_blocks} blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
