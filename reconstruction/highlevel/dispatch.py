"""Selector dispatch: payability decided by the dispatcher, and table dispatchers.

- A `require(!msg.value)` in the dispatcher applies to every public function
  dispatched after it on the same path (Vyper 0.2 checks once, after its
  payable functions; solc checks before any branch when nothing is payable).
- Vyper 0.3.10+ dispatches through a table in the code (src/selector_table.py
  executes it). The lifted dispatcher is an unstructured computed jump; it is
  printed instead as the selector chain the execution established: for each
  public function, the selector that reaches it and the checks the dispatcher
  makes first (value, calldata size), then `revert()` for any other selector
  (only when executing the dispatcher shows exactly that). The original
  statements stay as the chain's evidence.
"""

from __future__ import annotations

from collections import defaultdict

from src.selector_table import selector_table

from .ir import (
    Binary,
    Call,
    Comment,
    Const,
    Env,
    ExprStmt,
    If,
    RawBlock,
    Require,
    Return,
    Revert,
    Stmt,
    Unary,
)
from .passes import iter_statements, statement_ids

DISPATCHER = "__function_selector__"
SPECIAL = {"0x00000000", "0xeeeeeeee"}  # fallback / receive pseudo-selectors
TABLE_RULE = "selector-table"


def _is_value_check(stmt: Stmt) -> bool:
    return (
        isinstance(stmt, Require)
        and stmt.payload is None
        and isinstance(stmt.condition, Unary)
        and stmt.condition.op == "!"
        and stmt.condition.operand == Env("msg.value")
    )


def dispatch_value_checks(views) -> dict[str, Stmt]:
    """Public function name -> the dispatcher's value check every call of it follows."""
    dispatcher = next((v for v in views if v.name == DISPATCHER), None)
    if dispatcher is None:
        return {}
    sites: defaultdict[str, list[Stmt | None]] = defaultdict(list)

    def calls(stmt: Stmt) -> list[str]:
        exprs = stmt.values if isinstance(stmt, Return) else (stmt.expr,)
        return [e.name for e in exprs if isinstance(e, Call)]

    def walk(body: list[Stmt], check: Stmt | None) -> None:
        # Earlier statements of a list run before every later one (structured code).
        for stmt in body:
            if _is_value_check(stmt):
                check = stmt
            elif isinstance(stmt, If):
                walk(stmt.then, check)
                walk(stmt.otherwise, check)
            elif isinstance(stmt, RawBlock):
                walk(stmt.body, None)  # unstructured: no dominance claimed
            elif isinstance(stmt, (Return, ExprStmt)):
                for name in calls(stmt):
                    sites[name].append(check)

    walk(dispatcher.body, None)
    return {name: found[0] for name, found in sites.items() if all(found)}


def table_dispatcher(runtime_bytecode: str | None, views) -> bool:
    """Print a selector-table dispatcher as its selector chain; True when rewritten."""
    dispatcher = next((v for v in views if v.name == DISPATCHER), None)
    if dispatcher is None or not runtime_bytecode:
        return False
    table = selector_table(bytes.fromhex(runtime_bytecode.removeprefix("0x")))
    if not table.jumps or not table.fallback_reverts:
        return False
    public = {
        int(v.function.selectors[0], 16): v
        for v in views
        if len(v.function.selectors) == 1 and v.function.selectors[0] not in SPECIAL
    }
    entries = {selector: payable for _, selector, payable in table.entries}
    if entries and set(entries) != set(public):
        return False  # a checked-selector table must route exactly the public functions
    if not table.routed <= set(public):
        return False  # a selector the dispatcher routes has no public function here
    evidence = frozenset().union(*(statement_ids(s) for s in dispatcher.body))
    rules = frozenset({TABLE_RULE})
    body: list[Stmt] = [
        Comment(
            "Selector table (rule selector-table): the dispatcher reads msg.sig's entry from a "
            "table in the code and jumps to it; each branch is what executing it does.",
            evidence=evidence,
            rules=rules,
        )
    ]
    for selector, view in sorted(public.items()):
        then: list[Stmt] = []
        if entries:
            # Checked by the dispatcher before the jump, from the entry's flags.
            if not entries[selector]:
                then.append(Require(Unary("!", Env("msg.value")), rules=rules))
            size = table.min_sizes.get(selector, 0)
            if size:
                then.append(Require(Binary(">=", Env("msg.data.length"), Const(size)), rules=rules))
        then.append(Return((Call(view.name, ()),), rules=frozenset({"tail-call"}) | rules))
        body.append(If(Binary("==", Env("msg.sig"), Const(selector)), then, rules=rules))
    body.append(Revert(rules=rules))
    dispatcher.body = body
    dispatcher.state.body = body
    dispatcher.structured = True
    return True


def uses_table(views) -> bool:
    return any(
        TABLE_RULE in stmt.rules
        for view in views
        if view.name == DISPATCHER
        for stmt in iter_statements(view.body)
    )
