"""Structure resolved CFG edges into regions; retain ambiguity explicitly."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .model import Function, Instruction, Program


class Unstructured(ValueError):
    pass


@dataclass(frozen=True)
class Transfer:
    kind: str
    targets: tuple[str, ...] = ()  # Conditional: nonzero target, zero target.
    statement: str | None = None
    predicate: str | None = None
    ignored_terminal_targets: tuple[str, ...] = ()
    # A JUMP into another public function's entry (e.g. old dispatchers falling
    # back to the fallback function): control never returns, a tail call.
    callee: str | None = None


@dataclass(frozen=True)
class Copy:
    destination: str
    source: str
    phi: str


@dataclass
class Region:
    kind: str
    block: str | None = None
    target: str | None = None
    source: str | None = None
    children: list[Region] = field(default_factory=list)
    inverted: bool = False


@dataclass
class FlowPlan:
    function: str
    region: Region | None
    transfers: dict[str, Transfer]
    copies: dict[tuple[str, str], list[Copy]]
    resolved_phis: set[str]
    unresolved_phis: list[str]
    reachable_blocks: set[str]
    warnings: list[str]
    entry_copies: list[Copy] = field(default_factory=list)
    # Duplicated nodes ('<block>@<n>') -> original block id; empty without splitting.
    origin: dict[str, str] = field(default_factory=dict)


@dataclass
class NaturalLoop:
    header: str
    nodes: set[str]
    exit: str | None


def _reach(start: str, edges: dict[str, tuple[str, ...]]) -> set[str]:
    seen, todo = set(), [start]
    while todo:
        node = todo.pop()
        if node not in seen:
            seen.add(node)
            todo.extend(edges[node])
    return seen


def dominators(entry: str, edges: dict[str, tuple[str, ...]]) -> dict[str, set[str]]:
    reachable = _reach(entry, edges)
    predecessors: defaultdict[str, set[str]] = defaultdict(set)
    for node in reachable:
        for target in edges[node]:
            predecessors[target].add(node)
    dom = {node: {node} if node == entry else set(reachable) for node in reachable}
    changed = True
    while changed:
        changed = False
        for node in sorted(reachable - {entry}):
            value = {node} | set.intersection(*(dom[p] for p in predecessors[node]))
            if value != dom[node]:
                dom[node] = value
                changed = True
    return dom


def _postdominators(edges: dict[str, tuple[str, ...]]) -> dict[str, str | None]:
    """No merge is inferred through a region with an unmodelled divergent path."""
    exit_node = "@virtual-exit"
    graph = {node: targets or (exit_node,) for node, targets in edges.items()}
    graph[exit_node] = ()
    reverse: defaultdict[str, list[str]] = defaultdict(list)
    for node, targets in graph.items():
        for target in targets:
            reverse[target].append(node)
    reaches_exit = _reach(exit_node, {node: tuple(reverse[node]) for node in graph})
    pd = {
        node: {node} if node == exit_node or node not in reaches_exit else set(reaches_exit)
        for node in graph
    }
    changed = True
    while changed:
        changed = False
        for node in sorted(reaches_exit - {exit_node}):
            value = {node} | set.intersection(*(pd[target] for target in graph[node]))
            if value != pd[node]:
                pd[node] = value
                changed = True
    immediate = {}
    for node in edges:
        strict = pd[node] - {node}
        nearest = [candidate for candidate in strict if strict - {candidate} <= pd[candidate]]
        immediate[node] = nearest[0] if len(nearest) == 1 and nearest[0] != exit_node else None
    return immediate


def build_transfers(
    program: Program,
    function: Function,
    *,
    call_returns: list[tuple[str, str, str]] | None = None,
    allow_multiple_jumps: bool = False,
    public_tail_jumps: bool = False,
) -> dict[str, Transfer]:
    blocks = {block.id: block for block in program.blocks}
    members = set(function.blocks)
    public_entries = {
        _block_address(other.entries[0]): other.id
        for other in (program.functions if public_tail_jumps else ())
        if other.selectors and len(other.entries) == 1 and other.id != function.id
    }
    continuations: defaultdict[str, set[str]] = defaultdict(set)
    if call_returns is None:
        call_returns = program.semantics.call_returns if program.semantics else []
    for caller, _callee, continuation in call_returns:
        continuations[caller].add(continuation)
    transfers = {}
    for block_id in function.blocks:
        block = blocks[block_id]
        tail = block.instructions[-1] if block.instructions else None
        successors = set(block.successors)
        op = tail.opcode if tail else ""
        if op in {"RETURN", "REVERT", "STOP", "SELFDESTRUCT", "INVALID"}:
            # An EVM halt cannot follow an inliner's synthetic continuation edge.
            # Preserve the original edge in the IR and in this plan's metadata.
            transfers[block_id] = Transfer(
                "end",
                statement=tail.id if tail else None,
                ignored_terminal_targets=tuple(sorted(successors)),
            )
            continue
        if successors - members:
            raise Unstructured(f"CFG edge leaves function at {block_id}")
        if op in {
            "THROW",
            "RETURNPRIVATE",
            "EXIT",
        }:
            if successors:
                raise Unstructured(f"Terminal instruction has successors at {block_id}")
            transfers[block_id] = Transfer("end", statement=tail.id if tail else None)
        elif op in {"JUMP", "JUMPI"}:
            arity = 2 if op == "JUMPI" else 1
            if op == "JUMP" and tail is not None and not tail.operands and len(successors) == 1:
                # Target already resolved by the native analysis: a plain goto.
                transfers[block_id] = Transfer("goto", tuple(successors), tail.id)
                continue
            if tail is None or len(tail.operands) != arity:
                raise Unstructured(f"Malformed jump at {block_id}")
            destination = program.block_targets.get(
                tail.operands[0], program.constants.get(tail.operands[0])
            )
            if op == "JUMP":
                # Inlining changes block identities while the pushed EVM address stays
                # unchanged. A single recovered CFG edge identifies that renamed label.
                callee = public_entries.get(_block_address(destination)) if destination else None
                if not successors and callee is not None:
                    transfers[block_id] = Transfer("end", (), tail.id, callee=callee)
                    continue
                if len(successors) != 1:
                    if allow_multiple_jumps and successors <= members:
                        transfers[block_id] = Transfer("multi", tuple(sorted(successors)), tail.id)
                        continue
                    raise Unstructured(f"Multiple jump outcomes at {block_id}")
                transfers[block_id] = Transfer("goto", tuple(successors), tail.id)
            else:
                if len(block.fallthrough) != 1:
                    raise Unstructured(f"Unresolved fallthrough at {block_id}")
                other = block.fallthrough[0]
                if destination not in successors and len(successors - {other}) == 1:
                    destination = next(iter(successors - {other}))
                if successors != {destination, other} or destination == other:
                    raise Unstructured(f"Ambiguous branch outcomes at {block_id}")
                assert destination is not None
                transfers[block_id] = Transfer(
                    "if", (destination, other), tail.id, tail.operands[1]
                )
        elif op == "CALLPRIVATE":
            targets = continuations[block_id] | successors
            if len(targets) > 1 or targets - members:
                raise Unstructured(f"Ambiguous internal call continuation at {block_id}")
            transfers[block_id] = Transfer(
                "goto" if targets else "end", tuple(targets), tail.id if tail else None
            )
        elif len(successors) == 1:
            transfers[block_id] = Transfer("goto", tuple(successors))
        elif successors:
            raise Unstructured(f"Unresolved control flow at {block_id}")
        else:
            raise Unstructured(f"Missing terminal instruction at {block_id}")
    return transfers


def phi_copies(
    program: Program, function: Function, transfers: dict[str, Transfer]
) -> tuple[dict[tuple[str, str], list[Copy]], set[str], list[str], list[Copy]]:
    predecessors: defaultdict[str, set[str]] = defaultdict(set)
    for source, transfer in transfers.items():
        for target in transfer.targets:
            predecessors[target].add(source)
    candidates: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for phi, predecessor, variable in program.phi_inputs:
        candidates[(phi, predecessor)].add(variable)
    entry_candidates: defaultdict[str, set[str]] = defaultdict(set)
    for phi, value in program.phi_entry_inputs:
        entry_candidates[phi].add(value)
    copies: defaultdict[tuple[str, str], list[Copy]] = defaultdict(list)
    entry_copies: list[Copy] = []
    resolved, unresolved = set(), []
    blocks = {block.id: block for block in program.blocks}
    for block_id in function.blocks:
        for stmt in blocks[block_id].instructions:
            if stmt.opcode != "PHI":
                continue
            incoming = predecessors[block_id]
            known = {pred: candidates[(stmt.id, pred)] for pred in sorted(incoming)}
            initial = entry_candidates[stmt.id]
            is_entry = block_id in function.entries
            if (
                len(stmt.definitions) != 1
                or (
                    is_entry
                    and (len(initial) != 1 or not initial <= set(function.formal_variables))
                )
                or (not is_entry and initial)
                or not initial <= set(stmt.operands)
                or (not incoming and not is_entry)
                or any(
                    len(values) != 1 or not values <= set(stmt.operands)
                    for values in known.values()
                )
            ):
                unresolved.append(stmt.id)
                continue
            resolved.add(stmt.id)
            if is_entry:
                entry_copies.append(Copy(stmt.definitions[0], next(iter(initial)), stmt.id))
            for pred, values in known.items():
                copies[(pred, block_id)].append(
                    Copy(stmt.definitions[0], next(iter(values)), stmt.id)
                )
    return dict(copies), resolved, sorted(unresolved), entry_copies


def structure_function(
    program: Program,
    function: Function,
    *,
    call_returns: list[tuple[str, str, str]] | None = None,
    ignore_failure_paths: bool = False,
    split_shared_returns: bool = False,
    public_tail_jumps: bool = False,
) -> FlowPlan:
    """Structure a function's CFG.

    With ignore_failure_paths, merge points are computed as if successors that can
    only revert/abort did not exist. A guard's failure arm then no longer prevents
    the code after an if/else from being recognized as its join. The failure arms
    are still emitted; only the choice of join changes.
    """
    transfers: dict[str, Transfer] = {}
    copies: dict[tuple[str, str], list[Copy]] = {}
    resolved: set[str] = set()
    unresolved: list[str] = []
    reachable: set[str] = set()
    entry_copies: list[Copy] = []
    try:
        if len(function.entries) != 1:
            raise Unstructured("Function does not have one resolved entry")
        transfers = build_transfers(
            program,
            function,
            call_returns=call_returns,
            allow_multiple_jumps=split_shared_returns,
            public_tail_jumps=public_tail_jumps,
        )
        copies, resolved, unresolved, entry_copies = phi_copies(program, function, transfers)
        origin: dict[str, str] = {}
        if split_shared_returns and any(t.kind == "multi" for t in transfers.values()):
            transfers, copies, origin = split_shared_regions(program, function, transfers, copies)
        entry = function.entries[0]
        edges = {node: transfer.targets for node, transfer in transfers.items()}
        reachable = _reach(entry, edges)
        edges = {node: edges[node] for node in reachable}
        dom = dominators(entry, edges)
        if ignore_failure_paths:
            failing = _failure_nodes(edges, program)
            postdom = _postdominators(
                {
                    node: tuple(t for t in targets if t not in failing) or targets
                    for node, targets in edges.items()
                }
            )
        else:
            postdom = _postdominators(edges)
        predecessors: defaultdict[str, set[str]] = defaultdict(set)
        for source, targets in edges.items():
            for target in targets:
                predecessors[target].add(source)
        loop_nodes: defaultdict[str, set[str]] = defaultdict(set)
        for source, targets in edges.items():
            for header in targets:
                if header not in dom[source]:
                    continue
                body = {header, source}
                todo = [source] if source != header else []
                while todo:
                    node = todo.pop()
                    for pred in predecessors[node] - body:
                        body.add(pred)
                        if pred != header:
                            todo.append(pred)
                loop_nodes[header].update(body)
        loops = {}
        for header, body in loop_nodes.items():
            if any(pred not in body for node in body - {header} for pred in predecessors[node]):
                raise Unstructured(f"Loop has multiple entries at {header}")
            exits = {target for node in body for target in edges[node] if target not in body}
            header_exits = set(edges[header]) - body
            normal = [node for node in header_exits if not _only_reverts(node, edges, program)]
            exit_target = normal[0] if len(normal) == 1 else postdom[header]
            if exit_target in body:
                exit_target = None
            if exit_target is None:
                remaining = [node for node in exits if not _only_reverts(node, edges, program)]
                if len(remaining) == 1:
                    exit_target = remaining[0]
            loops[header] = NaturalLoop(header, body, exit_target)
        bodies = list(loops.values())
        for index, first in enumerate(bodies):
            for second in bodies[index + 1 :]:
                if first.nodes & second.nodes and not (
                    first.nodes <= second.nodes or second.nodes <= first.nodes
                ):
                    raise Unstructured("Overlapping loops cannot be structured")
        budget = max(256, len(reachable) * 32)

        def advance(
            source: str,
            target: str,
            stop: str | None,
            active: tuple[NaturalLoop, ...],
            seen: frozenset[str],
        ) -> Region:
            edge = Region("edge", source=source, target=target)
            if active:
                loop = active[-1]
                if target == loop.header:
                    return Region(
                        "sequence",
                        children=[edge, Region("continue", target=target, source=source)],
                    )
                if target == loop.exit:
                    return Region(
                        "sequence", children=[edge, Region("break", target=target, source=source)]
                    )
                if any(target in {outer.header, outer.exit} for outer in active[:-1]):
                    raise Unstructured("Control transfers across nested loop boundaries")
            return Region("sequence", children=[edge, walk(target, stop, active, seen)])

        def walk(
            start: str, stop: str | None, active: tuple[NaturalLoop, ...], seen: frozenset[str]
        ) -> Region:
            nonlocal budget
            items = []
            current = start
            while current != stop:
                budget -= 1
                if budget < 0:
                    raise Unstructured("Region expansion limit exceeded")
                if current in seen:
                    raise Unstructured(f"Irreducible or unresolved cycle at {current}")
                if current in loops and all(loop.header != current for loop in active):
                    loop = loops[current]
                    body = walk(current, None, (*active, loop), seen)
                    items.append(Region("loop", block=current, target=loop.exit, children=[body]))
                    if loop.exit is None:
                        return Region("sequence", children=items)
                    current = loop.exit
                    continue
                seen = seen | {current}
                items.append(Region("block", block=current))
                transfer = transfers[current]
                if transfer.kind == "end":
                    return Region("sequence", children=items)
                if transfer.kind == "goto":
                    target = transfer.targets[0]
                    if active and (target == active[-1].header or target == active[-1].exit):
                        items.append(advance(current, target, stop, active, seen))
                        return Region("sequence", children=items)
                    items.append(Region("edge", source=current, target=target))
                    current = target
                    continue
                join = postdom[current]
                if join is not None and active and join not in active[-1].nodes:
                    join = None
                if join is not None and any(join == loop.header for loop in active):
                    join = None
                arms = [
                    advance(current, target, join or stop, active, seen)
                    for target in transfer.targets
                ]
                items.append(Region("if", block=current, children=arms))
                if join is None:
                    return Region("sequence", children=items)
                current = join
            return Region("sequence", children=items)

        region = _flatten_terminal_branches(walk(entry, None, (), frozenset()), transfers)
        return FlowPlan(
            function.id,
            region,
            transfers,
            copies,
            resolved,
            unresolved,
            reachable,
            ([f"Unresolved PHI inputs: {', '.join(unresolved)}"] if unresolved else [])
            + [
                f"Ignored non-executable IR edges after EVM halt at {block}: {', '.join(t.ignored_terminal_targets)}"
                for block, t in transfers.items()
                if t.ignored_terminal_targets
            ],
            entry_copies,
            origin,
        )
    except (Unstructured, KeyError) as exc:
        return FlowPlan(
            function.id,
            None,
            transfers,
            copies,
            resolved,
            unresolved,
            reachable,
            [str(exc)],
            entry_copies,
        )


def _block_address(block_id: str) -> int | None:
    """Bytecode address a (possibly cloned) block id starts with: '0x6cb3bB0x731' -> 0x6cb3b."""
    import re

    match = re.match(r"0x[0-9a-f]+", block_id)
    return int(match.group(0), 16) if match else None


def _original(node: str) -> str:
    """Block id of a (possibly duplicated) node: virtual copies are '<block>@<n>'."""
    return node.split("@", 1)[0]


def _failure_nodes(edges: dict[str, tuple[str, ...]], program: Program) -> set[str]:
    """Nodes from which every path ends in REVERT/THROW/INVALID (least fixpoint)."""
    blocks = {block.id: block for block in program.blocks}
    blocks.update({node: blocks[_original(node)] for node in edges if node not in blocks})
    failing = {
        node
        for node, targets in edges.items()
        if not targets
        and blocks[node].instructions
        and blocks[node].instructions[-1].opcode in {"REVERT", "THROW", "INVALID"}
    }
    changed = True
    while changed:
        changed = False
        for node, targets in edges.items():
            if node not in failing and targets and all(t in failing for t in targets):
                failing.add(node)
                changed = True
    return failing


def _only_reverts(start: str, edges: dict[str, tuple[str, ...]], program: Program) -> bool:
    blocks = {block.id: block for block in program.blocks}
    blocks.update({node: blocks[_original(node)] for node in edges if node not in blocks})
    reached = _reach(start, edges)
    ends = [node for node in reached if not edges[node]]
    return bool(ends) and all(
        blocks[node].instructions
        and blocks[node].instructions[-1].opcode in {"REVERT", "THROW", "INVALID"}
        for node in ends
    )


def plan_metadata(plan: FlowPlan) -> dict:
    return {
        "function": plan.function,
        "status": "structured-partial"
        if plan.region and plan.unresolved_phis
        else "structured"
        if plan.region
        else "explicit-cfg",
        "warnings": plan.warnings,
        "resolved_phis": sorted(plan.resolved_phis),
        "entry_assignments": [asdict(copy) for copy in plan.entry_copies],
        "unresolved_phis": plan.unresolved_phis,
        "reachable_blocks": sorted(plan.reachable_blocks),
        "region": asdict(plan.region) if plan.region else None,
        "transfers": {
            block: {
                key: value
                for key, value in asdict(transfer).items()
                if key != "callee" or value is not None
            }
            for block, transfer in plan.transfers.items()
        },
        "edge_assignments": [
            {"source": source, "target": target, "copies": [asdict(copy) for copy in copies]}
            for (source, target), copies in sorted(plan.copies.items())
        ],
    }


def _flatten_terminal_branches(region: Region, transfers: dict[str, Transfer]) -> Region:
    """Move a continuation past an if only when its other arm cannot fall through."""
    region.children = [_flatten_terminal_branches(child, transfers) for child in region.children]

    def stops(node: Region) -> bool:
        if node.kind == "block":
            return transfers[node.block or ""].kind == "end"
        if node.kind in {"break", "continue"}:
            return True
        if node.kind == "loop":
            return node.target is None
        if node.kind == "sequence":
            return any(stops(child) for child in node.children)
        if node.kind == "if":
            return all(stops(child) for child in node.children)
        return False

    if region.kind == "if":
        first, second = region.children
        first_stops, second_stops = stops(first), stops(second)

        def size(node: Region) -> int:
            return 1 + sum(size(child) for child in node.children)

        # If both arms halt, preserve the smaller arm as an early guard. Keeping
        # an entire successful function inside nested guards obscures its body.
        if first_stops and (not second_stops or size(first) <= size(second)):
            return Region(
                "sequence",
                children=[
                    Region(
                        "if",
                        block=region.block,
                        children=[first, Region("sequence")],
                        inverted=region.inverted,
                    ),
                    second,
                ],
            )
        if second_stops:
            return Region(
                "sequence",
                children=[
                    Region(
                        "if",
                        block=region.block,
                        children=[second, Region("sequence")],
                        inverted=not region.inverted,
                    ),
                    first,
                ],
            )
    return region


def split_shared_regions(
    program: Program,
    function: Function,
    transfers: dict[str, Transfer],
    copies: dict[tuple[str, str], list[Copy]],
    *,
    max_rounds: int = 16,
    max_nodes: int = 6000,
) -> tuple[dict[str, Transfer], dict[tuple[str, str], list[Copy]], dict[str, str]]:
    """Tail-duplicate shared regions that return through a constant-address PHI.

    A JUMP with several recovered successors whose target is a PHI of constant
    return addresses (one per entering edge) is an unrecovered internal call:
    the region from the PHI's block H to the JUMP is entered only at H. Each
    entering edge gets its own copy of the region ('<block>@<n>'), whose JUMP
    goes to that edge's continuation. Copies reuse the original IR (instructions,
    PHI edge copies); only graph nodes are duplicated. Anything else raises
    Unstructured, keeping the explicit CFG.
    """
    blocks = {block.id: block for block in program.blocks}
    definitions = {
        v: (block_id, stmt)
        for block_id in function.blocks
        for stmt in blocks[block_id].instructions
        for v in stmt.definitions
    }
    phi_values: dict[tuple[str, str], set[str]] = defaultdict(set)
    for phi, predecessor, value in program.phi_inputs:
        phi_values[(phi, predecessor)].add(value)
    transfers = dict(transfers)
    copies = {key: list(value) for key, value in copies.items()}
    origin: dict[str, str] = {}
    counter = 0

    def original(node: str) -> str:
        return origin.get(node, node)

    def _address(variable: str) -> int | None:
        block = program.block_targets.get(variable)
        if block is not None:
            return _block_address(block)
        value = program.constants.get(variable)
        return int(value, 16) if value is not None else None

    def dispatch_phi(variable: str) -> tuple[str, Instruction] | None:
        """The PHI choosing among return addresses, through single-source copy PHIs."""
        seen: set[str] = set()
        while variable in definitions and variable not in seen:
            seen.add(variable)
            block_id, stmt = definitions[variable]
            if stmt.opcode != "PHI":
                return None
            sources = set(stmt.operands) - set(stmt.definitions)
            if len(sources) != 1:
                return block_id, stmt
            variable = next(iter(sources))
        return None

    for _ in range(max_rounds):
        multis = sorted(node for node, t in transfers.items() if t.kind == "multi")
        if not multis:
            return transfers, copies, origin
        predecessors: defaultdict[str, set[str]] = defaultdict(set)
        for source, transfer in transfers.items():
            for target in transfer.targets:
                predecessors[target].add(source)
        j = multis[0]
        jump = next(
            (s for s in blocks[original(j)].instructions if s.id == transfers[j].statement), None
        )
        found = dispatch_phi(jump.operands[0]) if jump is not None and jump.operands else None
        if found is None:
            raise Unstructured(f"Multiple jump outcomes at {j}")
        phi_block, phi = found
        heads = [n for n in transfers if original(n) == phi_block]
        # The region ends at j (its outgoing edges lead back to the callers) and
        # starts at the nearest copy of the head: paths through other copies are cut.
        edges = {n: (() if n == j else t.targets) for n, t in transfers.items()}
        forward = {
            h: _reach(
                h,
                {
                    n: tuple(x for x in targets if x == h or x not in heads)
                    for n, targets in edges.items()
                },
            )
            for h in heads
        }
        candidates = [h for h in heads if j in forward[h]]
        if len(candidates) != 1:
            raise Unstructured(f"Ambiguous shared region head for {j}")
        head = candidates[0]
        reverse = {n: tuple(predecessors[n]) for n in transfers}
        region = forward[head] & _reach(j, reverse)
        if any(not predecessors[n] <= region for n in region - {head}):
            raise Unstructured(f"Shared region at {head} has several entries")
        callers = sorted(predecessors[head] - region)
        if not callers or predecessors[head] & region:
            raise Unstructured(f"Shared region at {head} is not a plain call target")
        continuation = {}
        for caller in callers:
            values = phi_values.get((phi.id, original(caller)), set())
            if len(values) != 1:
                raise Unstructured(f"Return address of {caller} into {head} is unknown")
            matches = [
                t
                for t in transfers[j].targets
                if _block_address(original(t)) == _address(next(iter(values)))
            ]
            if len(matches) != 1:
                raise Unstructured(f"Return address of {caller} into {head} is not a successor")
            continuation[caller] = matches[0]
        if len(transfers) + len(region) * len(callers) > max_nodes:
            raise Unstructured("Shared-region duplication limit exceeded")
        for caller in callers:
            counter += 1
            rename = {n: f"{original(n)}@{counter}" for n in region}
            for n, new in rename.items():
                origin[new] = original(n)
                t = transfers[n]
                if n == j:
                    transfers[new] = Transfer("goto", (continuation[caller],), t.statement)
                else:
                    transfers[new] = Transfer(
                        t.kind,
                        tuple(rename.get(x, x) for x in t.targets),
                        t.statement,
                        t.predicate,
                        t.ignored_terminal_targets,
                    )
            for (a, b), values in list(copies.items()):
                if a in region and b in region:
                    copies[(rename[a], rename[b])] = values
                elif a == j and b == continuation[caller]:
                    copies[(rename[a], b)] = values
            if (caller, head) in copies:
                copies[(caller, rename[head])] = copies[(caller, head)]
            caller_transfer = transfers[caller]
            transfers[caller] = Transfer(
                caller_transfer.kind,
                tuple(rename[head] if x == head else x for x in caller_transfer.targets),
                caller_transfer.statement,
                caller_transfer.predicate,
                caller_transfer.ignored_terminal_targets,
            )
        for n in region:
            transfers.pop(n, None)
        copies = {
            key: value
            for key, value in copies.items()
            if key[0] not in region and key[1] not in region
        }
    raise Unstructured("Shared-region splitting did not converge")
