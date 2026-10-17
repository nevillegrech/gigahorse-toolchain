# Objective and completion evidence

> Build a local EVM decompiler that makes unverified contracts nearly as
> understandable as Dedaub, with bytecode evidence behind its output and
> clearly marked uncertainty.

This objective remains active. The sixteen fixture cases are development tests;
they are not the scope of the finished tool.

Completion must be judged on contracts selected before the final tuning pass.
That corpus should span compiler versions and optimization settings, common token
and protocol patterns, proxies, dynamic ABI values and difficult control flow.
The same bytecode must be assessed alongside saved Dedaub output. Reviewers should
be able to identify function inputs/outputs, authorization conditions, storage
effects and external interactions with comparable accuracy and effort. Record
incorrect claims, missing behavior, explicit unknowns, failures and analysis time;
do not turn an unknown into a confident answer to improve a coverage score.

Behavioral checks must accompany new reconstruction features, covering both
successful execution and failure paths. Retain bytecode hashes and supporting
IR for results, and report the tested scope. A fixture pass does not establish
general equivalence, and an analysis timeout must remain a visible failure.

| Requirement | Current authoritative evidence | Remaining work |
| --- | --- | --- |
| Local bytecode analysis | `reconstruct.py decompile`, native Gigahorse runs and opt-in live tests | Broader bytecode/compiler coverage, reproducible installation and resource limits |
| Readable storage and state transitions | Stable exports and source-layout regressions; native bool hints retain integer alternatives; exact packed-bit extraction and read-lifetime checks with source maps; WETH/registry differential cases | Complex structs, packed arrays, transient storage corpus and uncertain/conflicting models |
| Useful function interfaces | Raw calldata views, checked nested fields and call/condition roles, hash-checked signature hints, raw return-word evidence and candidate array/tuple/byte encodings | More encoder patterns, recursive layouts, stronger interprocedural type propagation and broader signature coverage; original names/types can remain ambiguous |
| Readable control flow | Structured if/else and natural loops; precise PHI edge values; generated local names with SSA/bytecode maps; control-only return-PC inputs omitted from twelve private interfaces and 57 call sites; EVM halts discard non-executable continuation edges with evidence retained; terminal payload helpers with complete IR maps and bound code-copy evidence; explicit fallback status | SSA coalescing, loop-role inference, broader expression-lifetime proofs, irreducible flow, useful internal helper summaries and dynamic encoder abstractions |
| Understandable external behavior | Call kinds/operands, ABI words through bounded MCOPY chains, signature hints, return-data snapshots, observed storage roles and proxy forwarding/caller-path summaries; decoded Error/Panic bytes, partial selectors and guard-payload annotations | Dynamic ABI values, events, custom/dynamic errors, interprocedural authority and state-effect summaries, reentrancy and broader proxy patterns |
| Bytecode evidence | Original relations, IR provenance, per-line evidence maps and input hashes | Evidence mapping for every new higher-level transformation and broader negative tests |
| Clearly marked uncertainty | Type candidates, unresolved `word` arguments, unmapped statements and complete raw output | More precise uncertainty for incomplete CFGs, unsupported semantics and ambiguous signatures |
| Near-Dedaub usefulness | Sixteen compiler fixtures and two frozen selections totaling eight deployed runtimes (seven absent from upstream regressions); twelve second-selection task reviews with IR/source anchors; current comparison packets | Broader unseen contracts, dynamic ABI/proxy explanations and an actual side-by-side Dedaub assessment; see EVALUATION.md |
| Confidence in semantic reconstruction | 343 tests pass with seventeen opt-in native skips; WETH/registry cases, 31 NFT guards/admin calls and 17 code-copy EVM scenarios; 173,580 reported expression, 1,984 path, 722 storage-read and 210 private-call checks across 993 reported input scenarios; bit/lifetime/memory/proof-corruption negative coverage | Symbolic pointer/range analysis, broader behavioral corpus, standalone emitted-text validation, reentrancy/world-state execution and validation of further high-level transformations |
| Compatibility with upstream analyses | All 66 upstream native regressions pass with four workers after the restored-JUMP operand fix; all 16 compiler fixtures and four deployed cases rerun; atomic binary publication and per-key cold-build locks | Pin executable identities across simultaneous different configurations and source edits; continue native compatibility checks |

### Status update 2026-10-16: readable decompiled view (branch `improvements`)

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Readable code | `decompiled.sol.txt`: corpus code lines 4,861 vs 9,996 in `structured.sol.txt`; WETH9 106 lines, close to its source; shared regions without a recovered function are split per caller (pair `skim`), and dispatch jumps into the fallback are printed as tail calls (cETH) | 0.8 `abi.decode`/`abi.encode` of structs, returned words of calls decoded from memory, dynamic argument contents (`bytesAt(p)`), loop idioms |
| Interfaces | Typed signatures from masks/validators, `nonpayable`, return types, dynamic-argument accessors, hash-checked names, opt-in openchain cache | Names of tuple/array elements, return types of dynamic values |
| Authorization/effects | Per-function summaries: caller checks, writes, calls, ETH sends, events, transitive private effects | Reentrancy/lock idioms, proxy summaries in the new view |
| Evidence | Every IR statement accounted (printed, absorbed, elided with reason, argument decode, structural) on 24 fixtures | — |
| Uncertainty | UNCERTAIN marks on unresolved PHIs, unverified ABI calls, raw events; scoped memory assumption recorded per line | Calibrated confidence per name/type |
| Behavioral confidence | The printed view is executed: 1,079 cross-checked executions agree with the IR machine (and Py-EVM); 0 unsupported; 28 pair `skim` cases run the split copies against Py-EVM with stub tokens; 135 Morpho cases with stub contracts at hard-coded addresses; printed ABI arguments are checked against the bytes each call sends | No proof of equivalence; bounded inputs |
| Held-out accuracy | 5 of 12 pre-selected mainnet contracts analyzed: 146/146 selectors and names correct; 5 wrong claims in run 1, fixed (0 after re-render) | 7 contracts not yet analyzed (run stopped by memory pressure); no same-bytecode Dedaub exports for them |
| Dedaub parity | One same-bytecode pair: 234 vs 192 code lines, all Dedaub facts present, one reason better decoded | A held-out set of same-bytecode Dedaub exports is still needed for a parity claim |

### Status update 2026-10-16 (later): solc ABI coders in the readable view

Code lines below are non-blank, non-comment lines of the whole file, the rule
that gives Dedaub's Morpho output 192 (the table above left out closing braces).

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Readable code | `abi.decode(x, (S0))` of calldata bytes into a struct (fields `v0.f5`), `abi.encode(S0(...))`, `keccak256(abi.encodePacked(...))`, ABI calls staged at the free pointer (`flashLoan(a, b, v31)`, `call(abi.encodeWithSelector(...))`, `call(b)`, `""`); 24 fixtures 4,890 -> 4,770 code lines, none longer; Morpho 241 -> 139 (Dedaub 192); Router02 1,658 -> 1,330 (all 44 `pairFor` hashes) | Returned words decoded from memory (struct returns), returndata `bool` decoding (`TransferHelper`), via-IR encoder layouts, dynamic arrays/nested structs in coders |
| Evidence | Each coder line keeps the replaced statements as its evidence (Morpho's `abi.decode` line: 195 IR statements); 25 fixtures fully accounted | — |
| Behavioral confidence | The interpreter executes the coders with solc's checks in order, allocations and memory writes; constant pointers folded by the analysis are checked. Morpho: 171 cases incl. one malformed callback per decoder check; Router02 (new calibration fixture): 65 cases, 101 calls, every `pairFor` target compared with Py-EVM. Cross-check unchanged: 1,079 agreeing, 0 unsupported. Found and fixed: private mask-typed parameters were not cast when executed | Bounded inputs; coders are matched only in the forms seen so far |
| Held-out accuracy | Re-render of the five analyzed contracts at 6032b68: 0 wrong claims | Seven contracts still unanalyzed |

### Status update 2026-10-16 (evening): held-out run 2 and the first Dedaub comparison

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Robustness | Inlined values over 128 nodes print as locals and canonical codec forms over 256 nodes become atoms (V3 pool render: >6 GB killed -> 3 s, 0.13 GB); one-operand IR stores stay UNCERTAIN raw operations; an IR operand with several values becomes an unordered PHI (never a choice); one failing function prints an UNCERTAIN stub; relations are kept when a step after Gigahorse fails. Held-out batch: per-contract cgroup memory cap, wall-clock limit, failure kinds and peak memory in the report | Gigahorse's own memory on 1inch (15.9 GB); Vyper dispatcher |
| Held-out accuracy | Run 2, first scores before any Dedaub export was opened (`results/run2.json`): 5 of 7 produced output, 112/113 selectors, 99 names correct, 12 wrong claims (V3 `uint160` as `address`, Seaport collision names); Curve and 1inch failed (fixed afterwards: `results/run2-after-fixes.json`). The five run-1 contracts: still 0 wrong claims | Static-struct arguments (1inch arity), `uint160` vs `address`, signature coverage |
| Dedaub parity | Same-bytecode comparison on all seven (`results/run2-dedaub-comparison.json`): 22,012 vs 12,671 code lines, raw share 38% vs 26%, names 120 vs 154 of 196, wrong claims 17 vs 19 (payability 0 vs 26), decoded revert reasons 103 vs 73 | **Not at parity**: memory allocations as objects, custom error/event/parameter names, Vyper, large assembly-heavy contracts |

### Status update 2026-10-16 (late): held-out run 3 and three wrong-claim causes

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Held-out accuracy | Run 3 (8 contracts frozen in 354be8c, first scores in fb0870a before tuning): 8/8 produced output, 141 names correct, 0 wrong, 23 wrong claims. After fixing collision names, flattened struct parameters and uint160-as-address (adcf6e5): run 1 0 -> 0, run 2 17 -> 1, run 3 23 -> 10, no new wrong claims | Structs decoded by helper functions (no arguments recovered), return widths of packed fields, via-IR validators for typing, Curve/Vyper dispatch (0/39 selectors) |
| Useful function interfaces | Static struct parameters from the decoder's own checks (`S<n> varg<i>`, fields `.f<j>`); argument counts capped at the decoder's head; dictionary names rejected when the decoder needs more bytes; `uint160` from signatures or numeric use | Nested struct types, dynamic tuples |

### Status update 2026-10-16 (night): memory objects and custom errors

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Readable code | Allocations as values (`new struct(k)`, `struct(a, b)`, `new bytes(n)`, `new uint256[](n)`, `v = varg0` / `v = returndata` copies, `"..."` constants, `.wordN` / `.length` / `[i]` fields); memory-built custom errors and Panic codes as one revert, dictionary-named (`revert InvalidMsgValue();`), both selector layouts. 7 run-2 contracts (calibration): 22,012 -> 19,139 code lines, raw share 38% -> 28% (Dedaub 26%), 306 -> 0 unnamed dictionary errors; fixtures 9,177 -> 8,708, none longer | 1inch's unstructured functions, Seaport's hand-written low-level code, the Vyper dispatcher, `revert(returndata)` bubbles, hashes over memory words |
| Behavioral confidence | Objects and payloads execute exactly the replaced statements; folded-pointer assumptions are checked when executed; synthetic bytecode against Py-EVM for every new form; 425 passed, 17 skipped; cross-check 1,079 agreeing | Bounded inputs |
| Held-out accuracy | Wrong claims unchanged (17 on run 2, 0 on run 1). New held-out set frozen before this work: `fixtures/evaluation-heldout-2/` (8 contracts, two via-IR, one Vyper), not yet analyzed | Run 3 on it, with Dedaub exports from the user |

### Status update 2026-10-16 (overnight): held-out set 3 frozen

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Held-out accuracy | Runs 1-3 are calibration. Held-out set 3 frozen before the next work: `fixtures/evaluation-heldout-3/` (8 contracts: Vyper 0.3.10 and 0.2.12, two via-IR, five with struct parameters, one unoptimized), not analyzed | Wrong claims to 0 on runs 1-3 (helper-decoded structs, return widths), Vyper dispatch, unstructured functions in Balancer and 1inch; then run 4 on set 3 |

### Status update 2026-10-16 (overnight, later): structs decoded by helpers, shared selectors

| Requirement | New evidence | Still open |
| --- | --- | --- |
| Held-out accuracy | Runs 1-3 (calibration) wrong claims 11 -> 3, none new, no correct count lower: Balancer's selectors shared with an internal `msg.sig` check now stay with the dispatched entry; calldata structs read through a decoder helper's pointer are one parameter (V3 position manager arity 38/38) | 3 return widths the bytecode cannot settle (masked `uint128` value returned as `uint256`): kept narrow by the user's choice, with a legend note that the source may declare wider |
| Useful function interfaces | Struct parameters from decoder pointers, from struct checks inside helpers, and (inlined decoders) from fields validated where read; unread fields kept to the checked size; fields typed where validated | A SafeCast-style check at entry hides a whole-head struct; struct fields used raw stay untyped |

Next priority: investigate the NFT receiver callback's unresolved PHI; add successful
NFT mint/transfer/receiver and multisig behavior checks; improve dynamic encoders,
interprocedural authority
and signature explanations, type propagation and SSA/loop presentation. Do not treat green fixture
tests, successful analysis coverage, or readable examples as completion of the
full objective. Dedaub comparison and a general behavioral equivalence claim remain
unproven. Bounded behavioral results and their scope are recorded in
`artifacts/codecopy-release-benchmark.json`, `artifacts/codecopy-projection-report.json`
and EVALUATION.md.

The first four deployed contracts are calibration cases after their initial inspection.
All 54 expected selectors are recovered; 48 have independent local name hints.
One function still uses an explicit CFG. Dynamic tuple arrays expose raw paths
and byte-copy ranges; proxy paths expose observed caller checks and forwarding.
Returned arrays now have candidate encodings with raw bytes retained. Dynamic encoder
bodies, original type ambiguities, interprocedural authority and complex state
effects remain difficult to read. Dedaub output is unavailable in the current environment;
the prepared importer requires matching runtime bytes and explicit export provenance.

The second selection recovered 92/92 expected selectors, with 120/121 fully
structured functions and one partial receiver-callback helper. WETH duplicates
an upstream runtime and is retained explicitly as regression coverage. All four
cases are now calibration after inspection. The NFT's 22 CODECOPY sites now
support decoding twelve additional Error(string) payloads, shortening the view by
72 lines. Its dynamic metadata/receiver helper remains verbose, with an unresolved
PHI and no successful mint/transfer/receiver execution coverage. Thirty-one early
guard/admin EVM calls pass. The multisig retains large signature/hash encoders,
lacks concise transitive authority summaries and has no independent execution
coverage yet. These gaps and the absent Dedaub comparison prevent a completion
claim despite passing local tests.
