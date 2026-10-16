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
