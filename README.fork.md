# Gigahorse reconstruction fork

This is a local development fork for building toward readable, Dedaub-style
contract analysis. The first milestone runs Gigahorse on runtime bytecode and
turns its recovered program into a structured JSON report and conservative
pseudocode, with the original relations retained for inspection.

The fork now also exports Gigahorse's storage and memory analyses through a
stable client, recovers mapping/array paths and packed fields, identifies ABI
argument validation patterns, and renders readable expressions and revert guards.
It also reconstructs structured branches and natural loops, preserving edge-specific
PHI values through native analysis and function inlining. A separate structured
view exposes unresolved cases and keeps the original CFG view available.
External calls show named gas/target/value/buffer operands, inferred ABI words,
local signature hints and recovered return-data consumers. Hints explicitly allow
selector collisions; CALL success remains distinct from a returned boolean.
Calldata tracking follows complete memory fragments through bounded constant-length
MCOPY chains, keeping copy/write evidence and explicit gaps after partial updates.
Dynamic calldata views expose observed relative array elements, tuple head words
and byte payloads while retaining modular offset arithmetic, zero padding and
all recovered checks. They do not claim original ABI types or field names.
Field summaries identify checked value constraints and direct call/condition uses.
Native memory facts and encoder witnesses provide candidate returned-array layouts;
dynamic candidates keep the raw RETURN byte range, and pointer hints are never
presented as scalar return values without complete word evidence.
Observed storage roles now identify words used for caller comparisons and delegate
targets. Forwarding summaries retain bytecode evidence and distinguish unresolved
input/output paths. Inferred role names do not establish admin privileges.
It is **not yet Dedaub-quality Solidity reconstruction**, compilable Solidity,
or a proof that all original behavior was recovered. The full objective and
remaining acceptance evidence are tracked in [ROADMAP.md](ROADMAP.md).
Eight deployed-contract evaluations, their concrete gaps and the pending
Dedaub comparison are documented in [EVALUATION.md](EVALUATION.md). The second
selection was frozen before analysis; three runtimes are absent from upstream
regressions, while WETH is a retained upstream duplicate. All 92 expected
selectors in that selection are recovered, with 120 of 121 functions fully
structured and one explicitly partial callback helper. These are coverage
measurements, not a readability or equivalence score.

The latest local release has 343 passing tests and seventeen skipped opt-in
native cases. Exact runtime bytes now support bounded CODECOPY/CODESIZE analysis
and zero-filled frame memory, recovering twelve additional NFT error strings.
The NFT view drops from 2,350 to 2,278 lines. Thirty-one independent EVM cases
check its early guards and admin changes; successful minting, token transfers and
receiver callbacks remain outside that coverage. Seventeen EVM microprogram
scenarios check copying, source bounds, padding and dynamic operands.

The prior storage correction retains integer alternatives for native one-byte
`bool` hints. Packed storage aliases require exact bit extraction and unchanged
storage/key values from the original load; maps retain that evidence.
Current outputs are in `artifacts/evaluation-codecopy-release/` and
`artifacts/evaluation-second-codecopy-release/`; native relations are reused.

## Readable decompiled view (`decompiled.sol.txt`)

Every bundle now also contains `decompiled.sol.txt` and `decompiled.map.json`,
produced by `reconstruction/highlevel/`. This is the view meant for reading an
unverified contract. The earlier views remain for detailed evidence.

The view lifts the recovered IR into expression/statement trees along the
structured control flow, then applies readability passes:

- simplification of masks/casts, the selector (`msg.sig`) and linear arithmetic;
- guards turned into `require(c, Error("..."))`, `Panic(n)` or
  `require(ok, returndata)`;
- recovery of short-circuit `&&`/`||`, loop conditions, the ETH
  `.transfer`/`.send` idiom and `nonpayable` entry checks;
- ABI calls printed as `target.method(args)` with named returned words, events
  as `emit Name(args)`, and returns as `return (words)`;
- mapping-key hashing and ABI encoders absorbed;
- argument and storage typing, getter-based storage names, and hash-checked
  event, function and error names;
- calldata accessors for dynamic arguments (`x.length`, `x.data`, `x.word(k)`)
  and named common subexpressions;
- summaries above each public function: caller checks, storage writes, calls
  and events, including effects of the private functions it calls;
- low-level calls decoded from memory when the native ABI model gave up
  (selector bytes, head words, `MCOPY` chains). Dynamic arguments print as
  `bytesAt(p)` / `stringAt(p)` / `arrayAt(p)` / `tupleAt(p)` / `dataAt(p)`:
  the value encoded in memory at `p`. Empty `bytes` print as `""`. Calls
  whose printed arguments do not cover their input carry an `input MEM[a:b]`
  note;
- solc's ABI coders, recognized step by step from the compiled sequence
  (`reconstruction/highlevel/abi_codec.py`): `v0 = abi.decode(x, (S0))` of
  calldata `bytes` into a struct (solc 0.8's Yul decoder; later calldata reads
  print as fields `v0.f5`), `abi.encode(S0(...))` of a struct literal,
  `keccak256(abi.encodePacked(...))` (e.g. Uniswap's `pairFor`), and the
  free-pointer staging of ABI calls (`flashLoan(a, b, v31)` with a `bytes
  memory` argument, `call(abi.encodeWithSelector(...))`, `call(b)`). Structs are
  declared once (`struct S0 { ... }`), members named by position. The
  interpreter executes these constructs with the compiler's checks, in order,
  and its allocations and memory writes. Free-pointer values that the analysis
  folded to constants are checked when executed;
- control flow the native analysis left shared. Old solc code reused by several
  call sites without becoming a private function is copied once per caller
  (UniswapV2Pair `skim`). A dispatcher jump into the fallback becomes
  `return fallback();` (Compound cETH).

Memory plumbing is removed by store-to-load forwarding and dead-store
elimination. These use a memory model with free-pointer value numbering,
pointer floors and ordering between pointer versions, plus interprocedural
read summaries. One scoped assumption is stated in the legend and recorded as
rule `assumes-solc-memory-discipline` on the lines it affects. An ABI
temporary written for a represented call/event/return is assumed not to be
re-read except through the same pointer value. Inputs of calls whose arguments
are not fully decoded are never absorbed.

Two idioms are summarized only after execution checks: storage string getters
(`return _name;`) and checked-arithmetic helpers (`_SafeAdd`/`_SafeSub`/...).
Each candidate is accepted only if executing its lifted body agrees with the
summary on every test state: ten string encodings, or 144 operand pairs. The
map records the rule and the number of states.

**Evidence and uncertainty.** Every IR statement is accounted for in
`decompiled.map.json`. It is either printed on a line (with IR ids and
bytecode offsets), absorbed into a line (`abstracted_ir_statements`), elided
with a reason (`elided`), an argument decode, or structural control flow.
Tests require `unaccounted_ir_statements` to be empty on all 25 fixtures.
Names marked `[dict]` are keccak-checked dictionary hints. `UNCERTAIN` marks
partially recovered constructs, which keep their raw operations.

**Validation by execution.** `reconstruction/highlevel/interpreter.py`
executes the printed statement trees themselves, without the hidden IR. The
test hook in `reconstruction_tests/conftest.py` re-runs every structured
IR-machine case of the behavioral suite through it, with the same replayed
external outcomes. It requires identical output, revert status, logs, storage
and call operands. Current result: 1,079 agreeing executions (241 external
calls, 103 logs, 222 reverts) and 0 unsupported. Separate tests run the view
directly against Py-EVM:

- WETH9: 45 cases;
- an NFT's `tokenURI`: 48 cases;
- UniswapV2Pair `skim`, with stub tokens: 28 cases;
- the Morpho liquidator, with stub contracts at its hard-coded addresses: 171
  cases, including a malformed callback for every `abi.decode` check;
- Uniswap V2 Router02 (calibration fixture from the held-out corpus), with stub
  pairs at the CREATE2 addresses the test computes: 65 cases (101 calls) of
  `getAmountsOut`/`getAmountsIn`, swaps and add/remove liquidity, so every
  `pairFor` result is compared with the EVM's.

For calls that send their printed memory, every printed argument must match
the bytes actually sent. This is bounded validation on the tested inputs, not
an equivalence proof. Building these checks found and fixed these bugs:

- dropped scalar storage writes;
- an unsound free-pointer elision;
- mis-resolved overloads;
- ERC20 `transfer` confused with ETH `.transfer`;
- unenforced `nonpayable`;
- absorbed inputs of partially decoded calls (found by review of the Dedaub
  comparison contract);
- dynamic call arguments printed as bare pointers (Morpho `liquidate`, pair
  `uniswapV2Call`);
- `Error(string)` writes hidden for one structured copy of a shared revert
  block after the other copy was elided;
- private parameters typed from masks (`address varg1`) not cast when the
  view was executed (found by the Router02 `addLiquidity` cases).

Output is deterministic: text and map do not depend on Python's hash seed
(a test renders two fixtures under two seeds).

**Names from openchain (opt-in).** `--online-signatures` looks up only the
selectors/topics the local dictionaries do not resolve. This discloses them to
openchain.xyz. Only keccak-checked names are kept; they are cached under
`cache/signatures/` and reused offline afterwards.

## Repository

- Upstream: https://github.com/nevillegrech/gigahorse-toolchain
- Starting revision: `1b06cef82f0a29790e87f576eba6d6d793170d70`
- Development branch: `solidity-reconstruction`
- Remote `upstream` points to `git@github.com:zS-harrison/gigahorse-toolchain.git`.
  Local reconstruction changes have not been pushed to the GitHub fork.
- The upstream BSD-3-Clause license and attribution remain in place.

## Run in the current workspace

From this directory:

```bash
source .env.local
.venv/bin/python reconstruct.py doctor
.venv/bin/python reconstruct.py decompile \
  fixtures/reconstruction/storage-via-ir.hex \
  --interpreted --output artifacts/my-first-run
```

Use a new output directory for each run. Existing directories are preserved.
The input must be a file containing **deployed/runtime EVM bytecode** as hex,
optionally prefixed with `0x`. Address/RPC input and creation-code extraction
are not implemented yet.

`--interpreted` avoids initial Datalog-to-C++ compilation. Omitting it uses
Gigahorse's compiled mode and a reusable cache; the first compilation can take
several minutes. `--timeout 120` controls the upstream analysis timers, not an
overall deadline for initial compilation. Signature network resolution is
disabled, so bytecode analysis works offline once dependencies are installed.

Each successful run creates:

| File | Contents |
| --- | --- |
| `analysis.json` | Functions, selectors, formal IR variables, blocks, instructions, CFG edges, constants, storage accesses, provenance and warnings |
| `pseudocode.sol.txt` | Pseudocode with storage reads/writes, arithmetic, branches and source instruction identifiers |
| `recovered.sol.txt` | Inferred declarations, storage accesses, checked input fields, raw return words, candidate dynamic layouts, expressions and revert guards |
| `recovered.map.json` | Per-line supporting IR statements and original bytecode offsets, including inlined expression evidence |
| `structured.sol.txt` | Structured branches, loops, internal calls/returns and simultaneous PHI edge assignments, with explicit fallback for unresolved flow |
| `structured.map.json` | Per-line evidence, region trees, recovered CFG transfers, PHI edge copies, and per-function uncertainty |
| `relations/` | Original Gigahorse output, including facts not interpreted by this first presentation layer |
| `upstream.log` | Analysis diagnostics |

Fresh native results for all sixteen fixtures are listed in
`artifacts/revert-release/native-fixtures-report.json`. Most bundles are under
`artifacts/revert-release/fixtures/`; the two failure fixtures are under
`artifacts/revert-release/native-fixed/`. All include the restored-JUMP inliner fix.
Current views of those relations are in `artifacts/storage-release/fixtures/`;
`artifacts/storage-release/fixture-views-report.json` records the reused inputs.
The formerly unresolved copied token call is visible in
`artifacts/memory-milestone/interaction-optimized/`.
Artifacts are ignored by Git.

`analysis.json` schema version 2 adds `semantics`. Its argument records are
separate from the raw functions' internal `formal_variables`. A type such as
`word` is unresolved, while a candidate list such as `["address", "uint160"]`
preserves an ambiguity. Names are generated from slots and selectors. Packed
writes retain the original word update alongside inferred field assignments.
`recovered.sol.txt` retains explicit labels and jumps. The structured view uses
parallel edge assignments for PHIs with one proven incoming value per predecessor.
Ambiguous/missing PHI values remain `phi_unordered`, with `structured-partial`
status. Irreducible cycles, multiple-destination jumps or unsupported regions
retain explicit CFG form. The extra SSA variables/copies are not yet coalesced,
so loop output is more verbose than typical hand-written Solidity.

The inferred views now use generated per-function names such as `memory_word1`,
`state_word1`, `merge1` and `input0`. These identify IR roles and are not recovered
source identifiers. `variable_names` in each source map connects them to raw SSA
variables, defining instructions and bytecode offsets. Raw IR names remain in
`pseudocode.sol.txt`, `analysis.json` and the original relations.

Private signatures omit a formal only when it is used exclusively as the first
operand of RETURNPRIVATE, never defined or used as data, and every known caller
has matching arity and an unambiguous continuation inside its function. Both
declarations and calls omit the same index, preserving the order of data inputs.
Ambiguous or data-bearing inputs remain visible. `internal_interfaces` in the
analysis and source maps records the omitted index, callers, continuation blocks
and bytecode evidence. This establishes a control-only input within recovered IR,
not original Solidity function boundaries or parameter types.

Optional offline names can be enabled with `uv sync --extra naming` and
`--signatures /path/to/selector-signature.tsv` on either `render` or `decompile`.
The format is one `0x12345678<TAB>method(type,...)` per line, as in the existing
`PublicFunctionSignature.facts` dictionary. Selected rows are checked using
Ethereum Keccak-256, and the exact dictionary hash is saved in `signature_info`.
A unique matching candidate produces a `hint_method_selector` name; collisions
retain the generic name and all candidates. These names never replace inferred
parameter types or prove return types/behavior. Without this flag, rendering
continues to use only the Python standard library.

## Render existing analysis results

This command uses only the Python standard library and does not require Souffle:

```bash
.venv/bin/python reconstruct.py render \
  artifacts/storage-via-ir/relations --output artifacts/rendered-again
```

Complete relation sets from this fork's upstream revision are required. Missing
files, contradictory structural facts and malformed operand indices produce
explicit errors rather than a misleading successful report.

## Dependencies and scratch space

The normal installation path is described in [README.md](README.md): Python
3.13+, uv, Souffle 2.3 or 2.4.1, Boost headers and Z3, then build the native
`souffle-addon` and run `uv sync --frozen`. The addon's `WORD_SIZE` must match
the value printed by `souffle --version`.

For this session, dependencies were downloaded/extracted without system-wide
installation. `.env.local` points to those temporary native libraries and the
Python installation under `/tmp/gigahorse-decompiler/`. That ignored file is
specific to this workspace. If temporary storage is cleared, reinstall using
the upstream instructions and recreate the virtual environment.

Analysis work and compiled caches prefer
`/mnt/model-ssd/scratch/gigahorse-decompiler/` when writable, falling back to the
system temporary directory otherwise. Intermediate directories are removed
after each run. Analysis results explicitly requested with `--output` remain
in the selected directory. In Codex's restricted shell the SSD can appear
read-only; live tests also need permission for Gigahorse's local multiprocessing
IPC socket.

## Validation

The checked-in `StorageFixture.sol` covers a simple getter, a guarded write,
mapping reads/writes, checked arithmetic and a conditional merge. Its runtime
bytecode is built with solc `0.8.30+commit.73712a01`, optimizer runs 200, Cancun,
and both standard and `viaIR` pipelines. JSON manifests record compiler settings,
source/bytecode SHA-256 hashes and the compiler's five expected selectors.
`LayoutFixture.sol` adds three fields packed into one slot, a dynamic array,
a nested mapping and an owner guard. Both compiler paths are included, for four
runtime fixtures total. Manifests also contain Solidity's ABI and storage layout
as ground truth; these are used for evaluation and never supplied to decompilation.
`ControlFlowFixture.sol` adds branch merges, loops with `break` and `continue`,
nested loops, swapping two loop-carried values, checked arithmetic and repeated
storage updates. Its two compiler paths bring the corpus to six runtime fixtures.
`InteractionFixture.sol` adds typed and raw token calls, static reads, ETH sends,
arbitrary calldata forwarding, delegate calls and failure/return-data handling,
bringing the corpus to eight. An auxiliary target is used only for EVM validation.
`CopyFixture.sol` adds chained copies, overwrites, truncation, both overlap directions,
variable copy lengths and stale read/modify/write sequences. Both compiler paths
bring the corpus to ten runtime fixtures. Its auxiliary target echoes calldata
only for independent EVM validation.

`ExpressionFixture.sol` adds words and mapping keys captured inside loops,
including a word computed only on the first iteration. Its two compiler paths
bring the corpus to twelve runtimes. Tests compare return bytes and every
observed SSTORE slot/value with the original EVM execution, including word wrap.

`AliasFixture.sol` adds aliased scalar and return-size words, direct memory returns
and overlapping MCOPY writes. Both compiler paths bring the corpus to fourteen
runtimes. Its 196 EVM cases cover overlapping/disjoint byte ranges, zero-length
copies, arbitrary words, changed return lengths and nonpayable calls.

`FailureFixture.sol` adds long/UTF-8 reasons, assert/arithmetic panics, fixed and
dynamic custom errors, overwritten message words and arbitrary caller-supplied
revert bytes. Its two pipelines bring the corpus to sixteen runtimes and add
70 independent EVM scenarios.

All sixteen fixtures were run through Souffle 2.4.1 with a 64-bit native addon.
There are still unmapped original statements, exposed in each report and in
the benchmark; they must be investigated before claiming completeness.

The relation snapshots under `fixtures/reconstruction/` come from those actual
runs. Offline tests check that every recovered opcode survives the presentation,
that all expected selectors survive, and that storage accesses remain visible.
Additional tests cover unordered PHI inputs, instruction ordering, ambiguous
constants, operand order, provenance, invalid input and output preservation.
The semantic regression suite compares packed byte ranges with the compiler,
checks argument-type ambiguities and source maps, and prevents state/memory
reads or calls from being reexecuted during expression inlining.

On these sixteen fixtures, all 94 expected selector instances and all 18 expected
top-level storage ranges are recovered. Storage type candidates contain the
source type for 14 of 18 fields; mapping address keys are currently reported as
256-bit keys. Only 12 of 172 argument instances have an unambiguous recovered type
matching the source. These limitations are visible in the benchmark; selector
and layout success alone are not evidence of general Dedaub parity.

The reconstruction suite has 343 passing tests and seventeen skipped opt-in native
cases, recorded in `artifacts/codecopy-release-tests.xml`. This includes the
unknown-instruction barrier regression and the new code-copy/memory/NFT checks.
The skipped cases are sixteen full native fixture analyses and one driver failure test.
The latter passes separately with the four cache tests in
`artifacts/constant-memory-native-cache-tests.xml`.
Ruff lint/format checks and mypy pass. All 66 upstream native regression tests
pass after changes to SSA output and the inliner. PHIs are materialized at
actual merge points, with final reaching values propagated through other blocks;
this preserves loop edge semantics and the upstream memory/call recognizers.
The upstream suite also passes after adding a guard against stale partial memory
stores: a load/modify/store is no longer treated as preserving other bytes when
an intervening memory write can have changed them.
The latest native compatibility report is `artifacts/revert-upstream-tests.xml`:
all 66 tests pass with four workers. Cache publication now replaces complete
binaries atomically, and a per-key lock shares cold compilation. An executing
binary's inode is preserved. A real cold Souffle run with four workers compiled
once and produced identical outputs (`artifacts/cache-cold-native.json`).
Compiler subprocess failures stop the driver before stale aliases can execute.
These checks cover a shared immutable configuration; pinning aliases across
simultaneous different configurations and source edits remains work.
Dedaub comparison remains unmeasured.
The independent deployed corpus also completes all four analyses and recovers
54/54 expected selectors. Signature hints cover 48/54 with the existing local
dictionary. One function retains an explicit CFG; selector coverage is not a
readability or equivalence score. Fresh native runs are in
`artifacts/evaluation-revert-release/`; current views with independent name hints
are in `artifacts/evaluation-codecopy-release/`. Current times measure rendering,
and the first report retains actual native timings.

Across those four cases, twelve private signatures and 57 call sites omit proven
return-PC inputs. The pair's ten helpers now expose only their data words, with
short input names. Thirty-two additional local EVM cases exercise its token
accounting paths: output/revert bytes, final touched slots and 15 logs agree with
both recovered execution modes. They include 49 private calls through three
helpers, finite/unlimited allowances, self/zero transfers, overflow rollback and
malformed calldata. Initial storage is controlled; pool, permit and production
state behavior remain outside these checks.

The latest pass recognizes 12 dynamic calldata roots and 12 byte copies across
the deployed cases. On Multicall3, 62 local EVM comparisons exercise all six aggregation
methods and malformed inputs. Both recovered CFG and structured execution agree
on outputs, reverts and call operands. The cases also check 287 modeled calldata
loads against their original EVM PCs, addresses and words, plus 845 raw-view values.
External outcomes, GAS, block number and BLOCKHASH are replayed from EVM observations; this
does not prove the emitted pseudocode text or the behavior of arbitrary contracts.
Raw calldata accessor definitions and evidence are recorded in the source maps.

Multicall3 has 15 observed nested fields, including six with address/uint160
constraint candidates; condition inputs are not automatically treated as bool.
All six aggregation returns have candidate encoding layouts. Forty-three successful
return cases decode consistently with those layouts and an independent ABI decoder.
The encoder bodies remain explicit, and bytes/string and bool/integer declarations
remain ambiguous. Current native runs analyze all sixteen fixture and deployed
runtimes directly from bytecode.

All eight USDC proxy functions now structure. Five non-executable continuation
edges after EVM RETURN are retained in the IR and recorded in flow-plan metadata.
Six delegation sites expose whole-calldata and recovered return/revert forwarding,
with caller comparisons and inferred storage-word roles. Thirty-one additional
stateful EVM cases compare proxy outputs, reverts, both storage words, five raw logs,
15 root calls and 21 summarized caller checks. They use controlled initial state
and local target programs, with external outcomes and GAS replayed from the EVM.
Implementation token logic, production state and general equivalence are untested.

With `--extra validation`, independent Py-EVM execution covers 190 contract calls
across the standard and `viaIR` control-flow fixtures. Return bytes, revert payloads,
and slot-zero state agree with both recovered CFG and structured-region execution;
the latter also traverses the same block trace. Cases include nested loops,
parallel swaps, overflow reverts, invalid calldata, nonpayable calls and persistent
storage updates. Another 25 opcode cases check the harness's word arithmetic
against EVM execution. This is bounded validation of IR/region execution, not
execution of the emitted pseudocode text, gas equivalence or a general proof.

Another 160 interaction/copy cases compare the caller's recovered execution with EVM
observations, covering 152 external calls and 96 inferred ABI word values. These
cases replay EVM-observed call outcomes and GAS values: they validate caller
arguments, control flow, return bytes, reverts and slot-zero state, without
independently reimplementing the external contracts or world-state transitions.
Four additional EVM microprograms check partial output-buffer copies and invalid
RETURNDATACOPY bounds. Failed calls, empty return data and a successful call
returning `false` are kept distinct.
A two-call EVM check also verifies that a saved return-data length is not
re-read after a later call changes the return buffer.

All six calls with fixed selectors in the original interaction fixture pair now
have decoded selectors and argument words, including the standard optimizer's
copied `rawTransfer` buffer. The copy fixture pair also checks that clipped words,
mixed overlap results, variable lengths and stale snapshots are not guessed.
Fragments are tracked only through unique constant copy lengths of at most 64 KiB.
Some fragmented fields after overwrites remain unknown. Dynamic forwarded calldata,
ETH transfers, dynamic ABI values, events and custom errors still need more work.

```bash
source .env.local
.venv/bin/ruff check
.venv/bin/ruff format --check
.venv/bin/mypy

# Exclude upstream's conftest, which otherwise compiles native analyses at startup.
.venv/bin/python -m pytest --confcutdir=reconstruction_tests reconstruction_tests \
  --basetemp=/mnt/model-ssd/scratch/gigahorse-decompiler/pytest

# Also rerun all sixteen bytecode-to-bundle cases and the native driver failure test.
GIGAHORSE_INTEGRATION=1 OMP_NUM_THREADS=2 \
  .venv/bin/python -m pytest --confcutdir=reconstruction_tests reconstruction_tests \
  --basetemp=/mnt/model-ssd/scratch/gigahorse-decompiler/pytest-live
```

Use the SSD for `--basetemp` when writable. `scripts/compile-reconstruction-fixtures.py`
regenerates bytecode/manifests when the pinned `solc` is on PATH. The full
upstream native regression suite remains available separately via
`uv run pytest test_gigahorse.py`.
These checks do not establish EVM behavioral equivalence or quality parity with
Dedaub.

The benchmark can be regenerated without native dependencies from the saved
relation snapshots:

```bash
.venv/bin/python scripts/benchmark-reconstruction.py \
  --output artifacts/semantic-benchmark.json
```

To reproduce the independent EVM checks and include their evidence in the report:

```bash
uv sync --frozen --extra validation
.venv/bin/python -m pytest --confcutdir=reconstruction_tests reconstruction_tests \
  -o junit_family=xunit1 --junitxml=artifacts/copy-tests.xml \
  --basetemp=/mnt/model-ssd/scratch/gigahorse-decompiler/pytest-validation
.venv/bin/python scripts/benchmark-reconstruction.py \
  --output artifacts/copy-benchmark.json --behavior-report artifacts/copy-tests.xml
```

The benchmark checks that behavioral evidence refers to the current fixture
bytecode and relation snapshots. All sixteen current fixtures recover their 94
expected selector instances and 18 top-level storage ranges. There are still
unmapped original statements and substantial type uncertainty; the benchmark
does not establish broad coverage or Dedaub-level usability.

After a live fixture run, capture fresh snapshots with:

```bash
.venv/bin/python scripts/capture-reconstruction-snapshot.py \
  artifacts/semantic-layout-via-ir --fixture layout-via-ir
```

The capture command checks that the bundle's actual bytecode matches the
compiler fixture. The stable semantic export is defined in
`clients/reconstruction.dl`; missing or incompatible exports fail explicitly.
Semantic schema 2 adds external selector, return and memory evidence tables;
schema 3 adds calldata fragments and their copy/write evidence. Schemas 1 and 2
remain readable; copy reconstruction is available only with the new tables.
The optional memory extension in `clients/reconstruction-memory.dl` has an
independent schema marker, version 1. It exports array/struct facts and physical
return-writer fragments. Older exports remain readable; return hints without
complete word evidence retain raw RETURN rather than treating a pointer as a value.
New bytecode analyses include the extension automatically. Existing native IR can
be refreshed without repeating bytecode lifting:

```bash
source .env.local
.venv/bin/python scripts/refresh-semantic-exports.py \
  artifacts/evaluation-initial/multicall3/bundle/relations \
  --output artifacts/my-refreshed-bundle
```

The refresh records bytecode and semantic-library hashes and rejects source changes
during native execution. Current native exports and named views for the deployed
cases are under `artifacts/evaluation-revert-release/`; named views are under
`artifacts/evaluation-folding-release/`, and comparison inputs are under
`artifacts/comparison-folding-release/`.
Rendering older core-only relations remains available, with a warning that
the semantic layer is unavailable.

## Expression lifetimes and printed checks

Expression expansion has bounded depth and length. When a bound requires a
temporary, its assignment is now retained, along with any temporaries needed by
that assignment. Source maps retain the defining IR/bytecode evidence.

A word stored in memory is a snapshot. A loop can execute an SSA definition or
update a PHI after that store, so the word cannot safely be printed as the
definition's current expression. Return-word substitutions now require the
stored value and its pure expression operands to survive until RETURN without
such an intervening update. The writer must also dominate RETURN, address its
word, and have no possibly overlapping write on a path to that return. Incomplete
range/count proofs produce `candidate_raw_words` comments while retaining the
raw RETURN. Unresolved value lifetimes withhold the word substitution entirely.

Native constant folding also stops at external calls between a store and load:
the output buffer may overwrite the word. A separate bounded numeric/byte-memory
pass now checks native hints that depend on reads, calls or function inputs. It
tracks stores, partial writes, copy snapshots, joins and resolved private calls;
unknown-address writes forget memory facts. It derives numeric values such as
free-memory pointers without accepting a native MLOAD constant on its own.
Unestablished native facts remain in `constant_hints`; separately established
replacement values are in `derived_constants`. Raw native exports remain intact.
`constant_verification` in the analysis and source maps records shared visited
IR/bytecode evidence, opaque functions and the step/context/depth/memory limits.
This is a proof within the recovered CFG with shared IR arithmetic semantics;
it does not verify native lifting or all EVM behavior. Symbolic pointer equality,
recursive/opaque calls and broader range/alias proofs remain work.

The optional validation harness parses the rendered expression strings with a
restricted AST interpreter. It checks operands, conditions, simultaneous PHI
assignments and raw return words along tested recovered traces. Its separate
frame contains only printed assignments and function inputs, so an elided
temporary cannot silently acquire its IR value. Constant and mapping storage
paths are checked against raw slots; array packing/stride remains explicitly
unchecked. Non-pure results and the execution trace still come from the IR
machine. This is bounded projection validation, not standalone execution of
the whole pseudocode or a general equivalence proof.

`artifacts/codecopy-projection-report.json` records 173,580 expression, 1,984
supported storage-path and 722 accessor-value checks across 993 reported EVM
input scenarios, including both CFG and structured runs, plus 210 private-call
checks. Twenty-four unsupported/withheld native path hints are counted as unchecked. Counts are printed
occurrences, not a proof-strength score: shorter expressions can require fewer
retained assignments, and hidden control inputs are no longer checked as printed
data. The earlier ordinary compiled CLI run completed on the
locked Multicall3 bytecode in `artifacts/constant-memory-release/compiled-smoke/`.

## Storage type hints and read snapshots

`semantics.storage_fields` and source-map `storage_fields` preserve native type
hints separately from candidates and limitations. A native `bool` hint can be a
one-byte heuristic; it does not establish a 0/1 range or an original declaration.
Ambiguous fields keep a raw `word` declaration and integer alternatives.

A packed storage accessor can replace an arithmetic alias only when its bits
match an original SLOAD/TLOAD exactly and no intervening storage/call effect or
accessor-key redefinition can change the value on recovered CFG paths. Otherwise
the alias uses the captured SSA value. `storage_read_proofs` records source-load,
bit-range and instruction evidence. Dynamic path addresses are still inferred;
bounded validation checks supported physical slots and accessor values against
execution. This is not a proof of arbitrary storage layouts or native lifting.

## Executed code and frame memory

`relations/bytecode.hex` binds CODESIZE and bounded CODECOPY facts to the exact
analysis input, independently of ABI/source and name hints. Copy evidence records
the input byte range, destination, zero padding and copied-byte hash. Source
indexing does not wrap; reads beyond code yield zeros. External-account code is
not supplied by this context. Missing code keeps these facts unresolved.

With a bound executed-code input, the numeric analysis starts the entry frame's
memory at zero. Unknown writes remove facts for their destination range; unknown
addresses/sizes and opaque calls discard the background. Joins retain only equal
facts, and private-call summaries include the complete memory context in their
cache key. Explicit facts remain bounded at 4,096 bytes; exceeding 128 disjoint
unknown ranges discards the zero background. Old exports without bytecode retain
unknown initial memory. Proof fingerprints bind decoded payloads and folded
helpers to the current code, IR, literals and copy observations.

The frozen NFT case has 22 CODECOPY sites and 35 context observations. Twelve
previously partial payloads now decode as Error(string), with source maps retained;
18 other payloads and the receiver helper's PHI remain unresolved. Thirty-one
synthetic-state EVM calls compare output/revert bytes, logs and touched storage.
They include 19 reverts, eleven observed CODECOPY operations, fourteen established
payload checks and ten decoded reasons. They cover early guards and admin changes,
not successful mint/transfer or receiver execution. Seventeen separate EVM
microprogram scenarios exercise code size/copy bounds, zero-length copies,
non-wrapping source offsets, padding and dynamic operands. Negative tests cover
missing/changed code, corrupted evidence, huge ranges and private memory contexts.

`artifacts/codecopy-release/presentation-report.json` records the NFT before/after.
`artifacts/codecopy-release/audit.json` checks all 24 current bundles, including
input hashes, unchanged raw IR, per-line IR/PC evidence, 328 storage-read proofs,
155 folded encoders and 34 established copy-byte observations. The suite and
bounded counters are retained alongside it; none establish native lifting,
standalone execution of the entire pseudocode or Dedaub parity.

## Failure payloads

Established REVERT bytes now expose canonical `Error(string)` reasons and
`Panic(uint256)` codes, with standard code meanings. Fixed unknown selectors can
show raw argument words; partial payloads show only established selectors and
byte ranges. Arbitrary caller data, clobbered words, malformed encodings and
opaque paths retain explicit uncertainty. These are decoded bytes, not a claim
about original error names, source-level causes or where the data originated.

`revert_memory` in the analysis records bounded known ranges; `revert_summaries`
records decoding and limitations. Source-map annotations reference the shared
`constant_verification` proof and the original REVERT. A guard gets a failure
payload only when every modeled path to its established reverts agrees; cycles,
private calls and conflicting/incomplete payloads withhold that annotation.
The detailed view retains the raw REVERT operations and failure bodies.

The structured view can replace established terminal encoders with
`evm.revert_error(text)`, `evm.revert_panic(code)` or `evm.revert_data(hex_bytes)`.
These helpers re-encode exact payload bytes; they are generated presentation
operations, not recovered source statements. Folding crosses unconditional
chains only when their internal blocks have one predecessor, no PHI copies and
no definitions used elsewhere. State reads/writes, logs, calls, unsupported flow,
partial payloads and oversized helpers stay expanded. Gas/resource behavior is
outside this payload-only abstraction.

`revert_folds` in `structured.map.json` records the original blocks, instructions,
bytecode offsets, hidden definitions and exact helper/payload. `revert_helpers`
defines the operations. Checksums bind folding to the current IR, literal inputs
and captured byte facts; changed or corrupt inputs withhold the abstraction and
decoded payload claim until analysis is refreshed. This checks consistency with
recovered IR and does not validate native lifting.

Across the four calibration cases, 37 encoders over 55 blocks represent 649 IR
instructions with helpers. The proxy view shrinks from 384 to 322 lines. The
factory has no eligible encoder and keeps its representation. Measurements are in
`artifacts/folding-release/presentation-report.json`; they are not Dedaub scores.
Validation parses the actual literal helper call, re-encodes its bytes separately
and compares them with tested IR memory and established payload bytes. Hidden
instructions do not supply printed-frame assignments. Reported tests include 24
executed helper checks, alongside the existing EVM payload comparisons.

Snapshots intersect equal byte facts across contexts, with initial memory as
specified above, at most 4,096 bytes per snapshot and 65,536 retained known bytes in total.
Opaque functions invalidate global value hints and revert snapshots in their
reachable callees. Independent dispatcher paths continue to be analyzed.
The failure fixture's decoded strings/codes are checked against Py-EVM and an
independent ABI decoder. The current reported tests include 270 revert-snapshot
and 8,704 byte comparisons, counted across both execution modes.

The assert fixture also exposed returned-value substitution adding data operands
to a call already restored as JUMP. The inliner now retains only its target.
`artifacts/revert-release/proof-fixes.json` records the bytecode-bound before/after
case and the opaque-caller regression. All sixteen fixtures, four deployed
calibration runtimes and 66 upstream tests were rerun after this native change.

## Next implementation steps

1. Extend the existing storage/memory integration to complex structs, dynamic
   arguments and uncertain accesses, and improve type propagation across calls.
2. Coalesce redundant SSA copies, infer loop roles and ABI decoding, and establish
   more useful internal helper summaries. Broaden support for irreducible flow
   while preserving explicit uncertainty.
3. Build a larger compiler/version/optimization corpus and compare output with
   Dedaub on representative contracts. Add behavioral execution checks as
   transformations become more ambitious.
4. Add optional naming and explanation assistance while retaining IR provenance
   and explicit unresolved constructs.

Pseudocode uses `u256` for arithmetic modulo `2**256` and `evm.*` for operations
whose EVM semantics must be preserved, including signed arithmetic and division
by zero. PHI inputs are explicitly unordered because these exported relations
do not associate each input with a predecessor in older core-only outputs.
New native output adds `TAC_PhiInput.csv` and preserves it through inlining;
structured output uses it only when every required incoming edge is unambiguous.
Raw functions'
formal variables are internal IR arguments; semantic arguments are separately
inferred from calldata and validation guards. Storage layout and type candidates
describe observed accesses and do not prove the exact original declarations.
