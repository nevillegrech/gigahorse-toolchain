# Deployed-contract evaluation

The original frozen selection is in `fixtures/evaluation/corpus.json`. It was saved in
the working tree before frontend evaluation or readability tuning on these cases.
All four runtime hashes were absent from the upstream regression bytecodes.
After examining these results, these contracts are calibration cases. A second
selection is recorded below; broader quality and Dedaub parity remain unproven.

| Contract | Compiler | Verified selectors recovered | Structured IR functions | Remaining CFG functions | Local name hints |
| --- | --- | --- | --- | --- | --- |
| Uniswap V2 USDC/WETH pair | 0.5.16 | 27/27 | 38/39 | 1 | 27/27 |
| Multicall3 | 0.8.12 | 16/16 | 18/18 | 0 | 10/16 |
| USDC proxy, excluding implementation token logic | 0.4.24 | 5/5 | 8/8 | 0 | 5/5 |
| Safe proxy factory | 0.7.6 | 6/6 | 9/9 | 0 | 6/6 |

These are coverage and presentation measurements. They do not establish correct
recovery of all behavior, good human comprehension, or Dedaub parity. There are
still unmapped original instructions: 170, 103, 53 and 223 respectively.

The runtime and evaluation metadata came from four specific
[Sourcify contract lookups](https://docs.sourcify.dev/docs/api/), with responses
cached once. The importer records response/runtime hashes, verification status,
compiler, deployment information and retrieval provenance. These are archived
onchain runtimes from Sourcify, not fresh or historical-block RPC attestations.
ABI, function signatures and compiler settings are scoring ground truth and are
never provided to native bytecode analysis. The optional naming pass instead
uses the independent local `PublicFunctionSignature.facts` dictionary, which
predates selection; its exact file hash is saved with each named output.

Initial native runs are in `artifacts/evaluation-initial/`. Fresh native runs after
the restored-JUMP inliner fix are in `artifacts/evaluation-revert-release/`.
Current named views are in `artifacts/evaluation-codecopy-release/`, with
independent signature hints and scoring ABI withheld. The first report records
native times; the named report measures rendering. Both bind results to source
and input hashes and state whether relations were reused. Sixteen fresh native
compiler fixture runs are listed in `artifacts/revert-release/native-fixtures-report.json`.
Current views reuse those relations under `artifacts/codecopy-release/fixtures/`.
This presentation pass changes no native analysis code; its timings measure
rendering. Native bytecode hashes and the supporting exports remain retained.
An earlier ordinary compiled CLI run on Multicall3 remains under
`artifacts/constant-memory-release/compiled-smoke/`.
Historical native runs and semantic refreshes remain in earlier folders.

The initial output nested successful functions inside terminal failure branches.
Choosing the smaller terminal arm as an early guard reduced maximum indentation
from 20 to 6 levels for the pair, 19 to 5 for Multicall3, and 9 to 5 for the
factory. Transfers and simultaneous PHI edge assignments remain the same.
Existing independent EVM/region comparisons also pass. Indentation is a concrete
presentation measure, not a substitute for a human readability assessment.

## Second selection and storage corrections

`fixtures/evaluation-next/corpus.json` locks four additional cases and twelve
inspection tasks before bytecode import and frontend evaluation. The baseline
implementation hash was
`e2b36ddfa0b6d2ce4f0ffc750ac3c66298234305e5a87ff74f2fe9ecef1ddd89`;
`artifacts/evaluation-second-baseline/report.json` confirms it stayed unchanged
through the fresh native runs. ABI/source were scoring ground truth only. The
same independent local signature dictionary was used for optional name hints.

| Contract | Compiler | Runtime bytes | Selectors recovered | Fully structured / IR functions | Partial / CFG fallback |
| --- | --- | --- | --- | --- | --- |
| WETH9 | 0.4.19 | 3,124 | 11/11 | 14/14 | 0 / 0 |
| ENS registry with legacy fallback | 0.5.16 | 5,346 | 13/13 | 18/18 | 0 / 0 |
| ERC721 collection at `0xbc4c…f13d` | 0.7.0 | 16,790 | 37/37 | 49/50 | 1 / 0 |
| Safe 1.3.0 singleton | 0.7.6 | 22,958 | 31/31 | 39/39 | 0 / 0 |

None duplicate the first corpus. WETH duplicates `tests/core-decompiler/WETH.hex`
and is **not new native coverage**; the other three hashes are absent from the
upstream regression bytecodes. No selected case was replaced or dropped. The
native runs took 49–54 seconds each. Coverage is not behavioral or readability
accuracy: these cases still have 16, 25, 100 and 116 unmapped original statements.
The NFT receiver-callback helper has one explicitly unresolved PHI.

All twelve tasks now have an agent inspection record in
`artifacts/storage-release/inspection.json`, with frozen-output IR/bytecode
anchors and separately archived verified source used for scoring. This is not
blind or independent human review. Deposit/withdrawal and registry authorization
can be followed in the output; event declarations, concise state roles, dynamic
metadata and wallet signature/authority explanations remain incomplete. In the
NFT, 22 CODECOPY sites exposed twelve partial error payloads at baseline. The
code-copy pass below now decodes them. Same-bytecode Dedaub exports remain absent from the
comparison packets; no parity score is claimed.

This evaluation found an actual type overclaim: WETH's byte-sized `decimals`
getter was labeled `bool` by upstream's default one-byte storage heuristic.
Native boolean hints now retain integer alternatives, a raw `word` declaration
and an explicit limitation; original hints remain in `native_type_hints`.
Reading a byte does not prove that storage contains only zero or one.

Packed-read aliases also require exact AND/shift/power-of-two-division extraction
from a real SLOAD/TLOAD and a recovered-CFG lifetime check. Any intervening
storage write, private/world call, possible mutation on another branch, or changed
accessor key withholds the live accessor and retains the captured SSA value.
Source maps record `storage_read_proofs`, the source load and extraction evidence.
This checks bit extraction and lifetime in recovered IR; dynamic path addresses
remain native inferences. The bounded validator separately compares supported
path slots and accessor values. Wrong masks/slots, state and call barriers, a
mutating branch and an injected incorrect accessor have negative coverage. An
independent EVM microprogram checks that an old byte remains old after a write.

The new behavior cases compare 45 WETH accounting/allowance/withdrawal scenarios,
six WETH byte values (including 18 and 255 with unrelated high bytes), and 45
registry scenarios. They compare CFG/structured results, logs and touched slots;
seven external outcomes and GAS observations are replayed from Py-EVM. Registry
cases cover owner/operator changes, packed resolver/TTL updates, a self-address
sentinel and three legacy calls. Both runtimes use synthetic local state, not
production storage. NFT early guards/admin paths now have bounded checks below;
multisig execution remains untested independently.

Current views of these four cases are in
`artifacts/evaluation-second-codecopy-release/`; current first-corpus views are in
`artifacts/evaluation-codecopy-release/`. These reuse the frozen native relations,
so their times measure rendering. `artifacts/codecopy-release-tests.xml` records
343 passing tests and seventeen skipped opt-in native cases. Ruff and mypy pass.
The final source/input/evidence audit is `artifacts/codecopy-release/audit.json`;
it checks all 24 bundles, unchanged raw IR, all mapped line evidence, 328 storage-read
proofs, 155 folded encoders and 34 established code-copy observations.
The bounded counter report is `artifacts/codecopy-projection-report.json`: 993
reported EVM input scenarios, 173,580 expression checks, 1,984 supported path checks,
722 accessor checks and 210 private-call checks, counted across both recovered modes.
Twenty-four unsupported/withheld path occurrences remain explicitly unchecked.
The current compiler-fixture benchmark is `artifacts/codecopy-release-benchmark.json`;
its 94 selectors, 18 storage ranges, 14 source-type candidates and 12 exact
unambiguous argument types out of 172 are unchanged. These remain bounded checks,
not a native lifting proof, full emitted-text execution, or Dedaub parity.

## Code copies and NFT failure guards

The executed input now binds CODESIZE/CODECOPY facts independently of ABI/source.
Each observed copy retains its source range, destination, zero padding and byte
hash. The analysis uses zero-filled entry-frame memory only with this bound input;
unknown writes/calls remove affected facts. Joins and private-call summaries retain
the full memory context. Copies are bounded at 4,096 bytes, with at most 128 unknown
zero-background ranges and 4,096 copy observations. Missing/changed code and
corrupted proof inputs withhold decoding/folding. These are facts in recovered IR,
not a proof that native lifting was correct.

The NFT view now decodes 27 Error(string) sites instead of 15. All twelve formerly
partial payloads are complete; 18 other revert payloads and the callback PHI stay
unresolved. Folding their encoding machinery shortens the structured output from
2,350 to 2,278 lines. The bytecode, raw functions/blocks and PHI exports are unchanged.
`artifacts/codecopy-release/presentation-report.json` records individual reasons
and original REVERT PCs, with full encoding evidence in the source maps.

The offline NFT snapshot is bound to the frozen native baseline and runtime hash.
Thirty-one synthetic-state calls agree with Py-EVM on outputs/reverts, logs and
touched slots in both recovered modes. They exercise empty/nonexistent-token guards,
sale/count/payment failures, approvals and owner changes. Nineteen calls revert;
eleven executed CODECOPY operations match their input-range/hash evidence, fourteen
established payloads match EVM bytes, and ten reasons match an independent ABI decoder.
Successful minting, token transfers, receiver callbacks and production state remain
outside these cases. Seventeen additional EVM microprogram scenarios check code size,
copy bounds, source offsets without wrapping, zero-length copies, padding and dynamic
operands. Unit regressions cover sparse-memory joins/clobbers, cache contexts, missing
or malformed bytecode, oversized copies and stale/corrupt proof evidence.

Current comparison packets are `artifacts/comparison-codecopy-release/` and
`artifacts/comparison-second-codecopy-release/`. Dedaub output is still absent;
no measured parity score or completion claim follows from these changes.

## First inspection and remaining gaps

- The pair's `swap` output exposes the slot-12 lock read, clearing write and
  reset paths. The callback selector can now be labeled with the candidate
  `uniswapV2Call(address,uint256,uint256,bytes)`. Bounds, reserve updates and
  transfers remain verbose; argument types are mostly unresolved.
- Multicall3 preserves the loop, target call and success checks. Nested calldata
  now uses raw views for array lengths, relative element offsets, tuple head words
  and copied byte payloads. Checked field constraints and direct use roles are
  now visible, and all six aggregation returns have candidate encoding layouts.
  Original tuple declarations and field names remain unresolved; encoder bodies
  remain explicit.
  The local dictionary lacks six methods, including `aggregate3`; no names or
  tuple types are invented for them.
- All eight USDC proxy functions now structure. Its storage words have inferred
  caller-check and delegate-target aliases, with summaries of whole-calldata and
  return-data forwarding on recovered paths. Original declarations, implementation
  token logic and broader authority analysis remain unresolved.
- The factory retains CREATE/CREATE2 and initializer-call operands. It does not
  yet turn those operations into a concise deployment/salt explanation.

For example, the pair's lock-clearing write is backed by IR/bytecode offsets
`0x6f5` and `0x6f9`. The Multicall3 target call is backed by call instruction
`0x7acS0x242` and its input expressions.
Full supporting offsets are recorded in each `structured.map.json`.

## Dynamic calldata views

The reconstruction pass verifies dynamic argument bases directly against their
head loads and follows modular ADD/MUL/SHL address expressions. It recognizes an
array element only when its relative head word is added to the array data base,
and a dynamic field only when its head word is added to its containing base.
Copies of `load(base)` bytes from `base+32` provide byte-sequence evidence.
The frozen ABI and signature dictionary do not feed this pass.

Across the four cases it recognizes 12 roots, 124 variable bindings and 12 byte
copies. Multicall3 contributes six roots, 96 bindings and six copies. Its copy
lines shrink from 571–631 characters to 179–215; these are presentation measures,
not a usability or equivalence score. For example:

```text
evm.calldatacopy(destination,
    cd_arg0.element(i).dynamic_field(0x2).data_offset,
    cd_arg0.element(i).dynamic_field(0x2).length);
```

These accessors retain raw EVM semantics: every address operation wraps at 256
bits, loads are zero padded, and indexing introduces no checks. All recovered
bounds/revert guards remain. `word(k)` is a tuple head word, not a claimed field
type. `dynamic_field(k)` does not distinguish bytes, strings, arrays or tuples.
Root, per-variable and byte-copy evidence are saved in the analysis and source
maps; accessor definitions are in the source maps. Unsupported or conflicting shapes
retain the lower-level expressions. No original field names are invented.

`artifacts/folding-release-tests.xml` records 293 passing tests and seventeen skipped
opt-in native cases. On the locked deployed Multicall3 runtime, 62 cases compare recovered
CFG and structured execution with Py-EVM: outputs, reverts and external-call
operands agree. The same cases check 287 modeled loads against observed EVM PCs,
addresses and words, plus 845 view/SSA values. There are 48 observed external
calls. Those outcomes, GAS values, block number and BLOCKHASH are supplied by the EVM;
this checks caller behavior and views, not a second world-state implementation.
The cases cover all six aggregation methods, empty/multiple entries, byte lengths,
failure policies, ETH-value mismatches and malformed offsets/lengths/words.
Emitted pseudocode text and general equivalence remain unproven.

## Input fields and returned encodings

Multicall3 has 15 observed nested field records. Six have checked address/uint160
candidates and direct CALL-target uses. The value-bearing variant also identifies
the word used for transferred ETH value. Other words remain condition inputs,
not invented bool parameters: bytecode can accept a nonzero word that a strict
bool ABI decoder would reject. Byte sequences retain the bytes/string ambiguity.
Each field records its loads, individual checks, roles and supporting instructions;
the constraints do not guarantee a type on every path or for every element.

The optional native memory extension has its own schema marker, version 1. It
exports array aliases/allocations, struct and array accesses, returned-array
members and physical return-writer fragments. Older base semantic schemas remain
readable. An upstream "return value" can be a memory pointer; it is now displayed
as a scalar only when complete full-word writer fragments, the exact returned
size, value lifetimes, dominance and intervening write-range checks establish the
raw words within the recovered CFG. Incomplete address/count proofs can retain
`candidate_raw_words` comments, with the raw RETURN authoritative.
The execution harness also checks established word
annotations against the actual returned memory. Otherwise raw RETURN is retained.

Nested array layouts use additional encoder witnesses: array count and stride PHIs,
relative head offsets, stores required on the loop's back edges, normalized 0/1
words, length-prefixed byte-copy loops, aligned cursor updates and padding writes.
Missing PHIs, changed strides, unknown stores, conflicting widths or incomplete
heads withhold a layout. No ABI or signature-derived types feed this analysis.
For example, `selector_82ad56cb` reports the candidate:

```text
((word{0,1}, byte_sequence)[])
```

This describes a returned array of two-field tuples with a normalized 0/1 word
and a byte sequence. It does not establish bool versus integer declarations or
bytes versus string. All six aggregation methods have inferred encoding candidates.
Forty-three successful return cases decode consistently with the candidates and
an independent ABI decoder using the frozen ABI only for scoring. The bounded
layout decoder checks relative offsets, bounds, padding and canonical 0/1 words;
malformed and cyclic/oversized layouts are rejected.

Across the deployed corpus, there are eight dynamic return candidates, 31 established
raw-word layouts, four unverified raw-word candidates and eight unresolved layouts.
The stricter range/count checks initially left thirteen word layouts as candidates.
Continuing independent dispatcher paths past an opaque tail now establishes nine
additional layouts without weakening those checks. Six unresolved layouts belong
to proxy paths that forward arbitrary implementation bytes; those still have
forwarding evidence and are not assigned an invented ABI. Two factory return
layouts remain unresolved. These counts measure recognized representations, not
original-type accuracy, general equivalence or Dedaub parity. Broader encoders,
including further MCOPY patterns and nested/static aggregates, remain work.

The refreshed compiler-fixture benchmark is `artifacts/folding-release-benchmark.json`.
Its 724 fixture behavior cases (564 standalone and 160 external replay cases)
are separate from the deployed-contract cases above.

## Printed expression checks and loop snapshots

The expression validator evaluates the actual formatted expression strings in a
separate frame containing only emitted assignments and function inputs. Tested
operands, branch conditions, simultaneous PHI copies and raw return-word
annotations must agree with the recovered execution. Supported constant/mapping
storage paths must also address the same physical slots. Array packing/stride
is counted as unchecked. Non-pure results and the trace come from the IR machine;
this does not execute the full pseudocode independently.

`artifacts/folding-projection-report.json` records 160,674 printed-expression
checks and 1,340 supported storage-path checks across 849 EVM input scenarios,
plus 138 private-call checks.
Occurrence counts include both recovered CFG and structured runs. No array
storage paths were exercised by these projection cases; the unchecked count of
zero does not establish support for them.

Two new compiler pipelines exercise first-iteration word snapshots, a value
computed only in a conditional loop body, and mapping keys captured before later
loop updates. Across 108 cases, the harness compares output/revert bytes and all
observed storage writes with Py-EVM, including wrapping word arithmetic. The
renderer retains a temporary when expansion limits reference it. A stored value
whose definition or expanded operands can change before RETURN stays a raw
memory return with an explicit lifetime limitation.

The printed checks also found an upstream memory constant surviving an external
call that overwrote its word. Native constant propagation now stops at that call
barrier. Additional scalar/size/direct-return alias examples showed why native
constant and return-writer facts need further verification. Two compiler paths
add 196 EVM cases for overlapping MSTORE/MCOPY ranges and changed return sizes.

A bounded numeric and byte-memory pass now checks read/call/input-dependent
native constant hints. Joins keep equal facts only, unknown-address writes forget
memory facts, MCOPY uses a snapshot, and resolved private calls use separate
argument/memory contexts. It also derives numeric constants absent from native
exports, preserving legitimate free-memory-pointer and return-word recovery.
The analysis retains `constant_hints` separately from `derived_constants`.
`constant_verification` in analysis/source maps records shared visited IR and
bytecode evidence, opaque functions, and the 200,000-step, 512-context, depth-32
and 4,096-known-byte limits. Missing values are unknown, including initial memory.
Unresolved functions/effects are conservative. Symbolic pointer equality and
broader range proofs remain incomplete. This pass shares the IR evaluator's
arithmetic and verifies values only within recovered CFGs; it does not establish
correct native lifting, full EVM equivalence, or soundness of every annotation.

The executable-cache publication race also has a retained reproduction and fix
(`artifacts/cache-race-reproduction.json`, `artifacts/cache-race-fixed.json`).
Publication now replaces complete binaries without modifying an executing inode,
and a per-key lock prevents concurrent cold builds. Four real Souffle workers
compiled once with identical outputs (`artifacts/cache-cold-native.json`). All
66 upstream tests pass with four workers (`artifacts/revert-upstream-tests.xml`);
five cache/driver tests pass in `artifacts/constant-memory-native-cache-tests.xml`.
Failed compiler children stop the driver before stale aliases can run. The
evidence covers a shared immutable configuration. Simultaneous different
configurations using fixed aliases and source changes during compilation still
need stronger pinning.

## Decoded failure payloads

The bounded byte-memory analysis now records complete or partial REVERT ranges.
The frontend decodes canonical `Error(string)` and `Panic(uint256)` payloads using
the [Solidity error formats and standard panic codes](https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions).
Unknown selectors can expose raw words without an invented name or types.
Matching a payload format does not establish its source, authority or cause;
error bytes can be fabricated or forwarded. Noncanonical encodings, invalid UTF-8,
unknown words and missing ranges remain explicit in the JSON and view.

| Calibration runtime | Error(string) sites | Panic sites | Partial payloads | Unresolved payloads |
| --- | --- | --- | --- | --- |
| Uniswap pair | 10 | 0 | 4 | 28 |
| Multicall3 | 1 | 18 | 1 | 5 |
| USDC proxy | 8 | 0 | 0 | 6 |
| Safe proxy factory | 0 | 0 | 0 | 4 |

There are 197 complete static payloads in total, including 160 empty reverts.
Thirty-seven guards receive a failure-payload annotation because every modeled
failure path reaches established, equal bytes. Conflicting payloads, cycles,
private calls or incomplete bytes withhold a single reason. The detailed view
retains raw REVERT operations and failure bodies. A decoded Panic code gives its standard
meaning without asserting that the original compiler generated it.

`revert_memory` retains known byte ranges, and `revert_summaries` records decoding
and limitations. Source-map annotations anchor the REVERT and reference shared
`constant_verification` IR/bytecode evidence. Snapshots intersect equal byte facts
across contexts, keep initial memory unknown, and cap snapshots at 4,096 bytes
and retained known bytes at 65,536. Symbolic pointer equality, code-copy contents,
arbitrary dynamic messages and unknown private-call effects remain incomplete.

Two pinned compiler pipelines add 70 EVM cases for short/long/UTF-8 reasons,
assert/overflow/division panics, fixed and dynamic custom errors, overwritten
message words, caller-supplied bytes and malformed inputs. The actual EVM strings
and codes also agree with an independent ABI decoder in eight Error and six
Panic scenarios. Forged caller payloads do not become static reason claims.
Reported counters include 188 revert-snapshot and 6,120 byte comparisons across
both execution modes. Tests without a recorded counter do not contribute to it.

This work exposed two correctness defects. Opaque callers now invalidate global
constant hints and revert snapshots in reachable callees; a specific known call
can still have a known result. Opaque dispatch tails no longer stop independent
dispatcher branches from being visited. A native inliner substitution also added
a returned data value to a call already restored as JUMP. Its operand export now
keeps only the target. The retained before/after case is
`artifacts/revert-release/proof-fixes.json`; the same source bytecode at PC 0x147
contains a one-operand EVM JUMP. All sixteen compiler fixtures, four deployed
runtimes and 66 upstream regressions were rerun after this fix.

## Compact terminal encoders

The structured view now uses literal payload helpers for established encoders.
`evm.revert_error(text)` emits canonical Error(string) with UTF-8 text,
`evm.revert_panic(code)` emits Panic(uint256), and `evm.revert_data(hex_bytes)`
emits exactly those bytes. These are presentation operations, not source recovery
or proof of an error's origin. The detailed view and raw IR keep every operation.

An encoder can span an unconditional chain whose internal blocks have a single
predecessor. Its operations must be pure/memory operations, with no internal PHI
copies or definitions exposed by other blocks or semantic expressions. Storage
reads/writes, transient state, logs, calls and unsupported control flow prevent
folding that region. Partial/unknown payloads and helpers exceeding the display
bound remain expanded. The abstraction preserves established payloads within the
recovered model; gas and resource behavior are outside its contract.

`revert_folds` in the structured map lists each original block, instruction,
bytecode offset and hidden definition with the exact helper and payload bytes.
Shared proof checksums bind the IR, literal inputs and captured byte facts;
stale/corrupt inputs withhold folding and payload decoding. They check consistency
with recovered IR and do not authenticate or prove native lifting.

| Calibration runtime | Encoders folded | Original blocks | Structured lines before/after |
| --- | --- | --- | --- |
| Uniswap pair | 10 | 10 | 2186 / 2118 |
| Multicall3 | 19 | 37 | 1366 / 1309 |
| USDC proxy | 8 | 8 | 384 / 322 |
| Safe proxy factory | 0 | 0 | 552 / 552 |

The 37 helpers represent 649 original IR instructions. These are presentation
measurements on calibration cases, not human-usability or Dedaub scores; see
`artifacts/folding-release/presentation-report.json`. The raw functions, blocks,
constants, return layouts and revert payload facts match the previous outputs.

The validation harness parses the emitted helper call and independently re-encodes
its literals, comparing bytes with tested IR memory and the established payload.
Hidden encoders execute only in the IR frame, providing no printed assignments.
Reported tests include 24 executed helper checks. Existing compiler cases compare
Error/Panic/custom payloads with Py-EVM and an independent ABI decoder; an extra
EVM microprogram verifies that an attempted SSTORE before REVERT remains visible
and rolls back. Negative tests cover effectful blocks, escaping values, changed
proof inputs, malformed/dynamic helper syntax and an intentionally wrong helper.
This remains bounded projection validation, not standalone pseudocode execution.

## Private interfaces and local names

The current presentation assigns generated names by function and IR role:
`input0`, `state_word1`, `memory_word1`, `merge1` and similar names. These are not
original identifiers. `variable_names` in each source map records raw SSA names,
definitions and bytecode offsets. Raw pseudocode and native relations retain
their original identifiers.

Twelve private interfaces across the pair, proxy and factory omit a return-PC
input at 57 known call sites. A formal qualifies only if every use is the first
operand of RETURNPRIVATE, no instruction defines it, and all known callers have
matching arity and a unique continuation within their owning function. Missing
edges, conflicting targets, redefinitions or data uses withhold the change.
Declarations and calls remove the same positional argument; the raw IR arity
and instructions stay intact. `internal_interfaces` records indices, call and
return statements, continuation blocks and bytecode offsets. These are recovered
IR interfaces, not a claim about original Solidity function boundaries or types.

For example, the pair's token-transfer helper now contains:

```text
result1 = fn_0x226e(input0, state_word1);
```

Its previous call included a third word, `0x2641`, used solely to resume the
caller. The callee now declares two data inputs. Negative tests also cover a
control argument in the middle of a signature and return-address words used as
data, which must remain visible.

Thirty-two stateful local EVM cases exercise the archived pair's token accounting
paths. Outputs, revert payloads, touched storage words and 15 logs agree in both
recovered execution modes. These cases make 49 private calls through three
helpers, covering transfer, approve, transferFrom, balance/allowance/supply reads,
finite and unlimited allowances, self/zero transfers, overflow rollback,
truncated/noncanonical calldata and nonpayable calls. Storage is initialized
locally; no external outcomes are replayed for these paths. Pool mint/burn/swap,
permit signatures, production state and the remaining pair helpers are outside
this comparison. The existing proxy cases also exercise its cleaned private
interface. The combined 138 printed private-call checks count both execution modes.

`artifacts/presentation-release/presentation-report.json` records character counts
before and after the earlier naming pass. Multicall3 shrank from 93,880 to 81,306 characters;
the factory grows slightly as role names and interface explanations are added.
These are presentation measurements, not human usability or Dedaub scores.
The printed-expression occurrence count also decreases because shorter names
can avoid expansion-limit spills and omitted control arguments are no longer
checked as printed data. It is not a measure of proof strength.

## Proxy paths and storage roles

Five proxy functions previously failed structuring because native inlining left
continuation edges after an EVM RETURN. EVM halts cannot take these edges. The
flow plan now records them as `ignored_terminal_targets` and emits the mismatch
in the view; original IR edges remain untouched. Internal-return pseudo-operations
with unexplained successors still retain an uncertain CFG. All eight proxy IR
functions now structure, and the latest view has 322 lines, down from 662. Across the
four cases, one function still retains an explicit CFG.

Storage roles come from opcode dataflow, without proxy-name, ABI or standard-slot
lookups. A word loaded into a DELEGATECALL target can receive the inferred alias
`role_delegate_target_word`; a word compared with CALLER can receive
`role_caller_check_word`. Overlapping declarations keep their original generated
names. These labels do not establish original variable names, types or admin
privileges. Caller-path summaries refer to values loaded at their evidence
statements, not a postcondition on storage that other code might mutate.

The six proxy delegation sites have direct whole-calldata copy evidence. Each
also has a recovered path that copies the full return data and returns on success
or reverts on failure. The analysis checks both outcomes and withholds that claim
on unmodeled paths, memory clobbers, stale size snapshots or inverted outcomes.
Whole-calldata inputs that cannot be established use `null`, with an explicit
limitation. Bounds and resource limits on the proof search remain conservative.

`artifacts/folding-release-tests.xml` records 293 passing tests and seventeen skipped
opt-in native cases. The original proxy runtime was deployed locally with
controlled initial slot values and local target microprograms. Thirty-one stateful
cases compare raw CFG and structured execution with Py-EVM, covering matching and
nonmatching callers, all administrative selectors, upgrades, admin replacement,
failed initialization, nonpayable calls, truncated calldata and forwarding.
Return/revert bytes, the two persistent words and five emitted raw logs agree.
The cases compare 15 root external calls and exercise 21 summarized caller checks.
External outcomes and GAS are replayed from the EVM; arbitrary implementation
code, production USDC state, reentrancy and world-state equivalence remain outside
this check. No general equivalence or Dedaub parity claim follows from these cases.

## Reproduce

```bash
source .env.local
uv sync --frozen --extra naming
.venv/bin/python scripts/evaluate-corpus.py \
  --output artifacts/my-deployed-evaluation --jobs 2

# Rerender the same IR with independent signature hints, without ABI ground truth.
.venv/bin/python scripts/evaluate-corpus.py \
  --reuse-relations artifacts/my-deployed-evaluation \
  --signatures PublicFunctionSignature.facts \
  --output artifacts/my-named-evaluation
```

The native runner records each failure/timeout and binds its report to input and
implementation hashes. Use a new output directory for each evaluation. The local
signature dictionary is optional and is not shipped as evaluation ground truth.

## Dedaub comparison

No Dedaub output has been obtained or scored. The public contract-page request
returned HTTP 403 here. The
[documented API](https://docs.dedaub.com/docs/api/nested/) exposes artifacts keyed
by the binary bytecode's MD5 and requires authorization. No jobs were submitted,
account created or paid access purchased.

`artifacts/comparison-folding-release/` contains per-contract bytecode hashes, artifact
request identifiers, local output links and the inspection tasks chosen before
evaluation. A comparison must use the same runtime bytes and identify whether
the reference is primary decompiled output, decompiled Yul or AI reconstruction.

`scripts/prepare-comparison.py` accepts normalized, user-provided exports in a
directory, one `<contract-id>.json` per case:

```json
{
  "vendor": "Dedaub",
  "representation": "decompiled",
  "source_url": "https://app.dedaub.com/...",
  "captured_at": "2026-10-15T00:00:00Z",
  "bytecode": "0x...the runtime returned with the vendor artifact...",
  "code": "...the saved decompiled text..."
}
```

This is the local import format, not a claim about the vendor's raw JSON schema.
The importer rejects different runtime bytes and missing code/provenance. It
records the text hash and representation, and keeps unavailable or rejected
references in the review packet. Provenance is supplied by the export provider;
the importer does not authenticate a vendor signature or generate a parity score.

```bash
.venv/bin/python scripts/prepare-comparison.py \
  --evaluation artifacts/evaluation-folding-release \
  --baselines /mnt/model-ssd/scratch/gigahorse-decompiler/dedaub-exports \
  --output artifacts/my-comparison
```


## Same-bytecode Dedaub comparison: Morpho liquidator (calibration)

`fixtures/dedaub/morpho-liquidator/` holds a 5,954-byte runtime (solc 0.8.34,
SHA-256 `e37d8859…f1f2`). It came with the Dedaub output for the same bytes,
supplied by the user on 2026-10-16. The pair was used during readability work,
so it is a calibration case, not a held-out test. Code lines exclude comments.

| Function | Dedaub | `decompiled.sol.txt` | previous `structured.sol.txt` |
| --- | --- | --- | --- |
| sweep | 12 | 14 | 62 |
| onMorphoFlashLoan | 84 | ~125 | 288 |
| MORPHO / owner / fallback | 6 | 6 | 15 |
| 0x441c1495 | 63 | 69 | 217 |
| selector dispatch | 17 | 22 | 24 |
| **whole contract** | **192** | **247** | **617** |

What a reviewer gets:

- **Names.** Both outputs name `sweep`, `MORPHO` and `owner`. With
  `--online-signatures` (once, then cached), the local view also names
  `onMorphoFlashLoan`, `idToMarketParams` and `liquidate`. `0x441c1495`
  remains unnamed in both.
- **Storage.** Both show `address _owner` at slot 0, bytes 0..19.
- **Access checks.** `!owner` and `!morpho` appear in both. The local view also
  lists them in a per-function summary.
- **Revert reasons.** Both decode `approve` and `min profit`. Dedaub prints
  `Error(0x73776170)` where the local view decodes `Error("swap")`.
- **Calls.** Both print `target.method(args)` for balanceOf, transfer,
  idToMarketParams, liquidate and flashLoan, and low-level `approve` via
  `call(abi.encodeWithSelector(...))`. Flash-loan data construction remains
  visible in both.
- **Noise.** Dedaub keeps return-data free-pointer updates and struct writes.
  The local view removes them where forwarding/liveness proves (or the
  scoped discipline assumes) they are unread.
- **Evidence and uncertainty.** Dedaub has none. The local view has per-line
  IR/bytecode maps, full IR accounting, and UNCERTAIN marks on the calls whose
  dynamic `bytes` arguments are not decoded.

Remaining gaps against Dedaub on this contract:

- `abi.decode` of the `bytes` callback data still appears as calldata field
  reads (`msg.data[t0 + 32]` …), not as a struct.
- `abi.encode(struct)` for flashLoan's data is still raw memory writes.
- 0.8 ABI-decoder bounds checks are printed. Dedaub prints them too.

Behavioral execution tests for this contract are still missing. Its view is
covered by the static invariants, not by the execution cross-check.
