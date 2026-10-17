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
so it is a calibration case, not a held-out test.

Code lines are non-blank lines that are not comments, from a function's
signature to its closing brace; the whole-contract row counts every such line
of the file (contract header, declarations). This is the rule that gives
Dedaub's file 192 lines. Earlier versions of this table left out closing
braces for the local view, so its 234 is 241 by this rule.

| Function | Dedaub | `decompiled.sol.txt` (15ce6b8) | `decompiled.sol.txt` (now) |
| --- | --- | --- | --- |
| sweep | 13 | 15 | 15 |
| onMorphoFlashLoan (`0x31f57072`) | 85 | 121 | 49 |
| MORPHO / owner / fallback | 9 | 9 | 9 |
| 0x441c1495 | 64 | 70 | 39 |
| selector dispatch | 18 | 23 | 23 |
| **whole contract** | **192** | **241** | **139** |

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
- **Flash-loan data.** Dedaub builds `v0 = new struct(7)` field by field (23
  lines, with every calldata read written out) in the callback, and writes the
  encoding word by word in `0x441c1495`. The local view declares `struct S0 {
  uint256 f0; address f1; uint256 f2; address f3; bytes f4; address f5; address
  f6; }` once and prints `v0 = abi.decode(varg1, (S0));` in the callback (the
  argument is typed `bytes`) and `v31 = abi.encode(S0(varg0, varg1, varg2,
  varg4, varg5, address(v7), address(v8)));` in the owner entry point. The
  shared name shows that the owner entry point encodes what the callback
  decodes. Later reads are fields: `idToMarketParams(v0.f0)`,
  `address(v0.f5).call(...)`, `address(v0.f3).call(v0.f4)`.
- **Calls.** Both print `target.method(args)` for balanceOf, transfer,
  idToMarketParams, liquidate and flashLoan, and the low-level `approve` via
  `call(abi.encodeWithSelector(...))`. Dedaub keeps the five memory statements
  of each `approve` buffer and the two of the swap's data copy. The local view
  folds them into the calls (`address(v0.f3).call(v0.f4)`). The empty `bytes` argument of `liquidate` is `v12 = new
  uint256[](0)` in Dedaub and `""` in the local view. `flashLoan(address(v7),
  varg3, v31)` takes the encoded struct.
- **Noise left.** Both still print the return-data free-pointer updates and
  the length checks of returned words; Dedaub also the returned struct's
  writes.
- **Evidence and uncertainty.** Dedaub has none. The local view has per-line
  IR/bytecode maps (the `abi.decode` line stands for 195 IR statements, the
  `abi.encode` line for 137) and full IR accounting. No code line of this
  contract is UNCERTAIN now: the inputs of all ABI calls are verified against
  their staging writes.

How the coders are recognized: `reconstruction/highlevel/abi_codec.py` walks
the compiled statements and compares each with the step solc emits: the
decoder's offset and size checks, `allocate_memory`, the member validators,
and the bytes member's bounds checks, copy and zero word. Expressions are
compared in a canonical form (linear arithmetic normalized, free-pointer
reads resolved). The interpreter then executes `abi.decode`/`abi.encode`
themselves: the same checks in the same order (`Panic(0x41)` where solc raises
it), allocation at the free pointer, and the same memory writes. The constant
struct address the analysis folded (0x80) is checked when executed.

Execution tests: 171 cases (165 external calls) run the printed view against
Py-EVM. Stubs sit at the hard-coded Morpho address and at token addresses. The
cases cover `onMorphoFlashLoan` (approve and swap failures, non-Morpho callers
and 14 malformed callbacks, one per decoder check: short data, offsets beyond
64 bits or past the end, dirty addresses before and after the bytes member,
oversized length and allocation (`Panic(0x41)`), bytes past the end, a
non-standard offset, trailing data), the owner entry point (flash loan, min
profit) and `sweep`. Mutating the interpreter's decoder (a dropped bounds
check, an empty revert in place of `Panic(0x41)`) makes the test fail. These
tests earlier found the `liquidate` argument error.


## Held-out corpus `heldout-2026-10-16` (partial)

`fixtures/evaluation-heldout/corpus.json` lists twelve mainnet runtimes, chosen
and committed (0459594) before any of them was analyzed: Tether USDT, DAI,
Compound cETH, Uniswap V2 Router02, the Chainlink ETH/USD proxy, the Uniswap V3
USDC/WETH pool, Azuki (ERC721A), the Aave V3 pool proxy, the ENS ETH registrar
controller, the 1inch v5 router, Seaport 1.5 and Curve 3pool (Vyper 0.2.4).
Verified ABIs are fetched alongside them. Only `scripts/evaluate-heldout.py`
reads them, after analysis. It counts each printed claim (name, arity, argument
type, payability, return types) as correct, unresolved or wrong. An unknown is
never counted as correct.

**Run 1** (`results/run1-partial.json`, code 0459594) stopped after five
contracts. The batch was stopped under system memory pressure while the
Uniswap V3 pool was being analyzed, and the timings were lost. The remaining
seven contracts have not been analyzed yet.

| Contract | Selectors | Names | Wrong claims (run 1) | Code lines | UNCERTAIN | Unstructured fns |
| --- | --- | --- | --- | --- | --- | --- |
| tether-usdt | 32/32 | 32 correct | 0 | 402 | 1 | 0 |
| dai | 22/22 | 22 correct | 2: `rely`/`deny` arity 2 vs 1 | 311 | 1 | 0 |
| compound-ceth | 45/45 | 45 correct | 3: `redeem`, `redeemUnderlying`, `seize` printed payable | 3,229 | 56 | 10 |
| uniswap-v2-router02 | 24/24 | 24 correct | 0 | 1,905 | 1 | 0 |
| chainlink-eth-usd-proxy | 23/23 | 23 correct | 0 | 488 | 10 | 0 |

The five wrong claims had two causes:

- **DAI.** The `note` modifier reads the selector word through a calldata load
  that was mislabeled as an argument.
- **cETH.** Payability was claimed for functions whose bodies were
  unstructured.

Both are fixed (9f0711e). Two later commits (b069b42, d51fda1) structure the
remaining cETH functions in three ways:

- jumps whose targets the native analysis already resolved;
- per-caller copies of code that old solc shares across call sites;
- the dispatcher's jumps into the fallback.

**Re-rendered from run 1's saved relations** (`results/run1-rerendered.json`,
code ddda645; no new native run). Because run 1 informed these fixes, these
numbers are no longer held-out measurements:

| Contract | Wrong claims | Code lines | UNCERTAIN | Unstructured fns | Returns unresolved |
| --- | --- | --- | --- | --- | --- |
| tether-usdt | 0 | 399 | 1 | 0 | 0/32 |
| dai | 0 | 296 | 3 | 0 | 6/22 |
| compound-ceth | 0 | 1,894 | 1 | 0 | 0/45 |
| uniswap-v2-router02 | 0 | 1,658 | 1 | 0 | 8/24 |
| chainlink-eth-usd-proxy | 0 | 488 | 10 | 0 | 8/23 |

**Re-rendered again after the ABI coder recognition**
(`results/run1-rerendered-abi.json`, code 6032b68, same saved relations): only
Router02 changes, 1,658 -> 1,330 code lines. All 44 `pairFor` hashes print as
`keccak256(abi.encodePacked(hex"ff", address(0x5c69…), keccak256-of-the-sorted-pair,
0x96e8…))`, and its `TransferHelper` buffers fold into their calls. Wrong
claims stay 0 on all five; UNCERTAIN, unstructured functions and unresolved
returns are unchanged. Router02's relations are now also a calibration
fixture (`fixtures/calibration/`), so its view is executed in tests (65 cases,
101 external calls against Py-EVM with stub pairs at the computed CREATE2
addresses).

DAI's two extra UNCERTAIN lines mark the reconciled arity of `rely`/`deny`. The
unresolved returns are mostly dynamic values (`string`, arrays) whose ABI
encoding is not recognized, and these are printed without a return type. The
Chainlink proxy's UNCERTAIN lines are ABI calls whose input length could not be
verified.

Router02 reads close to its source after these changes:

- `TransferHelper.safeTransferETH` reads `to.call{value: v}("")`.
- The pair swaps read `pair.swap(a0, a1, to, "")`, decoded from memory.
- All 27 code-copied revert reasons are decoded, e.g.
  `require(..., Error("UniswapV2Router: EXPIRED"))`. These carry rule
  `error-padding-not-modeled`: the unwritten padding after a copied reason is
  assumed zero. 6 such reverts are executed by tests and match the EVM bytes.

The remaining seven contracts are analyzed in run 2 below.

**Re-rendered after the size limits and the robustness fixes below**
(`results/run1-rerendered-limits.json`, code 7000f4a, same saved relations):
0 wrong claims on all five; code lines unchanged (399, 296, 1,894, 1,330, 488).


## Held-out run 2: the seven remaining contracts (first scores)

These are the first results for the seven contracts that run 1 did not reach.
They were recorded before any of the user's Dedaub exports for them were opened.
The exports were saved on 2026-10-16 in `fixtures/dedaub/heldout-2026-10-16/`
(committed unopened in c616d28). Everything after this section that uses these
contracts is calibration, not a held-out result.

**One change came from these contracts before scoring.** Run 1 was killed
while analyzing the Uniswap V3 pool. Its leftover working directory showed that
Gigahorse had finished in 8 s; the readable view then grew past 6 GB. The fix
(f7fb360) was made on that saved run-1 analysis only:

- The lifter inlined every pure value into each use, so chained reuse
  (Newton steps, `x * x + x`) doubled the printed tree per step. A value whose
  inlined form exceeds 128 nodes is now printed once as a local, marked
  `// not inlined: over 128 nodes` (rule `inline-size-limit`). The largest
  inlined value in the fixtures has 72 nodes, so no fixture changed.
- The ABI coder tracker's canonical forms shared subterms the same way
  (hashing and `repr` were exponential). A form over 256 nodes becomes a fresh
  atom that equals nothing, so a recognizer can only miss, never match wrongly.

**How the contracts ran** (code b5a9a9d, `results/run2.json`): natively, one at
a time, smallest first, each in a systemd scope capped at 16 GB with swap off,
a 1-hour wall-clock limit and Gigahorse's 300 s analysis timeout. At least
20 GB of free memory was checked before each start. Peak memory is that of the
largest single process (GNU time).

| Contract | Bytes | Status | Time | Peak memory | Selectors | Names (correct / unnamed / wrong) | Wrong claims | Code lines | UNCERTAIN | Unstructured fns |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| aave-v3-pool-proxy | 2,400 | ok | 1.4 s | 0.03 GB | 5/5 | 5 / 0 / 0 | 0 | 163 | 3 | 0 |
| ens-eth-registrar-controller | 7,633 | ok | 3.0 s | 0.07 GB | 20/20 | 18 / 2 / 0 | 0 | 634 | 7 | 0 |
| azuki-erc721a | 14,251 | ok | 8.8 s | 0.14 GB | 45/45 | 45 / 0 / 0 | 0 | 1,103 | 5 | 0 |
| curve-3pool (Vyper) | 21,199 | **failed** (Python error) | 7.5 s | 0.42 GB | - | - | - | - | - | - |
| uniswap-v3-pool-usdc-weth | 22,142 | ok | 69.3 s | 0.27 GB | 26/26 | 26 / 0 / 0 | 5 | 1,932 | 5 | 0 |
| oneinch-router-v5 | 22,484 | **failed** (Gigahorse error) | 168.8 s | 15.93 GB | - | - | - | - | - | - |
| seaport-1-5 | 24,367 | ok | 47.9 s | 0.69 GB | 16/17 | 5 / 8 / 3 | 7 | 8,963 | 24 | 1 |

What went wrong:

- **Curve 3pool: no output.** Gigahorse finished. The readable view then
  raised `IndexError` in `lift.py` (`_statement`): a memory store with a single
  operand, inside a block of Vyper code that could not be structured. One
  crash in one function cost the whole contract.
- **1inch v5: no output.** Gigahorse itself stopped after 169 s with
  `TAC_Use: conflicting operand at 0x14e2, index 0`, while its peak memory
  (15.9 GB) was just under the 16 GB cap. Whether the cap contributed is not
  known.
- **Uniswap V3 pool: 5 wrong claims, one cause.** `uint160` values are printed
  as `address`: `initialize`'s argument, `swap`'s `sqrtPriceLimitX96`, and one
  return value each of `slot0`, `observations` and `snapshotCumulativesInside`
  (the `sqrtPriceX96` / `secondsPerLiquidity` words). A 160-bit mask is read as
  an address. Separately, 140 IR statements are not accounted for in the
  evidence map (every fixture has 0).
- **Seaport 1.5: 7 wrong claims.**
  - Three names come from deliberate selector collisions in the local signature
    dictionary (`SubToJunionOnYoutubeXD_lvfsnfguwqne()` for `cancel`'s
    `0xfd9f1e10`, and two similar ones). The hash matches; the name is wrong.
    Because Seaport reads its arguments in assembly, no arguments were
    recovered, so the printed arity (0) agreed with the wrong name and nothing
    flagged it: 3 name and 3 arity errors.
  - `getOrderStatus` returns `uint120` where the ABI says `uint256` (the value
    is a packed 120-bit storage field).
  - Selector `0x00000000` (`fulfillBasicOrder_efficient_6GL6yc`) is not shown as
    a public function.
  - Eight functions are unnamed (their struct-array signatures are not in the
    local dictionary), one function's control flow is not structured, and the
    file has 8,963 code lines.
- **ENS controller:** `makeCommitment` and `register` (with `bytes[]`
  arguments) are unnamed, and four dynamic arguments have unresolved types.

Totals over the five contracts with output: 112/113 selectors, 99 names
correct, 10 unnamed, 3 wrong; 12 wrong claims, all in the V3 pool and Seaport.

**After two robustness fixes** (cb22824, made after the first scores and
informed by the two failures; `results/run2-after-fixes.json`, re-rendered from
saved relations, no new native run for the scored five):

- A statement with fewer operands than its EVM stack inputs (Curve's 24
  one-operand `MSTORE`s) stays a raw operation marked UNCERTAIN.
- An operand the IR gives several values for (1inch: 60 positions in 29
  statements) becomes an unordered PHI over them, with a warning, instead of
  rejecting the program. One is never picked. Conflicting definitions still
  fail.
- A failure in one function's view now costs only that function (an
  UNCERTAIN stub that claims no arguments), and `decompile` keeps Gigahorse's
  relations when a later step fails.

The five contracts that had output render byte-identically. Curve now has
1,767 code lines, but no public functions are separated (0/38 selectors: the
Vyper dispatcher is not recognized) and its body is unstructured. 1inch has
7,450 code lines, 45/45 selectors, 21 names correct and 24 unnamed, 5 wrong
claims (functions taking a static struct are printed with one argument per
struct word, e.g. arity 10 for `swap`'s 4), 434 UNCERTAIN lines and 12
unstructured functions.


## Held-out run 2: same-bytecode comparison with Dedaub

The user's exports of Dedaub's standard decompiler output for the seven
contracts (`fixtures/dedaub/heldout-2026-10-16/`) were opened only after the
first scores above were committed (96ef441). `scripts/compare-dedaub.py`
(`results/run2-dedaub-comparison.json`) scores both texts with the same
held-out scorer against the verified ABIs. Dedaub's signatures come from its
dispatcher and its argument types and payability from its function headers.
Dedaub prints no return types. The local outputs are those after the fixes
above. Code lines use the whole-file rule (non-blank, non-comment). "Raw" lines
read or write `MEM[...]` or `msg.data[...]` or copy memory, in either tool.

| Contract | Code lines (local / Dedaub) | Raw share | Public functions found (of ABI) | Names correct | Wrong claims (excl. payability) | Decoded revert reasons |
| --- | --- | --- | --- | --- | --- | --- |
| uniswap-v3-pool-usdc-weth | 1,932 / 1,976 | 23% / 9% | 26 / 26 (26) | 26 / 26 | 5 / 0 | 32 / 0 |
| azuki-erc721a | 1,103 / 896 | 22% / 6% | 45 / 45 (45) | 45 / 45 | 0 / 0 | 52 / 54 |
| aave-v3-pool-proxy | 163 / 130 | 33% / 18% | 5 / 5 (5) | 5 / 5 | 0 / 0 | 6 / 6 |
| ens-eth-registrar-controller | 634 / 512 | 42% / 18% | 20 / 20 (20) | 18 / 20 | 0 / 0 | 4 / 4 |
| oneinch-router-v5 | 7,450 / 3,168 | 24% / 15% | 45 / 45 (45) | 21 / 45 | 5 / 6 | 9 / 9 |
| seaport-1-5 | 8,963 / 5,406 | 57% / 43% | 16 / 15 (17) | 5 / 13 | 7 / 13 | 0 / 0 |
| curve-3pool (Vyper) | 1,767 / 583 | 23% / 20% | 0 / 38 (38) | 0 / 0 | 0 / 0 | 0 / 0 |
| **total** | **22,012 / 12,671** | **38% / 26%** | **157 / 194 (196)** | **120 / 154** | **17 / 19** | **103 / 73** |

Payability is counted separately. Dedaub prints every V3 pool function
`payable`, as it did for Morpho, although both contracts reject ETH in the
dispatcher: 26 labels disagree with the ABI for Dedaub, 0 for the local view.

**Not at parity.** Accuracy is comparable (17 wrong claims against 19), but
Dedaub's output is 1.7 times shorter overall and much less raw. Only the V3
pool is about the same length (0.98x). The gaps, largest first:

- **Memory as values.** Dedaub prints allocations as objects: `new struct(7)`
  with `.word0`...`.word6` for the V3 `swap`'s cached `slot0`, `new bytes[](n)`
  and array accessors in ENS's commitment encoding. The local view prints the
  same steps as `MEM[...]` writes. This is most of the raw-share difference
  (38% against 26%).
- **Names from a larger database.** Dedaub names all 20 ENS and 45 1inch
  functions (local: 18 and 21) and 13 of Seaport's 17 (local: 5). It also
  names parameters (`recipient`, `zeroForOne`), custom errors
  (`InsufficientValue()`, `SwapAmountTooLarge()`, where the local view prints
  the selectors `0x11011294`, `0xcf0b4d3a`), external calls
  (`registerAndWrapETH2LD`) and events. Some of Dedaub's names come from
  source-level knowledge, not from the bytecode: 39 private functions in three
  contracts carry source names with node ids (`@rentPrice_3602`,
  `@_setImplementation_127`, 33 in 1inch). There are none in the unverified
  Morpho contract. The local view uses no source or ABI, by design.
- **Vyper.** Neither tool splits Curve into functions. Dedaub's single
  dispatcher function is structured and lists all 38 selectors. The local
  view's is unstructured blocks, three times longer.
- **Large assembly-heavy contracts.** The local view is 1.7 times longer on
  Seaport and 2.4 times on 1inch. On 1inch, 395 of its 434 UNCERTAIN lines are
  unordered PHIs, from the ambiguous operands above and other unresolved
  merges.

Where the local view is ahead or equal:

- **Revert reasons.** The V3 pool's short reasons decode (`Error("LOK")`,
  `Error("SPL")`, 32 sites); Dedaub prints them as numbers (`Error(0x4c4f4b)`).
- **Wrong claims.** Both share the 1inch struct-argument arity errors (5
  local, 6 Dedaub) and Seaport's selector-collision names (3 local, 2 Dedaub;
  Dedaub omits `cancel`). Dedaub's Seaport headers also misplace array
  parameter types (8 wrong types, e.g. `[] varg1`, `[][] recipient`). The local
  view's own error is the V3 pool's `uint160` printed as `address` (5).
- **Payability and return types** are printed and correct; Dedaub prints no
  return types.
- **Evidence and uncertainty.** Every local line maps to IR and bytecode, and
  unresolved constructs are marked; Dedaub has neither.
- **Simple contracts.** On Azuki and the Aave proxy both find the same
  functions, names, access checks and revert reasons. The local view is about
  1.25 times longer, with more raw memory writes.

Analysis cost: the seven first runs took 307 s together. The largest peak was
1inch, at 15.9 GB in Gigahorse's core decompiler (17.3 GB under a 24 GB cap).

Next priorities, by measured gap: memory allocations printed as objects (the
raw share); signature coverage for custom errors, events, external calls and
parameter names; static-struct arguments (arity) and `uint160` against
`address`; the Vyper dispatcher.


## Memory objects and custom errors (calibration on the run-2 contracts)

The seven run-2 contracts became calibration once their Dedaub exports were
read, so the work below was tuned on them. To keep a later measurement honest,
a new held-out set was frozen first (354be8c, `fixtures/evaluation-heldout-2/`):
WBTC (solc 0.4.24), wstETH (0.6.12), the Uniswap V3 position manager (0.7.6),
the Balancer V2 vault (0.7.1), the ENS public resolver (0.8.17), Permit2
(0.8.17, via-IR), the Uniswap V4 pool manager (0.8.26, via-IR) and the Curve
stETH pool (Vyper 0.2.8). None of them has been analyzed yet.

**What changed** (0a47f5e, cd75c30, 7fffd2d):

- **Custom errors and Panic codes built in memory** become one revert:
  `revert InvalidMsgValue();`, `require(c, InsufficientValue())`,
  `revert(Panic(33))`, or `revert(abi.encodeWithSelector(0x68275857, ...))`
  when the selector has no dictionary name. Named errors get
  `error Name(types); // [dict]` declarations. Both selector layouts are
  matched: left-aligned at the payload start (solc) and right-aligned
  (`mstore(0, sel); revert(0x1c, n)`, Seaport/Solady). The argument words
  must fill exactly the reverted range, and a memory read among them keeps
  the stores before it, so the payload bytes are those the code reverts with.
- **Allocations at the free pointer print as values** (a final presentation
  pass, after every memory analysis):
  - `v = new struct(k)`, and `v = struct(a, b, ...)` when all words are
    written right after; fields print as `v.wordN`;
  - `new bytes(n)` and `new uint256[](n)`, with `v.length` and elements
    `v[i]`;
  - `v = varg0; // calldata bytes|array copied to memory` and
    `v = returndata; // returned data copied to memory`;
  - byte constants print as `"Uniswap V2"`.

  An allocation executes exactly the statements it replaced, and a field is
  exactly `MEM[base + offset]`.
- **Folded pointers.** Where the analysis folded the free pointer (V3:
  `MEM[64] = 352`, fields at `MEM[160]`), an object assumes solc's initial
  `0x80`, but only at a public entry point before anything could move the
  pointer. The interpreter checks the assumption when it runs the view (rule
  `assumes-folded-free-pointer`).

**Results on the seven run-2 contracts** (`results/run2-objects-errors.json`,
`results/run2-dedaub-comparison-objects-errors.json`):

| Contract | Code lines (before -> now; Dedaub) | Raw lines (before -> now; Dedaub) |
| --- | --- | --- |
| uniswap-v3-pool-usdc-weth | 1,932 -> 1,820; 1,976 | 447 -> 196; 187 |
| azuki-erc721a | 1,103 -> 1,048; 896 | 241 -> 153; 54 |
| aave-v3-pool-proxy | 163 -> 151; 130 | 53 -> 40; 24 |
| ens-eth-registrar-controller | 634 -> 581; 512 | 266 -> 203; 94 |
| oneinch-router-v5 | 7,450 -> 7,082; 3,168 | 1,812 -> 1,252; 480 |
| seaport-1-5 | 8,963 -> 6,690; 5,406 | 5,098 -> 3,049; 2,306 |
| curve-3pool | 1,767 -> 1,767; 583 | 405 -> 405; 114 |
| **total** | **22,012 -> 19,139; 12,671** | **8,322 -> 5,298 (38% -> 28%); 3,259 (26%)** |

- **Errors named.** Reverts whose selector is in the local error dictionary
  but printed raw went from 306 to 0. Before, 264 of them were inline Panic
  codes. Seaport now declares 29 named errors.
- **Wrong claims are unchanged:** 17 on run 2 (the same claims) and 0 on the
  five run-1 contracts (`results/run1-rerendered-objects-errors.json`).
- **No fixture got longer.** Fixture renders went from 9,177 to 8,708 code
  lines (cETH 1,894 -> 1,730, Router02 1,330 -> 1,220).

**Behavioral evidence:** 425 tests passed and 17 were skipped; the cross-check
is unchanged at 1,079 agreeing executions with 0 unsupported. Counted during
the suite, the view executed:

| Construct | Executions |
| --- | --- |
| Arrays | 157 |
| Byte arrays | 183 |
| Structs | 150 |
| Struct literals | 106 |
| String constants | 21 |
| Calldata copies | 81 |
| Returned-data copies | 129 |
| Field reads (length / word / element) | 601 / 64 / 48 |
| Field writes (word / element) | 102 / 74 |
| Custom errors | 21 |
| Reverts folded from memory | 19 |

Synthetic bytecode compares with Py-EVM:

- struct literals, partial structs and fields;
- `new bytes` and arrays with elements, including a store at a
  calldata-chosen address that hits the fields;
- an inline Panic, and exact against clobbered or partly unwritten error
  payloads;
- right-aligned payloads: one argument, an argument in the `0x40` slot, and
  an argument read from memory.

A wrong folded-pointer assumption raises when executed, both in a payload and
in the pair's checked string constant. Mutations are caught: a shifted field
offset, a missing length word, and dropped stores before a memory-reading
argument.

**Still open:**
- 1inch's 12 unstructured functions (block labels and gotos);
- Seaport's hand-written low-level memory code;
- Curve, where the Vyper dispatcher is not recognized and the code stays
  unstructured;
- return-data bubbles (`RETURNDATACOPY` then `revert(MEM[0:n])`) not yet
  printed as `revert(returndata)`;
- hashes over words written to memory;
- array elements at folded constant addresses, which stay raw because the
  array's extent depends on its length.

The next measurement is run 3 on `fixtures/evaluation-heldout-2/`, with the
user's Dedaub exports for those eight contracts.


## Held-out run 3: `heldout-2-2026-10-16` (first scores)

The eight contracts frozen in 354be8c (`fixtures/evaluation-heldout-2/`), each
analyzed once natively at 364c079, before any change made for them:

- **How they ran:** one at a time, smallest first, each in a systemd scope
  capped at 24 GB with swap off, a 1-hour wall-clock limit and Gigahorse's
  300 s timeout, with at least 30 GB of free memory checked before each.
- **Where the results are:** `fixtures/evaluation-heldout-2/results/run3.json`.
- **Dedaub:** no exports have been requested yet.

| Contract | Compiler | Status | Time | Peak | Code lines | Selectors | Names (correct / unnamed / wrong) | Wrong claims | UNCERTAIN | Unstructured fns |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| wbtc | 0.4.24 | ok | 2.2 s | 0.04 GB | 261 | 24/24 | 24 / 0 / 0 | 0 | 1 | 0 |
| wsteth | 0.6.12 | ok | 2.3 s | 0.05 GB | 377 | 21/21 | 21 / 0 / 0 | 0 | 1 | 0 |
| permit2 | 0.8.17 via-IR | ok | 4.4 s | 0.10 GB | 1,098 | 15/15 | 2 / 13 / 0 | 3 | 7 | 0 |
| ens-public-resolver | 0.8.17 | ok | 7.6 s | 0.16 GB | 2,115 | 30/30 | 25 / 5 / 0 | 0 | 8 | 0 |
| curve-steth-pool | Vyper 0.2.8 | ok | 4.1 s | 0.24 GB | 1,318 | 0/39 | - | 0 | 30 | 1 |
| uniswap-v4-pool-manager | 0.8.26 via-IR | ok | 69.6 s | 0.19 GB | 2,938 | 33/33 | 16 / 17 / 0 | 8 | 45 | 1 |
| uniswap-v3-position-manager | 0.7.6 | ok | 11.5 s | 0.23 GB | 1,678 | 38/38 | 34 / 4 / 0 | 6 | 4 | 0 |
| balancer-v2-vault | 0.7.1 | ok | 333.8 s | 0.48 GB | 4,002 | 26/26 | 19 / 7 / 0 | 6 | 671 | 6 |

**Totals.** All eight produced output. Selectors: 187/226; all 39 missing are
Curve's, because the Vyper dispatcher is not recognized. Names: 141 correct,
46 unnamed, 0 wrong. Wrong claims: 23 in all.

The 23 wrong claims by cause:

- **18 argument counts for struct parameters:**
  - Permit2, V4 and Balancer (10): a static struct is printed as one
    parameter per word, e.g. 8 for `permit(address, PermitSingle, bytes)`.
  - V3 position manager and Balancer (8): the code-derived count is 0 while
    the hash-checked signature has one or more struct parameters, e.g.
    `collect(CollectParams)`, `mint(MintParams)`, `swap(SingleSwap, ...)`.
- **2 types:** V4's `mint`/`burn` take a `uint256 id` that the code uses as an
  address, and it is printed as `address`.
- **1 type:** the position manager's `createAndInitializePoolIfNecessary`
  prints its `uint160` price as `address`.
- **2 return widths:** values returned as `uint128` or `uint112` where the ABI
  declares `uint256` (or `address`).

**After fixing three wrong-claim causes** (adcf6e5, made after the first
scores above; re-rendered from saved relations, no new native runs):

- **Dictionary names the decoder contradicts.** solc never requires more
  argument bytes than the head of the declared parameters, so a hash-matched
  name with fewer head bytes than the decoder checks is rejected. The
  rejection is shown as a note under the selector. This removes Seaport's
  three spam names (`SubToJunionOnYoutubeXD...`). Code-derived arity is also
  capped at that head, since further words are tail reads.
- **Static struct parameters.** The decoder checks each static struct
  separately (`msg.data.length - H >= S`, as a require or a branch). Those
  words print as one `S<n> varg<i>` parameter with fields `varg<i>.f<j>`; with
  a hash-matched signature, its tuples decide.
- **uint160 printed as address.** A 160-bit mask or validator cannot tell the
  two apart:
  - a hash-matched signature decides;
  - a mask-only word declared wider keeps its masks at each use;
  - without a signature, `numeric.py` retypes arguments and returned values
    that are used in arithmetic, and address uses always win.

| Set | Wrong claims (before -> after) | Remaining |
| --- | --- | --- |
| Run 1 (5 contracts) | 0 -> 0 | - |
| Run 2 (7 contracts) | 17 -> 1 | Seaport `getOrderStatus` returns `uint120` (a packed field) where the ABI says `uint256` |
| Run 3 (8 contracts) | 23 -> 10 | 8 argument counts of structs decoded by helper functions (V3 position manager, Balancer: no arguments recovered); 2 return widths (`uint128` / `uint112` against `uint256`) |

No new wrong claims in any set (`results/run1-rerendered-parameters.json`,
`results/run2-parameters.json`, `evaluation-heldout-2/results/run3-after-fixes.json`).
Names in run 2: Seaport goes from 3 wrong to 3 unnamed. Existing fixture
renders are byte-identical, except two DAI comment lines ("head word(s)"
instead of "parameter(s)"). Struct parameters add one declaration line each
in the held-out outputs (Permit2 +3, V4 +3, 1inch +2, Balancer +1).

**Tests.** A new compiler fixture, `ParameterFixture` (solc 0.8.30,
optimized and via-IR), has calldata and memory structs, a `uint160`
parameter and storage, a computed `uint160` return, a `uint256` used as an
address, and a read past the head.

- Both variants score 0 wrong claims against the compiler ABI.
- Both run against Py-EVM: struct words with dirty address bits, owner checks,
  and dirty `uint160` and `uint256` words.
- A colliding name is rejected and the real one kept; the signature settles
  `uint160`; the scorer compares struct types word by word.
- Turning off the truth-test exclusion, or not keeping the masks, fails the
  tests.
- 434 passed, 17 skipped; the cross-check is unchanged at 1,079 agreeing.

## Held-out corpus `heldout-3-2026-10-16` (frozen, not analyzed)

Runs 1-3 are calibration now. Before the next changes (structs decoded by
helper functions, Vyper dispatch, unstructured functions), eight more verified
mainnet runtimes were frozen in `fixtures/evaluation-heldout-3/`: two Vyper
(0.3.10 stableswap-ng pool, 0.2.12 tricrypto2), two via-IR (Uniswap V4
position manager, MetaMorpho), SwapRouter02 and CoW settlement (0.7.6, struct
parameters), Maker's Vat (0.5.12, no optimizer) and the Euler EVC (0.8.24). No
runtime equals an existing fixture's. They are run once, and scored, only after
that work is done.

## Structs decoded by helper functions, and selectors shared with internal code

Calibration on runs 1-3 (set 3 stays frozen). The 8 remaining wrong argument
counts had two causes, neither of them the one assumed:

- **Balancer (4): one selector, two functions.** The native analysis marks a
  function public when code compares `msg.sig` with a selector before reaching
  it. The vault's swap and join paths do that inside an internal function, so
  each of `swap`, `batchSwap`, `joinPool`, `exitPool` (and
  `setRelayerApproval`) had a second "public" function with no arguments,
  which the scorer read. The dispatcher passes no stack arguments, so when
  exactly one claimant of a selector has none, the claimants with formal
  arguments are printed as the internal functions they are (`fn_0x496a(...)`).
- **V3 position manager (4): struct read through a decoder's pointer.** solc
  returns a `calldata` struct parameter as a pointer from its decoder helper
  (`fn_0x5550(4, msg.data.length)`), and the function reads field j at
  `pointer + 32 * j`. The native argument relation does not follow the
  pointer, so no argument was bound. The struct's own bounds check sits in the
  helper (`calldatasize - pointer < S`); it is now found by following calls
  made with a constant head position and `calldatasize`, and the words read
  through the pointer become one struct parameter (`function 0x88316456(S2
  varg0)`). Fields the code never reads are kept (unread), because the decoder
  checks the whole struct.

Two more cases came from the new fixture rather than from the held-out sets:

- With an inlined decoder (via-IR), a struct that is the whole head leaves
  only the head check. Separate parameters are validated at entry; a calldata
  struct's members are validated where they are read. A head whose words are
  validated late, none at entry, with at least two different types (a static
  array's elements share one) is one struct. A uint128 check at entry (a
  SafeCast) looks like a decoder validator, so such a function keeps its
  separate words (`scaled` in the fixture).
- Fields of these structs are typed from validators where they are read when
  every other use is the same cast; the checks stay in the body and nothing
  is enforced at entry (a field read on one branch only must not revert on the
  other).

| Set | Wrong claims before | After |
| --- | --- | --- |
| Run 1 (5) | 0 | 0 |
| Run 2 (7) | 1 | 1 |
| Run 3 (8) | 10 | 2 |

- No new wrong claims, and no correct count lower in any set
  (`results/run1-helper-structs.json`, `results/run2-helper-structs.json`,
  `results/run3-helper-structs.json`). V3 position manager: arity 34 -> 38 of
  38, argument types 59 -> 61 correct, the mint struct typed exactly as the
  ABI. Balancer: arity 22 -> 26 of 26, payability 21 -> 26, returns 16 -> 17.
- Only those two outputs changed (Balancer +11 lines for the internal
  functions that were mislabelled public). Every existing fixture renders
  byte-identically.
- The three claims left are return widths: V3 `collect` (`uint128` vs
  `uint256`), Balancer `getPoolTokenInfo` (`uint112`) and Seaport
  `getOrderStatus` (`uint120`). The returned value is masked to the field's
  width; solc emits the same mask for a `uint128` return and for a `uint256`
  return of a `uint128` value (encoder cleanup vs conversion cleanup, folded
  by the optimizer), so the bytecode does not decide the declared type. The
  same reading is right for 41 narrow returns in 18 other functions of these
  sets. Widening every mask-only return to `uint256` would remove the three
  claims but turn those 18 functions from correct to unresolved; the user
  chose to keep the narrow reading and say what it rests on. A view that
  prints a narrow return now carries a legend note: the width is the mask's,
  and the source may declare a wider type for the same value. These three are
  recorded as limits the bytecode cannot settle, not as open defects.

Tests: new compiler fixture `DecoderFixture` (solc 0.8.30, optimized and
via-IR) with the struct as the whole head, a field validated on one branch, a
struct after a word, and a SafeCast-style check on a uint256 field.

- The optimized variant scores 0 wrong claims against the compiler ABI; via-IR
  gets every struct except the SafeCast case.
- Both run against Py-EVM, with a dirty word in each field and a dirty field
  on the branch that does not read it.
- A synthetic program checks the shared-selector rule.
- Breaking any of the seven rules (the selector rule, unread words, the
  direct struct decoder call, field typing, entry enforcement, the argument
  definition, the whole-head rule) fails the tests.
- 441 passed, 17 skipped; the cross-check is unchanged at 1,079 agreeing.

## Vyper dispatch

The two Vyper contracts in runs 1-3 had no public functions at all: Curve
3pool (Vyper 0.2.4, 38 functions) and Curve stETH (0.2.8, 39) printed as one
dispatcher. Newer Vyper compilers dispatch in two more ways, so four compiled
fixtures cover them (`VyperFixture.vy`, 13 functions each):

| Compiler | Dispatch | Fixture |
| --- | --- | --- |
| Vyper 0.2.x | `mstore(28, calldataload(0))`, then `mload(0) == selector` per function | `vyper-v0216` |
| Vyper 0.3.9 | `shr(224, calldataload(0))` on the stack, `xor` per function | `vyper-v039` |
| Vyper 0.3.10, gas | the selector picks a bucket from a table in the code; `jump(mload(0))` | `vyper-v0310` |
| Vyper 0.3.10, codesize | a hashed table entry holds (selector, handler, flags); checked, then jumped to | `vyper-v0310-codesize` |

What was missing, and what changed:

- **Vyper 0.2 (native rule).** Gigahorse already matches the
  `eq`/`iszero`/`jumpi` comparison, but only accepts a selector that comes
  from `calldataload(0)` shifted or divided. A selector read back as
  `mload(0)` after `mstore(28, calldataload(0))` is now one. Without this rule
  Curve 3pool has 0 public functions; with it, 38.
- **Selector tables (native facts from execution).** The jump target is read
  from code through memory, which a stack analysis cannot follow.
  `src/selector_table.py` runs the dispatcher prefix on concrete calldata
  instead of matching either layout:
  - a jump every probe selector reaches is a bucket jump, and its targets are
    the buckets;
  - a jump only some selectors reach checks the selector first, so each
    selector that reaches it is dispatched to that handler;
  - probing with a call value and short calldata gives the dispatcher's own
    checks per entry.
  The targets become `JumpTableTarget` facts (new CFG edges, mapped to each
  analysis' cloned statement ids); dense-table handlers also become public
  functions (`SelectorTableEntry`).
- **A guard that hid every Vyper 0.3 function.** The Vyper transformation is
  switched off when Solidity-style dispatch (`eq` with a constant, then
  `jumpi`) appears anywhere. Vyper 0.3's reentrancy check,
  `sload(lock) == 2`, matched it, so a single `@nonreentrant` function left
  the whole contract with no public functions. Only a selector-sized constant
  compared with the dispatcher's selector counts now.
- **The table dispatcher printed as its selector chain.** The lifted
  dispatcher is an unstructured computed jump. It prints instead as
  `if (msg.sig == ...) return f();` per function, with the dispatcher's own
  checks for dense entries, and `revert()` last, which is only printed when
  executing the dispatcher with unrouted selectors shows exactly
  `revert(0, 0)`. Every routed selector must have a public function, or the
  original form is kept. The original statements are the chain's evidence.
- **Payability.**
  - A `require(!msg.value)` in the dispatcher marks every function dispatched
    after it on the same path. Vyper 0.2.16 checks once, after its payable
    functions.
  - Vyper 0.3 merges the value and calldata-size checks; the merged check is
    split into the two.
  - Vyper 0.2 checks its `@nonreentrant` lock before the value. A data-less
    require and a store before the check do not change what a call with value
    does (it reverts without data either way), so the check still marks a
    public function.
- **Static arrays from signatures.** A hash-matched signature's `uint256[3]`
  groups its three head words into one parameter (`uint256[3] varg0`, uses
  `varg0[i]`), like its tuples.

Results, with every run 1-3 contract re-analyzed natively after the Datalog
changes (`results/runs1-2-vyper-dispatch.json`,
`results/run3-vyper-dispatch.json`):

| Contract | Before | After |
| --- | --- | --- |
| Curve 3pool | 0/38 selectors | 38/38, 38 names correct, 0 wrong claims |
| Curve stETH | 0/39 selectors | 39/39, 39 names correct, 0 wrong claims |
| 18 Solidity contracts | | native relations byte-identical to before; scores and lengths unchanged |

- Total wrong claims on runs 1-3: 3, the documented return widths.
- The Curve views are longer (1,767 -> 2,380 and 1,318 -> 2,225 code lines)
  because their functions now print one by one. 13 and 15 of those functions
  are still unstructured, and the uncertain lines rose (37 -> 55, 30 -> 60).
- 1inch needs Gigahorse's scalable fallback, which starts at half the native
  timeout. With a 1,800 s timeout, the default configuration runs until it
  passes 24 GB, and also 32 GB; this happens with the previous Datalog too.
  With the 300 s timeout of the earlier runs it finishes at 17.75 GB.

Tests:

- The four Vyper fixtures recover all 13 functions with 0 wrong claims and all
  payability right, and run against Py-EVM: value sent to nonpayable
  functions, underflow, owner checks, dirty address and bool words, short and
  unknown calldata, a locked add_liquidity.
- The recognizer finds nothing on the linear dispatchers or on solc code, the
  sparse bucket jump with every routed selector, and the dense entries with
  payability and minimum sizes. A fallback that does not revert is not
  vouched for.
- Breaking any of seven rules fails the tests: the chain, dispatcher value
  checks, the merged check, signature arrays, the lock prefix, dense entry
  checks, the fallback check.
- Existing fixtures render byte-identically (8,953 code lines). 455 passed,
  17 skipped; the cross-check is unchanged at 1,079 agreeing.

## Unstructured functions in Balancer and 1inch

Before: 18 unstructured functions (Balancer 6, 1inch 12) and 1,100 UNCERTAIN
lines (666 and 434), nearly all of them PHI assignments that unstructured code
cannot associate with predecessors.

What was structured:

- **Balancer `fn_0x23f4`: a shared region with two returns.** An internal
  function is inlined into one region entered from two call sites, and returns
  from two places, both through the same return-address PHI. The splitter
  copied the region per caller but took only one return jump, so the other
  return's path looked like a second entry. All return jumps through the PHI
  now form the region's exits; each caller's copy returns to its own
  continuation. Balancer's uncertain lines go from 666 to 12.
- **Balancer's five pseudo-functions: a `msg.sig` switch.** The vault's
  signature type-hash lookup switches on `msg.sig` inside an internal function
  (`if eq(selector, ...)`). The native analysis took each case for a public
  function entry (phase 1 printed them as internal functions; they still could
  not be structured). solc and Vyper emit the dispatcher first, so a selector
  comparison that repeats one at a lower address no longer starts a function
  (native rule). The cases are blocks of the lookup function again, which is
  structured. Without the rule, `SwitchFixture` gets each switched selector
  twice.
- **1inch `fn_0x14b2`, `fn_0x18bd`, `fn_0x32d7`: copies of a callee next to
  the call.** A call block also had an edge into a copy of the callee's
  entry, named after the caller (`0x54b00x14b2`), whose return jump is
  unresolved. The call already runs the callee, so when the call has a single
  continuation such edges are ignored. The copies are then unreachable, and
  their statements are accounted for as "callee_copy_not_executed". Splitting
  shared regions now only considers jumps the function can reach. These three
  now print as structured code, but 15 of their PHI assignments still have no
  recorded predecessor association. They stay marked UNCERTAIN rather than
  guessed, which is why 1inch's count rises by 15.

| Contract | Unstructured functions | UNCERTAIN lines | Code lines |
| --- | --- | --- | --- |
| Balancer vault | 6 -> 0 | 666 -> 12 | 4,014 -> 3,313 |
| 1inch v5 router | 12 -> 9 | 434 -> 449 | 7,084 -> 7,099 |
| Both | 18 -> 9 | 1,100 -> 461 | |

Still unstructured (all 1inch), by cause:

- `uniswapV3Swap`, `uniswapV3SwapTo`, `uniswapV3SwapToWithPermit`: a shared
  region whose return address for one caller is not a constant but the result
  of another internal call, which passes the return label through. The
  splitter needs a constant per caller.
- `0x62e238bb`, `0xd365c695`, `0xe5d7bde6`: a call to `0x3e31` for which the
  native call-return relation lists two continuations (`0x1d1b`, `0x1db0`).
  solc pushes the return address of the next internal call before this one, and
  the native analysis merges the two contexts.
- `0x3c15fd91`, `0x3eca9c0a`, `0x70ccbd31`: a jump to a constant address
  (`0x42e`, `0x31d`), solc's return-encoding tail shared by several public
  functions. The native analysis assigns it to another function and records no
  edge.

Every change was checked against all 20 run 1-3 contracts re-analyzed
natively (`results/runs1-2-structuring.json`, `results/run3-structuring.json`):
only Balancer's native relations change; the 19 others are byte-identical;
no wrong claim is new, no correct count lower (3 wrong claims, the return
widths). Every compiler and deployed fixture with a snapshot re-analyzed
natively gives the same relations as its snapshot.

Tests:

- Synthetic CFGs cover a shared region with two returns per caller and a call
  with a copy of its callee (structured, copy not printed, accounted for). Any
  other second target, or a second continuation, stays explicit.
- The new compiler fixture `SwitchFixture` (an EQ-compared `msg.sig` switch in
  an internal function, optimized and via-IR) has only its real public
  functions, structured, executed against Py-EVM.
- Breaking any of the four rules fails the tests: all exits, ignoring callee
  copies, reachable-only splitting, copy accounting.
- Existing fixtures render byte-identically (8,953 code lines). 461 passed,
  17 skipped; the cross-check is unchanged at 1,079 agreeing.

## Held-out run 4: `heldout-3-2026-10-16` (first scores)

Set 3 was frozen in ce7ee54, before the work on helper-decoded structs, Vyper
dispatch and structuring, and was not analyzed until that work was committed
(639bcc9). Each contract then ran once natively (24 GB cap, 300 s native
timeout, one at a time, smallest first); these are the first scores, before
any tuning (`results/run4.json`). No Dedaub export was opened.

| Contract | Selectors | Names correct / unresolved / wrong | Wrong claims | Code lines | Uncertain / unstructured | Time | Peak |
| --- | --- | --- | --- | --- | --- | --- | --- |
| maker-vat (0.5.12, no optimizer) | 28/28 | 28 / 0 / 0 | 2 | 467 | 9 / 0 | 3.4 s | 0.07 GB |
| cow-gpv2-settlement (0.7.6) | 15/15 | 13 / 2 / 0 | 0 | 1,211 | 10 / 0 | 8.2 s | 0.14 GB |
| metamorpho-steakhouse-usdc (0.8.21 via-IR) | 73/73 | 48 / 25 / 0 | 2 | 3,568 | 640 / 1 | 328.0 s | 0.40 GB |
| euler-evc (0.8.24) | **failed**: native analysis error | | | | | 158.6 s | 12.43 GB |
| curve-stableswap-ng-usde-usdc (Vyper 0.3.10) | 61/61 | 38 / 23 / 0 | 2 | 65,269 | 231 / 7 | 528.5 s | 0.79 GB |
| uniswap-v4-position-manager (0.8.26 via-IR) | 39/39 | 25 / 14 / 0 | 2 | 2,570 | 11 / 0 | 22.4 s | 0.38 GB |
| curve-tricrypto2 (Vyper 0.2.12) | 62/62 | 57 / 5 / 0 | 2 | 2,232 | 40 / 18 | 5.8 s | 0.11 GB |
| uniswap-v3-swaprouter02 (0.7.6) | 39/39 | 33 / 6 / 0 | 0 | 2,177 | 4 / 0 | 11.2 s | 0.26 GB |

- 7 of 8 produced output; 317/317 selectors recovered, including all of both
  Vyper contracts (the 0.3.10 selector table, the 0.2.12 memory selector).
  242 names correct, 75 unresolved, none wrong.
- The Euler EVC failed in Gigahorse's IR export (`TAC_Use: non-contiguous
  operand indices at 0x13ba`), after 159 s at 12.4 GB; the relations are kept
  for diagnosis.

Wrong claims (10), by cause:

| Contract | Function | Claim | Cause |
| --- | --- | --- | --- |
| maker-vat | `debt()`, `vice()` | returns `int256` vs `uint256` (2) | The storage words are typed `int256` from the signed arithmetic the Vat applies to them (`add(uint, int)` helpers); the getters return that field type. The source declares `uint256`. |
| metamorpho | `acceptCap`, `submitMarketRemoval` | arity 5 vs 1 (2) | A `MarketParams memory` struct is the whole head, no dictionary name. via-IR decodes it at entry, so neither a struct check of its own nor late validation distinguishes it from five parameters. |
| stableswap-ng | `exchange_received` | arity 2 vs 4 | Only `i` and `j` are bound. The function's IR has no constant-offset loads of its third and fourth head words, and its body was not structured (region expansion limit), so their reads were not recovered. Vyper has no head-size check to count the head. |
| stableswap-ng | `last_price(uint256)` | returns `uint128` vs `uint256` | The returned value is masked to 128 bits (a packed price): the return-width case the bytecode cannot settle. The legend says the source may declare wider. |
| v4-position-manager | `getPoolAndPositionInfo` | returns 6 words vs `(PoolKey, uint256)` | A returned static struct is printed as its words; returned structs are not grouped. |
| v4-position-manager | `unlockCallback(bytes)` | returns `(uint256, uint256)` vs `bytes` | A returned `bytes` value is printed as the encoder's head words (offset and length). |
| tricrypto2 | `fee_calc(uint256[3])`, `calc_token_fee(uint256[3],uint256[3])` | arity 3 vs 1, 6 vs 2 (2) | Static array parameters without a dictionary name. Vyper checks nothing that marks them, and only hash-matched signatures group arrays. |

Readability, also first observations:

- **stableswap-ng is 65,269 code lines.** Three functions hold 43,000 of them
  (`remove_liquidity_one_coin` twice, 16,000 lines each, and
  `calc_withdraw_one_coin`). Vyper calls its internal functions through
  return-address jumps, and shared-region copying repeats `get_D`/`get_y_D`
  per call site, nested (96 loops in one function).
- **tricrypto2: 18 unstructured functions.** 18 of its functions' payability
  is unresolved for the same reason.
- **MetaMorpho: 640 uncertain lines**, mostly in one unstructured function.

## Return widths printed as words (phase 1 as written)

The goal was resumed with phase 1's text unchanged: 0 wrong claims on runs
1-3, and returned values narrowed below their declared type printed as
`uint256` with the proven width as a comment. The bytecode cannot tell a
narrow declared type from a wider one holding a narrow value (see "Structs
decoded by helper functions" above). So every narrow integer return now
prints as `uint256 /* uint128 */`, signed widths included (`uint256 /* int24 */`).
The legend says the source may declare that type or a wider one. Only the
header changes; the masks in the body stay, so execution is unchanged. The
held-out scorer reads the type before a comment.

| Runs 1-3 | Before | After |
| --- | --- | --- |
| Wrong claims | 3 | **0** |
| Functions with every return type exact | 437 | 424 |

- The three return widths (V3 `collect`, Balancer `getPoolTokenInfo`, Seaport
  `getOrderStatus`) are no longer wrong; Seaport's tuple is now exact.
- 14 functions whose narrow return type was right go from correct to
  unresolved: V3 pool 7, V3 position manager 2, Chainlink 2, Azuki, WBTC and
  wstETH 1 each. This lowers the "correct returns" count, which the gates
  forbid; it is the trade-off phase 1's text asks for, since the bytecode
  cannot settle the declared type.
- No other score changes, no code line changes
  (`results/runs1-2-return-widths.json`, `results/run3-return-widths.json`).
  Run 4's first scores (set 3) stay as recorded.
- Existing fixtures keep their length (8,953 code lines); only headers and the
  legend text change. 461 passed, 17 skipped; cross-check 1,079 agreeing.

## Vyper 0.2 internal calls

46 functions in the three Vyper 0.2 contracts were unstructured: Curve 3pool
(0.2.4) 13, stETH (0.2.8) 15 and tricrypto2 (0.2.12) 18. Each one was cut off
at its first internal call. Vyper 0.2 keeps an internal call's return address
in memory: the call pushes `pc + 6`, the callee stores it at its entry
(`mstore(slot, ra)`) and returns with `jump(mload(slot))`. Gigahorse follows
only stack values, so the return had no target and everything after the call
was dropped. The changes, all with evidence on two new compiled fixtures:

- **Returns through memory (native rule).** The call is already recognized
  (`PUSH1 6; PC; ADD` folds to the continuation). In a context where a callee's
  entry stored its incoming stack top at a constant slot, a return through
  `mload(slot)` goes to that address. The address must be a continuation
  pushed by a call into that entry. The address counts as a used label, so
  the later analyses keep the call a call. Function discovery uses it, so
  the callees print as private functions.
- **Stack loops (native facts, from `src/vyper_stack_loops.py`).** Vyper 0.2
  moves multi-word values through the stack in loops whose counter is in
  memory: a return pushes its result's words (any version), and a caller with
  more than 10 local variables saves its frame before the call and restores it
  after (0.2.4 to 0.2.12). A stack analysis cannot count the iterations, so it
  loses which word is where. The count is a constant, found by executing the
  block that sets the counter. Each loop is rewritten by the statement
  inserter: the same loads (or stores), in the same order, before the counter
  is set, and the loop's own load popped (or its own store made `MEM[a] =
  MEM[a]`). Memory is unchanged: the loop writes only its counter, which is
  outside the words moved.
  - Only loops of up to 36 words are rewritten. The inserter gives each
    insertion point 80 statement ids, and a 63-word frame (126 instructions)
    collided with the next, so the local stack analysis never ended (3pool
    timed out, then ran out of 16 GB). Larger frames also overflow the
    analysis' 70 stack slots. 3pool has four frames over 36 words (42, 50, 53
    and 63), which stay as they were.
- **A guard instead of wrong data flow.** After a loop of one or two blocks
  whose round trip changes the stack height (a stack loop that was not
  rewritten), no return through memory is resolved, neither from the callee
  nor to the caller's continuation. With the rewrite switched off, the
  fixture's tuple-returning functions fall back to explicit blocks instead of
  popping the caller's saved frame as their results, which is what the
  first version did.
- **Vyper's `if 0` wrapper.** Vyper 0.2 puts the internal functions behind
  `PUSH1 0; ISZERO; PUSH; JUMPI`, which always jumps. Following the dead
  fallthrough made the dispatcher reach every internal function (3pool's
  dispatcher grew to 2,724 lines, 929 of them unassociated PHIs). Only this
  exact form becomes a jump. The general rule Gigahorse disabled
  (undeployed code's immutable placeholders look constant) stays off. A
  first, wider version also matched solc's `new bytes(0)` (a constant
  length tested with `ISZERO`), which is sound but changed Router02's
  relations, so it was narrowed.
- **A render that did not finish.** `numeric.sources` followed every
  definition of a local with only a per-path `seen` set. That is exponential
  in chains of merge copies, and the newly structured 3pool functions have
  many: its render ran for over 15 minutes. It is now a fixpoint per function,
  computed once (5 s), with the same result: a source reached around a cycle
  is also reached on the path without it. Shifts of 256 bits or more count
  as no source.

Signed storage (Maker Vat, a separate cause from run 4): the native model
types a storage word `int256` when any alias of it meets a signed operation.
The Vat's `add(uint x, int y)` compares `y` signed, and the alias flow put
`debt` and `vice` with it. The view now declares a full-width word
`uint256` when it is compared unsigned (directly, through a local, or as a
private function's parameter), never reaches a signed operation or signed
cast (through calls to any depth), and is never written a signed value. The
declaration notes the native type. Only these two Vat fields and
SwapRouter02's `amountInCached` (private, now `uint256` as in the source)
change.

Results, every held-out contract re-analyzed natively
(`results/runs1-2-vyper-calls.json`, `results/run3-vyper-calls.json`,
`results/run4-vyper-calls.json`; set 3 is calibration since run 4):

| Contract | Unstructured | Uncertain lines | Payability correct | Returns correct | Code lines |
| --- | --- | --- | --- | --- | --- |
| Curve 3pool (0.2.4) | 13 -> 8 | 55 -> 24 | 26 -> 30 of 38 | 29 -> 31 | 2,380 -> 3,063 |
| Curve stETH (0.2.8) | 15 -> **0** | 60 -> 3 | 25 -> **39** of 39 | 23 -> 34 | 2,225 -> 1,721 |
| Curve tricrypto2 (0.2.12) | 18 -> **0** | 40 -> 3 | 44 -> **62** of 62 | 47 -> 57 | 2,232 -> 3,130 |
| Maker Vat | 0 | 9 | 28 of 28 | 26 -> 28 (2 wrong -> 0) | 467 |

- No new wrong claims. Runs 1-3 stay at 0. Set 3 goes from 10 to 7: the
  Vat's two by this work, stableswap-ng's `last_price` by the earlier
  return-width change (which also moves MetaMorpho's returns 59 -> 56 and the
  V4 position manager's 27 -> 25 to unresolved).
- 3pool and tricrypto2 are longer because the code after every internal call
  was missing before. 3pool keeps 8 unstructured functions, all around its
  four frames over 36 words.
- Every other contract's native relations are identical, apart from row
  order (MetaMorpho) and Balancer. Balancer's analysis has two outcomes
  across identical runs: the batch run found `0x1b0f` as a function (3,094
  code lines, same scores), and a second run gave the previous relations,
  which are recorded. This is in Gigahorse before this change, likely its
  choice-domain relations under parallel evaluation, and none of the new
  rules can apply to Balancer (no memory returns, stack loops or `if 0`).
- The Euler EVC still fails in Gigahorse's IR export, as in run 4.

Tests:

- `vyper-calls-v0216` (7 functions; one-word, tuple and no-result internal
  functions, nested, called twice from one function, from a loop, and
  returning from inside a `for` loop): all structured, 0 wrong claims, run
  against Py-EVM with each branch and revert.
- `vyper-frames-v0212` (Vyper 0.2.12, saved frames of 11 to 14 words, nested
  in an internal function): structured, run against Py-EVM. With the restore
  loop's stores in the wrong order, the native output fails this test.
- The loop finder on synthetic code: both counter forms, frame save and
  restore, and no loop when the count is unknown, not a word multiple, or the
  counter is among the words.
- Signed storage: a word compared unsigned is declared `uint256`, including
  through a helper's parameter, and signed reach through locals, casts and
  calls keeps `int256` (removing the parameter or cast handling fails the
  test). The value-source
  fixpoint over a 60-local chain of merge copies takes under a second.
- The 35 existing fixtures' native relations are unchanged and they render
  byte-identically (7,079 code lines as the scorer counts them); the two new
  fixtures add 567. 471 passed, 17 skipped; cross-check 1,079 agreeing.

Not done: the return address shows as the first argument of a Vyper 0.2
internal call (`fn_0x2ab(82, varg0)`, stored at the callee's entry). Hiding it
needs the store proven unread, and the memory liveness cannot prove that,
because callers keep their locals at the callee's addresses and restore them
after the call. The rewritten loops stay as empty loops (`while (MEM[a] > 0)
MEM[a] -= 32`). stableswap-ng (Vyper 0.3.10) is a different problem: its
internal functions are copied per call site (65,269 lines).

## Inlining cost limit and one-word returns

Curve stableswap-ng (Vyper 0.3.10) printed 65,269 code lines, three functions
holding 43,000 of them. Gigahorse found its 24 internal functions, but its
inliner then copied most of them into every call site: the pool math
(`get_D`, `get_y`, up to 653 statements, called 3 to 12 times) appeared once
per call, nested. Vyper passes array arguments and result buffers as memory
pointers, which the inliner's memory heuristics (written for solc's
allocation helpers) take as reasons to inline.

- **Inlining limit (native rule).** A function of at least 100 statements is
  not inlined when its copies would add more than 500 statements ((call sites
  - 1) x size). Its callers can still be inlined, and it does not ask for
  another inlining round. Small helpers called many times (solc's, 14 to 38
  statements at 46 to 57 sites) are still inlined.
- **One-word returns.** Without inlining, a public function often ends with
  `fn_0x4abb(0xb00); return MEM[0xb00:0xb20];`: the callee wrote the result
  through the pointer. A return of exactly 32 bytes is the word at that
  address, so it prints as `return MEM[0xb00];` with `returns (uint256)` (the
  raw-word default; the scorer counts it correct only when the ABI says
  `uint256`).

Results, every held-out contract re-analyzed natively
(`results/runs1-2-inlining.json`, `results/run3-inlining.json`,
`results/run4-inlining.json`), against the previous section's runs:

| Contract | Code lines | Uncertain lines | Other |
| --- | --- | --- | --- |
| Curve stableswap-ng | 65,269 -> **12,172** | 231 -> 113 | unstructured 7 -> 1; returns correct 28 -> 45 of 61; 509.8 s -> 66.1 s |
| Seaport 1.5 | 6,690 -> 4,544 | 22 -> 13 | |
| 1inch router | 7,099 -> 6,662 | 449 -> 409 | |
| ENS public resolver | 2,115 -> 1,574 | | |
| MetaMorpho | 3,568 -> 3,177 | | |
| Balancer vault | 3,313 -> 3,051 | | unaccounted IR statements 65 -> 56 (a second run reproduced it) |
| V4 pool manager | 2,941 -> 2,664 | 45 -> 29 | |
| V4 position manager | 2,570 -> 2,358 | 11 -> 12 | one call now prints its arguments, marked "ABI input length not verified" |
| Permit2 | 1,101 -> 825 | 7 -> 2 | |
| CoW settlement | 1,211 -> 1,115 | | |
| V3 pool | 1,820 -> 1,823 | | `getSurroundingObservations` and `binarySearch` are now functions, as in the source; the observations slot is their parameter, so its three packed fields lose their `stor_8_*` names |

- All held-out contracts: 116,474 -> 58,742 code lines, 1,520 -> 1,332
  uncertain lines. Every score count is the same or higher (returns correct
  674 -> 691), and wrong claims stay at 7. Recognized idioms and decoded
  events are unchanged. The other 16 contracts' native relations are
  identical.
- The inliner limit fires on more contracts than the call graph before
  inlining suggests (11, not 5): functions grow as their callees are inlined
  in earlier rounds.

Tests:

- New compiled fixture `InliningFixture` (solc 0.8.30): `_mix` reads calldata
  through its argument and is called seven times. With the previous inliner
  the optimized view printed it eight times (505 code lines, no private
  function); now once (177 lines). It runs against Py-EVM (30 cases), and the
  previous inliner's relations fail the test. In the via-IR variant solc
  inlines `_mix` itself.
- A first version of that fixture, passing a raw memory pointer in via-IR,
  fails in Gigahorse's IR export with the error that stops the Euler EVC
  (`TAC_Use: non-contiguous operand indices`): a small reproducer for later.
- The one-word return rule changes four fixture views (`return MEM[0];` with
  `returns (uint256)`), with the same line counts; the cross-check executes
  them. The 37 existing fixtures' native relations are unchanged. 475 passed,
  17 skipped; cross-check 1,079 agreeing.

## Operands the analysis did not recover (Euler EVC)

The Euler EVC (set 3) produced no output in run 4: loading Gigahorse's IR
stopped at `TAC_Use: non-contiguous operand indices`. One `DIV` had its divisor
but no dividend. The dividend is read with `DUP11`, deep in the caller's
stack (via-IR code does this), and that slot is not among the arguments
Gigahorse inferred for the function, so the IR has no value for it. A
compiled reproducer (a via-IR function writing through a raw memory pointer)
fails the same way.

Such an operand is now an unknown value: an unordered PHI with no inputs,
printed `v0 = phi(); // UNCERTAIN: value not recovered by the analysis`, with a
warning. This applies only when the operands still fit the opcode (two for
`DIV`); too many operands or a negative index still reject the relations,
as before.

The Euler EVC's first scores (`results/run4-missing-operands.json`; its
native relations are from the same run, nothing in between targeted it):
44/44 selectors, 2 names correct and 42 unresolved (the dictionary lacks
the EVC's functions), 0 wrong names, arity 44/44, payability 42 correct and 2
unresolved, returns 37 correct and 7 unresolved, **0 wrong claims**; 2,726
code lines, 114 uncertain, 5 unstructured functions, 3 unrecovered values.
Set 3 now produces output for all 8 contracts. No other contract's view
changes (none had such an operand). 476 passed, 17 skipped; cross-check
1,079 agreeing.
