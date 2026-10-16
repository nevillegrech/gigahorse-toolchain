# Second deployed-contract selection

`corpus.json` was frozen before bytecode import and frontend evaluation, against
implementation `e2b36ddfa0b6d2ce4f0ffc750ac3c66298234305e5a87ff74f2fe9ecef1ddd89`.
The address/chain, archived response hash, runtime hash, compiler, verified ABI
and signature ground truth are retained in each case's JSON. Native analysis
receives only the runtime hex; optional names use the preexisting independent
`PublicFunctionSignature.facts` dictionary, never these ABIs or sources.

WETH duplicates `tests/core-decompiler/WETH.hex`; it is regression coverage,
not an unseen native case. The other three hashes are absent from upstream
bytecodes and all four differ from the first corpus. No case was replaced.
After inspection these are calibration cases too, not an untouched holdout.

WETH, registry and NFT `.relations.json`/`.semantic.json` snapshots support offline
behavioral regression tests. NFT coverage is limited to early guards and admin
changes; successful mint/transfer/receiver execution remains untested. `.snapshot.json` binds them to native output and
runtime hashes. Evaluation ground truth does not feed those snapshots' loading.
Fresh baseline output is retained at `artifacts/evaluation-second-baseline/`;
current views and the explicit task-review record are described in EVALUATION.md.
Coverage counts alone do not establish behavioral correctness or Dedaub parity.
