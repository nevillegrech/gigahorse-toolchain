# Held-out corpus `heldout-3-2026-10-16`

Eight verified mainnet runtimes, chosen and committed on 2026-10-16 before any
of them was analyzed and before the work on helper-decoded struct parameters,
Vyper dispatch and unstructured functions began. Runs 1-3
(`fixtures/evaluation-heldout/`, `fixtures/evaluation-heldout-2/`) are
calibration now: fixes have been made while looking at them, so only this set
measures how that work carries over.

| id | Compiler | Pipeline | Bytes |
| --- | --- | --- | --- |
| curve-stableswap-ng-usde-usdc | Vyper 0.3.10 | - | 23,509 |
| curve-tricrypto2 | Vyper 0.2.12 | - | 24,427 |
| uniswap-v4-position-manager | solc 0.8.26 | via-IR | 23,877 |
| metamorpho-steakhouse-usdc | solc 0.8.21 | via-IR | 19,340 |
| uniswap-v3-swaprouter02 | solc 0.7.6 | legacy | 24,497 |
| cow-gpv2-settlement | solc 0.7.6 | legacy | 16,165 |
| maker-vat | solc 0.5.12 | legacy, no optimizer | 13,493 |
| euler-evc | solc 0.8.24 | legacy | 21,989 |

Compiler, pipeline (`viaIR`), optimizer and sizes come from the Sourcify
responses (`<id>.json` records the response hash and retrieval time; fetched
with `scripts/fetch-heldout-corpus.py`). None of the runtimes equals another
fixture's, and none of the contracts is in an earlier set. Two are Vyper (one
with the 0.3.10 selector table, one with linear dispatch), two via-IR, and
five take struct or struct-array calldata parameters (V4 position manager,
MetaMorpho, SwapRouter02, CoW settlement, EVC).

Rules:

- `<id>.abi.json` is scoring ground truth only; it is never given to the
  analysis or the readable view.
- Not analyzed until the current work is finished. Then each runs once
  natively (`scripts/evaluate-heldout.py`, one at a time, memory-capped), and
  its first score is recorded before anything is tuned on it.
- Same-bytecode Dedaub exports may be saved by the user at any time, but they
  are not opened until those first scores are recorded.
