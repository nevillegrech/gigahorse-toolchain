# Held-out corpus `heldout-2-2026-10-16`

Eight verified mainnet runtimes, chosen and committed on 2026-10-16 before any
of them was analyzed and before the memory-object and custom-error work began.
The earlier held-out contracts (`fixtures/evaluation-heldout/`) became
calibration once their Dedaub output was read, so improvements made on them say
nothing about other contracts; this set is for that.

| id | Compiler | Pipeline | Bytes |
| --- | --- | --- | --- |
| wbtc | solc 0.4.24 | legacy | 4,582 |
| wsteth | solc 0.6.12 | legacy | 6,492 |
| uniswap-v3-position-manager | solc 0.7.6 | legacy | 24,384 |
| balancer-v2-vault | solc 0.7.1 | legacy | 24,512 |
| ens-public-resolver | solc 0.8.17 | legacy | 12,336 |
| permit2 | solc 0.8.17 | via-IR | 9,152 |
| uniswap-v4-pool-manager | solc 0.8.26 | via-IR | 24,009 |
| curve-steth-pool | Vyper 0.2.8 | - | 15,735 |

Compiler, pipeline (`viaIR`) and sizes come from the Sourcify responses
(`<id>.json` records the response hash and retrieval time). None of the
runtimes equals another fixture's.

Rules:

- `<id>.abi.json` is scoring ground truth only; it is never given to the
  analysis or the readable view.
- These contracts are not analyzed until the current work is finished. Then
  each runs once natively (`scripts/evaluate-heldout.py`), and its first score
  is recorded before anything is tuned on it.
- Same-bytecode Dedaub exports for them are requested from the user only after
  those first scores are recorded.
