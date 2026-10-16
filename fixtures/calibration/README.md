# Calibration fixtures from the held-out corpus

Contracts here were first analyzed as part of the held-out corpus
(`fixtures/evaluation-heldout/`, run 1 at code 0459594). Their results have since
informed changes, so they are calibration cases now, not held-out measurements.
The frozen relations let tests execute their decompiled views offline.

- `uniswap-v2-router02`: Uniswap V2 Router02 (solc 0.6.6), relations captured from
  the run-1 bundle (`snapshot.json` names it) with
  `scripts/capture-reconstruction-snapshot.py` and `scripts/capture-memory-links.py`.
  The manifest and runtime are copies of the held-out corpus files. The verified ABI
  stays in the held-out corpus as scoring ground truth and is not used by tests.
