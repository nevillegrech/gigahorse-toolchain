# Same-bytecode Dedaub reference: Morpho liquidator

- `runtime.hex`: deployed runtime bytecode, 5,954 bytes,
  SHA-256 `e37d8859c56c25ed9c50824373531d7cd8c528c65ed80f72ec24c352f6ffe1f2`.
  CBOR metadata reports solc 0.8.34 (PUSH0 and MCOPY present).
- `dedaub.sol.txt`: Dedaub output for these bytes, as supplied by the user on
  2026-10-16 (header: "Decompiled by library.dedaub.com 2026.10.15 20:24 UTC").
  Kept verbatim, including Dedaub's own artifacts such as `v4a4V0x8a.length`.

Source code and ABI are not available for this contract. Dedaub's function names
(`sweep`, `onMorphoFlashLoan`, `MORPHO`, `idToMarketParams`, `liquidate`,
`flashLoan`) come from its signature database; `0x441c1495` was unresolved there.

This is the first same-bytecode comparison pair. It was supplied after the
readability work began, so it is a calibration case, not a held-out test.
