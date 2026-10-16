# Same-bytecode Dedaub exports: held-out corpus `heldout-2026-10-16`

Dedaub's output for the twelve mainnet contracts in
`fixtures/evaluation-heldout/corpus.json`, saved by the user from Dedaub's
standard decompiler (not an AI-rewritten view). One file per contract, named
`<id>.sol.txt` after the corpus `id`, kept verbatim with Dedaub's header (date,
compiler). Dedaub requests from this machine are blocked, so these files are
the only Dedaub reference.

The proxies (`aave-v3-pool-proxy`, `chainlink-eth-usd-proxy`) are decompiled at
the proxy address itself, not at the implementation. The address links each
export to `fixtures/evaluation-heldout/<id>.hex`; the code at these addresses
cannot change.

Not yet analyzed (true held-out): `uniswap-v3-pool-usdc-weth`, `azuki-erc721a`,
`aave-v3-pool-proxy`, `ens-eth-registrar-controller`, `oneinch-router-v5`,
`seaport-1-5`, `curve-3pool`. Do not open these seven exports before the
contract's first local result is scored and recorded, so that Dedaub's output
cannot influence it.

Already analyzed (calibration since run 1): `tether-usdt`, `dai`,
`compound-ceth`, `uniswap-v2-router02`, `chainlink-eth-usd-proxy`.
