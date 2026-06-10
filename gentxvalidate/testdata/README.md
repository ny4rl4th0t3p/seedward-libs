# Test fixtures — real mainnet gentxs

Every file here is a **real, signed gentx from a chain's genesis**, used as an
external oracle: signature verification and address derivation can only pass
if the library's sign-bytes reconstruction and address encoding are
byte-identical to what the validators' wallets produced. Unit tests prove
behavior; these files prove *bytes*.

**Do not modify, reformat, or pretty-print these files.** Any byte change
breaks their value as oracles (and most edits would simply make their
signatures fail).

## Corpora

| Directory            | Chain                        | Role                                                                                                                                         | Source                             |
|----------------------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `osmosis-1-gentx/`   | osmosis-1 (Jun 2021)         | full validation corpus: 26 DIRECT, 11 amino, one 2-of-2 multisig (`gentx-Stargaze.json`), one sparse 2-of-3 multisig (`gentx-iqlusion.json`) | github.com/osmosis-labs/networks   |
| `juno-1-gentx/`      | juno-1 (Oct 2021)            | full validation corpus, second chain (HRP `juno`, denom `ujuno`)                                                                             | github.com/CosmosContracts/mainnet |
| `stargaze-1-gentx/`  | stargaze-1 (Oct 2021)        | full validation corpus, third chain (HRP `stars`, denom `ustars`)                                                                            | github.com/public-awesome/mainnet  |
| `cosmoshub-4-gentx/` | cosmos hub (2019 launch era) | **rejection corpus**: legacy pre-protobuf StdTx JSON, out of scope by decision (spec §1) — every file must fail `well_formed` cleanly        | github.com/cosmos/mainnet          |

Retrieved 2026-06-10 from the chains' public launch repositories. The data is
public chain history: public keys, signatures, addresses, and validator
descriptions as published at genesis.

## Named fixtures

Tests that pin a specific behavior load individual files from
`osmosis-1-gentx/` via `loadFixtureNamed`:

- `gentx-Bi23Labs.json` — single-key `SIGN_MODE_DIRECT` (the Phase 0 oracle)
- `gentx-staker_space.json` — single-key `SIGN_MODE_LEGACY_AMINO_JSON`
- `gentx-Stargaze.json` — 2-of-2 `LegacyAminoPubKey` multisig, amino
- `gentx-iqlusion.json` — 2-of-3 multisig, sparse bitarray (member 1 unsigned)

Adding a new chain corpus: drop the directory here and add one entry to
`chainCorpora` in `corpus_test.go` with the launch's chain-id, bond denom, and
bech32 prefix.