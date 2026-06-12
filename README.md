# seedward-libs

Shared libraries for Seedward — coordination tooling for launching new Cosmos SDK networks. This module is the
dependency-graph leaf: it imports nothing internal, and the Seedward server, CLI, and web app import from it.

## gentxvalidate

Validates a **single Cosmos SDK gentx** against a launch's declared
parameters. Every correctness invariant is an individually callable pure
function returning a structured `Result`; runners compose them. Invariants
never panic — malformed input is a failed result.

```go
raw, _ := os.ReadFile("gentx.json")

results := gentxvalidate.RunAll(raw, gentxvalidate.Params{
ChainID:           "osmosis-1",
BondDenom:         "uosmo",
Bech32Prefix:      "osmo",
MinSelfDelegation: "1",
MinCommissionRate: "0.050000000000000000",
})
for _, r := range results {
fmt.Printf("%s ok=%v %s\n", r.Invariant, r.OK, r.Reason)
}
```

**Invariants** (each also callable on its own): well-formedness, bond denom,
self-delegation floor, commission internal consistency and launch bounds,
moniker rules, operator/delegator address derivation from the signing account,
and full signature verification by sign-bytes reconstruction.

**Sign modes**: `SIGN_MODE_DIRECT` (protobuf `SignDoc`) and
`SIGN_MODE_LEGACY_AMINO_JSON` (`StdSignDoc`), including `LegacyAminoPubKey`
k-of-n multisigs (compact bitarray + `MultiSignature` envelope + threshold).
Sign-bytes reconstruction is hand-rolled and dependency-light: the module's
entire dependency tree is bech32, secp256k1, and `x/crypto`.

**Runners**: `RunAll` (server-grade, includes signature verification) and
`RunLight` (advisory subset for instant client-side feedback).

Pre-protobuf legacy `StdTx` gentxs (SDK < 0.40) are explicitly out of scope
and rejected with a clear error.

### Install

```sh
go get github.com/ny4rl4th0t3p/seedward-libs/gentxvalidate
```

### How it's tested

Unit tests prove behavior; **real mainnet gentxs prove bytes**. The test
corpus is the complete genesis of three chains (osmosis-1, juno-1,
stargaze-1) — every signature must verify and every address must re-derive,
which is only possible if the sign-bytes and address reconstruction are
byte-identical to what the validators' wallets produced in 2021. See
[`gentxvalidate/testdata/README.md`](gentxvalidate/testdata/README.md).

## WASM build

The same validator compiles to a browser blob (~1.9 MB gzipped, 2 MB budget
enforced in CI) exposing `seedwardRunLight(gentxJSON, paramsJSON)` and
`seedwardRunAll(gentxJSON, paramsJSON)` on `globalThis`. Tagged releases
(`v*`) attach the blob and its matching `wasm_exec.js` as release assets.

```sh
make wasm        # build web/demo/gentxvalidate.wasm
make test-wasm   # run the full test suite inside the WASM runtime (needs Node)
```

A minimal demo lives in [`web/demo/`](web/demo/) — build, serve the directory
with any static file server, paste a gentx.

## Development

```sh
make help        # annotated target list
make check       # lint + test (default target)
make cover       # coverage summary
make wasm-size   # build the blob and enforce the size budget
```

CI runs lint, native tests, WASM-runtime parity tests, and the blob size gate
on every PR (plus manual dispatch via the Actions tab).

## License

Apache-2.0.