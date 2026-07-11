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

The signing **account key** (`auth_info.signer_infos[0]` — the tx signer, distinct from the ed25519
*consensus* key in the message) must be **secp256k1**, the standard for Cosmos accounts. A gentx signed
by an ed25519 account is rejected (`operator_address` fails). This is a deliberate, safe limitation — the
failure mode is rejection, never false acceptance. See [Possible next additions](#possible-next-additions).

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

The decoder is additionally **fuzzed** (`FuzzDecode`, seeded from that corpus)
to prove it never panics on hostile input — malformed bytes always surface as
an error. A plain `go test` replays the seed corpus; `go test -fuzz=FuzzDecode`
runs active mutation.

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

## canonicaljson

Deterministic JSON serialization for **signatures** — the bytes a signer signs must be reproducible
byte-for-byte by the verifier. coordd and the rehearsal service both depend on it (coordd signs/verifies
coordinator actions and the audit log; rehearsal signs result facts that coordd verifies), so its rules
are a shared contract across the suite.

Rules: keys sorted lexicographically at every level, no whitespace, UTF-8, numbers without trailing
zeros, timestamps as RFC 3339 UTC at second precision.

- `Marshal(v)` — canonical JSON of any JSON-serialisable value.
- `MarshalForSigning(v)` — the signing form: strips the top-level `signature` and `pubkey_b64` (not part
  of the signed content) but **keeps `nonce`**, binding replay protection into the signature so a captured
  request cannot be replayed with a fresh nonce.

```sh
go get github.com/ny4rl4th0t3p/seedward-libs/canonicaljson
```

## Development

```sh
make help        # annotated target list
make check       # lint + test (default target)
make cover       # coverage summary
make wasm-size   # build the blob and enforce the size budget
```

CI runs lint, native tests, WASM-runtime parity tests, and the blob size gate
on every PR (plus manual dispatch via the Actions tab).

## Possible next additions

Deferred by design — pulled in only when a consumer or a target chain actually needs them:

- **ed25519-account signature verification + address derivation** — support gentxs whose *account* key
  (the tx signer, not the consensus key) is ed25519. Currently rejected (safe: false-rejection-only). Add
  **on demand from a chain that uses ed25519 accounts** — needs an ed25519-account fixture.
- **`SIGN_MODE_TEXTUAL`** — a third sign mode; registers behind the existing sign-mode verifier interface.
- **TinyGo WASM build** — a sub-MB blob (standard Go is ~1.9 MB gz, under budget). Optimization only, with
  recorded entry criteria (compile the reflection-free path, prove corpus parity, ship TinyGo's own
  `wasm_exec.js` as a second artifact).
- **Per-launch `MsgCreateValidator` wrappers** — chain-specific validator-message overrides.

## Versioning

This module follows [Semantic Versioning](https://semver.org). From **v1.0.0** the exported API of
`gentxvalidate` and `canonicaljson` — including the WASM exports `seedwardRunLight` / `seedwardRunAll` —
is stable: it will not break without a major-version bump. Bug fixes and additive, backward-compatible
changes ship as minor/patch releases.

**`canonicaljson`'s output is part of the contract.** Its bytes are a signing surface — signers and
verifiers reproduce them byte-for-byte — so any change to the canonical encoding (key order, number
formatting, timestamp precision, escaping) is a **breaking change** requiring a major bump, even when the
Go API is untouched. Adding fields to *your own* signed payloads is fine; changing how existing values
serialize is not.

Pin an exact tag — or a commit SHA for the strongest supply-chain guarantee. Pre-`v1.0.0` tags predate
this stability commitment. Tagged releases (`v*`) also attach the WASM blob and its matching
`wasm_exec.js` as assets.

## License

Apache-2.0.