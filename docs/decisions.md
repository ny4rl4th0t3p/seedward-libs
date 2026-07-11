# gentxvalidate — design decisions

Repo-internal decisions for `seedward-libs`. The cross-cutting ones — the single-gentx boundary
(ADR-0001) and WASM shipping (ADR-0002) — live in the suite ADR log; this file records choices that only
matter inside this repo. Distilled from the project's phase build history.

## Sign-bytes are hand-rolled, byte-faithful to an SDK oracle (2026-06-10)

DIRECT `SignDoc` and amino `StdSignDoc` sign bytes are reconstructed by hand (explicit proto / sorted
JSON encoding), never via cosmos-sdk. Byte-exactness was established during development by an **SDK
equivalence oracle** (a throwaway module — not committed — that reconstructs the same bytes via the real
cosmos-sdk and asserts byte-for-byte equality), and is enforced enduringly by the **committed mainnet
corpus** (osmosis-1 / juno-1 / stargaze-1 — every signature must verify and every address re-derive). The
SDK is only ever a test oracle, never a shipped dependency. Shipped tree: bech32, secp256k1, `x/crypto`
(ripemd160). The encoding sharp edges are in [sign-bytes-notes.md](sign-bytes-notes.md).

## `chain_id` is a sign-time input, not a light invariant (2026-06-10)

A gentx JSON carries no chain-id, so a parsed gentx can't structurally fail a chain-id check. It is
enforced *cryptographically*: `RunAll`'s signature check signs over `Params.ChainID`, so a gentx signed
for another chain fails there. `CheckChainID(claimed, params)` is still exported for coordd, whose request
envelope carries a claimed chain-id.

## Per-mode invariant IDs; no generic `signature` (2026-06-10)

`signature_direct` and `signature_amino_json` are distinct invariant IDs — a consumer sees exactly which
sign-mode path ran, rather than an opaque `signature` pass/fail.

## Single-`MsgCreateValidator` folded into `well_formed` (2026-06-10)

A gentx must carry exactly one `MsgCreateValidator`. `Decode` enforces it as part of `well_formed` rather
than a separate invariant ID — no consumer needs the distinction yet.

## Standard Go WASM; TinyGo deferred (2026-06-10)

The blob builds with the standard Go toolchain (~1.9 MB gz, under the 2 MB budget). TinyGo is a
*potential future size optimization only*, with recorded entry criteria (compile the reflection-free
path; prove corpus parity under TinyGo's runtime; ship TinyGo's own `wasm_exec.js` as a second artifact) —
not attempted until blob size becomes a real product complaint.

## Module path: `github.com/ny4rl4th0t3p/seedward-libs` (2026-06-10)

Kept the personal-handle path; not migrating to a vanity/org path until an org domain materializes and
external consumers exist.

## Account key must be secp256k1; ed25519 accounts rejected (2026-07-08)

The signing account key (`auth_info.signer_infos[0]` — the tx signer, distinct from the ed25519 consensus
key in the message) must be secp256k1. Cosmos account keys are almost always secp256k1, and the whole
mainnet corpus is; ed25519-account support (signature verify and address derivation) is not implemented —
a non-secp256k1 account returns a failed `operator_address` result rather than a guess. **Accepted**
because the failure mode is **false rejection, never false acceptance**: a rare ed25519-account validator
can't join, but nothing invalid slips through. Revisit only on demand from a chain that uses ed25519
accounts (tracked in the README "Possible next additions").