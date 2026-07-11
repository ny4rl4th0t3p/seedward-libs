# Sign-bytes reconstruction — encoding sharp edges

`gentxvalidate` verifies a gentx signature by **reconstructing the signer's sign bytes** and checking the
signature against them. The reconstruction must be **byte-identical** to what the signer's wallet
produced, or a valid signature fails. These are the non-obvious encoding rules — learned from real
mainnet gentxs and enforced by the **committed mainnet corpus** (a dev-time SDK equivalence oracle
established the byte-exactness originally; it is not part of the shipped repo).

> **Scope: gentx signatures only.** This documents the `gentxvalidate` **gentx** sign-byte reconstruction.
> The suite's *authentication* path (ADR-036 challenge signing, `BuildADR036AminoBytes`) is a separate
> amino reconstruction that lives in `seedward-chaincoord` — see suite **ADR-0011** for that wire contract.

## DIRECT (`SIGN_MODE_DIRECT` → protobuf `SignDoc`)

- **LegacyDec scaling.** Commission rates render as `"0.100000000000000000"` in JSON but wire-encode as
  the ×10¹⁸ integer string `"100000000000000000"` (no decimal point). Same for `max_rate` /
  `max_change_rate`. Wrong scaling is an invisible byte mismatch → signature fails.
- **proto3 default omission.** `timeout_height: "0"`, `extension_options: []`, `fee.amount: []`,
  `payer` / `granter`: `""`, `sequence: "0"` are defaults/empty and must be **omitted** from the wire
  bytes, not encoded as zero-length fields.
- **`Any` type-URLs** (`/cosmos.staking.v1beta1.MsgCreateValidator`, `/cosmos.crypto.ed25519.PubKey`,
  `/cosmos.crypto.secp256k1.PubKey`) encode verbatim as `Any.type_url`; the message/key bytes go in
  `Any.value`.
- **`SignDoc` field layout:** `body_bytes=1, auth_info_bytes=2, chain_id=3, account_number=4`.
  `account_number = 0` and `sequence = 0` for a gentx (the account doesn't exist at genesis). `chain_id`
  comes from `Params` (a sign-time input, not carried in the gentx).

## Keys & signatures

- **Two different keys.** The signature verifies against the **secp256k1** `public_key` in
  `auth_info.signer_infos[0]` (the *account* key). The ed25519 `pubkey` inside the message is the
  *consensus* key and does not sign the tx.
- **Wire formats.** The signature is **64 raw bytes, r‖s compact — not DER**; split into two 32-byte
  scalars. The account pubkey is **33-byte compressed** secp256k1.
- **Operator/delegator address** derives from the signing account: bech32 (`<prefix>valoper` /
  `<prefix>`) over `RIPEMD160(SHA256(secp256k1 pubkey))`.

## AMINO (`SIGN_MODE_LEGACY_AMINO_JSON` → `StdSignDoc`)

- Reconstructed with `encoding/json` over structs whose fields are declared in **alphabetical json-key
  order**, reproducing amino's `sortJSON` output (sorted keys, compact, HTML-escaped) byte-exactly — with
  **no amino dependency**.
- **Multisig** (`LegacyAminoPubKey`, k-of-n): the `mode_info.multi` compact bitarray selects which members
  signed; each component sig verifies against the same amino sign bytes; the threshold is checked. The
  multisig address is SHA256 over the legacy-amino binary encoding of the `LegacyAminoPubKey` (type prefix
  + threshold + per-member prefixed keys), truncated to 20 bytes.
- Legacy multisig is **AMINO-only**: DIRECT sign bytes cover the `multi` bitarray in `AuthInfo`, so a
  "DIRECT multisig" gentx cannot exist.

## Out of scope

Pre-protobuf `StdTx` gentxs (SDK < 0.40) are rejected with a clear error, not reconstructed.