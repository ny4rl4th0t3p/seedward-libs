package gentxvalidate

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,gosec // required: Cosmos secp256k1 addresses are RIPEMD160(SHA256(pubkey))

	"github.com/cosmos/btcutil/bech32"
)

const accountAddrLen = 20 // RIPEMD160 digest size

// signerAddressBytes derives the signing account's 20-byte address:
// RIPEMD160(SHA256(pubkey)) for single secp256k1 keys, SHA256 truncated over
// the amino-encoded LegacyAminoPubKey for multisigs.
func signerAddressBytes(s *SignerInfo) ([]byte, error) {
	if s.Multisig != nil {
		return multisigAddressBytes(s.Multisig)
	}
	if s.PubKeyTypeURL != secp256k1PubKeyTypeURL {
		return nil, fmt.Errorf("unsupported account key type %q", s.PubKeyTypeURL)
	}
	if len(s.PubKey) != compressedPubKeyLen {
		return nil, fmt.Errorf("account pubkey is %d bytes, want %d (compressed)", len(s.PubKey), compressedPubKeyLen)
	}
	return accountAddressBytes(s.PubKey), nil
}

// accountAddressBytes derives the 20-byte Cosmos account address from a
// 33-byte compressed secp256k1 pubkey: RIPEMD160(SHA256(pubkey)).
func accountAddressBytes(compressedPubKey []byte) []byte {
	sha := sha256.Sum256(compressedPubKey)
	h := ripemd160.New() //nolint:gosec // not a security boundary: address derivation mandated by the Cosmos spec
	h.Write(sha[:])
	return h.Sum(nil)
}

// encodeBech32Address encodes a 20-byte address payload as bech32 with the given HRP.
func encodeBech32Address(hrp string, payload []byte) (string, error) {
	data5, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("convert bits: %w", err)
	}
	addr, err := bech32.Encode(hrp, data5)
	if err != nil {
		return "", fmt.Errorf("bech32 encode: %w", err)
	}
	return addr, nil
}

// AccountAddress returns the validator's self-delegation account address: the gentx's signing
// account, bech32-encoded with hrp. It is the account form of the verified validator_address — the
// same key bytes without the "valoper" suffix — and is the genesis-relevant validator identity (the
// self-delegator). The address is derived from the gentx signer, so it is only meaningful once the
// operator-address invariant has passed (RunAll + AllOK, which proves validator_address derives from
// this same account).
func (g *ParsedGentx) AccountAddress(hrp string) (string, error) {
	b, err := signerAddressBytes(&g.Signer)
	if err != nil {
		return "", err
	}
	return encodeBech32Address(hrp, b)
}

// decodeBech32Address decodes addr, requiring the given HRP and a 20-byte
// payload.
func decodeBech32Address(addr, wantHRP string) ([]byte, error) {
	hrp, data5, err := bech32.Decode(addr, 1023)
	if err != nil {
		return nil, fmt.Errorf("invalid bech32: %w", err)
	}
	if hrp != wantHRP {
		return nil, fmt.Errorf("HRP %q, want %q", hrp, wantHRP)
	}
	payload, err := bech32.ConvertBits(data5, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("invalid bech32 payload: %w", err)
	}
	if len(payload) != accountAddrLen {
		return nil, fmt.Errorf("address payload is %d bytes, want %d", len(payload), accountAddrLen)
	}
	return payload, nil
}
