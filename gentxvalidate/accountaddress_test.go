package gentxvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccountAddress: the account address derives from the gentx signer, encodes to bech32 under
// the given HRP, and round-trips back to the same 20-byte payload the derivation produced.
func TestAccountAddress(t *testing.T) {
	pub := make([]byte, compressedPubKeyLen)
	pub[0] = 0x02 // valid compressed-key prefix; the rest is arbitrary for address derivation
	g := &ParsedGentx{Signer: SignerInfo{PubKeyTypeURL: secp256k1PubKeyTypeURL, PubKey: pub}}

	addr, err := g.AccountAddress("cosmos")
	require.NoError(t, err)

	got, err := decodeBech32Address(addr, "cosmos")
	require.NoError(t, err, "decode %q", addr)
	assert.Equal(t, accountAddressBytes(pub), got, "address bytes mismatch")
}

// TestAccountAddressUnsupportedKey: an unsupported account key type is an error, not a panic.
func TestAccountAddressUnsupportedKey(t *testing.T) {
	g := &ParsedGentx{Signer: SignerInfo{PubKeyTypeURL: "/not.a.real.Key", PubKey: make([]byte, compressedPubKeyLen)}}
	_, err := g.AccountAddress("cosmos")
	assert.Error(t, err, "expected error for unsupported account key type")
}
