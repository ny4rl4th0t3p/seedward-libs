package gentxvalidate

import (
	"bytes"
	"testing"
)

// TestAccountAddress: the account address derives from the gentx signer, encodes to bech32 under
// the given HRP, and round-trips back to the same 20-byte payload the derivation produced.
func TestAccountAddress(t *testing.T) {
	pub := make([]byte, compressedPubKeyLen)
	pub[0] = 0x02 // valid compressed-key prefix; the rest is arbitrary for address derivation
	g := &ParsedGentx{Signer: SignerInfo{PubKeyTypeURL: secp256k1PubKeyTypeURL, PubKey: pub}}

	addr, err := g.AccountAddress("cosmos")
	if err != nil {
		t.Fatalf("AccountAddress: %v", err)
	}

	got, err := decodeBech32Address(addr, "cosmos")
	if err != nil {
		t.Fatalf("decode %q: %v", addr, err)
	}
	if want := accountAddressBytes(pub); !bytes.Equal(got, want) {
		t.Errorf("address bytes mismatch:\n got:  %x\n want: %x", got, want)
	}
}

// TestAccountAddressUnsupportedKey: an unsupported account key type is an error, not a panic.
func TestAccountAddressUnsupportedKey(t *testing.T) {
	g := &ParsedGentx{Signer: SignerInfo{PubKeyTypeURL: "/not.a.real.Key", PubKey: make([]byte, compressedPubKeyLen)}}
	if _, err := g.AccountAddress("cosmos"); err == nil {
		t.Error("expected error for unsupported account key type, got nil")
	}
}
