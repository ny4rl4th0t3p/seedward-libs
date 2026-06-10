package gentxvalidate

import (
	"testing"

	"github.com/cosmos/btcutil/bech32"
)

// TestDecodeBech32AddressPayloadLength: a valid bech32 string under the right
// HRP must still be rejected when its payload is not the 20-byte account
// address length.
func TestDecodeBech32AddressPayloadLength(t *testing.T) {
	data5, err := bech32.ConvertBits(make([]byte, accountAddrLen+1), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := bech32.Encode("osmo", data5)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeBech32Address(addr, "osmo"); err == nil {
		t.Error("21-byte payload decoded without error")
	}
}
