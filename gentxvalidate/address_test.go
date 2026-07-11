package gentxvalidate

import (
	"testing"

	"github.com/cosmos/btcutil/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeBech32AddressPayloadLength: a valid bech32 string under the right
// HRP must still be rejected when its payload is not the 20-byte account
// address length.
func TestDecodeBech32AddressPayloadLength(t *testing.T) {
	data5, err := bech32.ConvertBits(make([]byte, accountAddrLen+1), 8, 5, true)
	require.NoError(t, err)
	addr, err := bech32.Encode("osmo", data5)
	require.NoError(t, err)

	_, err = decodeBech32Address(addr, "osmo")
	assert.Error(t, err, "21-byte payload decoded without error")
}
