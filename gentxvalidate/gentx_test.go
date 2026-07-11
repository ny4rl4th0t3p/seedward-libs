package gentxvalidate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture is a real osmosis-1 mainnet gentx. Its signature is the
// strongest possible oracle: VerifyDirect can only return true if the
// reconstructed sign bytes are byte-identical to what the validator's wallet
// signed.
const (
	fixtureChainID = "osmosis-1"
	fixtureAccNum  = 0
)

func loadFixture(t *testing.T) *ParsedGentx {
	t.Helper()
	return loadFixtureNamed(t, "gentx-Bi23Labs.json")
}

func loadFixtureNamed(t *testing.T, name string) *ParsedGentx {
	t.Helper()
	g, err := Decode(readFixtureBytes(t, name))
	require.NoError(t, err, "decode fixture")
	return g
}

// readFixtureBytes reads a named fixture from the osmosis-1 corpus, which is
// where all individually-pinned fixtures live (they are corpus members).
func readFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "osmosis-1-gentx", name))
	require.NoError(t, err, "read fixture")
	return data
}

func TestDecodeFields(t *testing.T) {
	g := loadFixture(t)

	assert.Equal(t, "Bi23 Labs", g.Msg.Description.Moniker)
	assert.Empty(t, g.Msg.Description.SecurityContact, "security_contact should be empty")
	assert.Equal(t, "0.100000000000000000", g.Msg.Commission.Rate)
	assert.Equal(t, "uosmo", g.Msg.Value.Denom)
	assert.Equal(t, "1000000", g.Msg.Value.Amount)
	assert.Zero(t, g.TimeoutHeight)
	assert.Equal(t, "SIGN_MODE_DIRECT", g.Signer.Mode)
	assert.Zero(t, g.Signer.Sequence)
	assert.Len(t, g.Signer.PubKey, 33, "account pubkey, want 33 (compressed)")
	assert.Len(t, g.Msg.ConsensusPubKey, 32, "consensus pubkey, want 32 (ed25519)")
	assert.Len(t, g.Signature, 64, "signature, want 64 (r||s)")
	assert.Equal(t, uint64(200000), g.Fee.GasLimit)
}

func TestVerifyMainnetSignature(t *testing.T) {
	g := loadFixture(t)

	ok, err := VerifyDirect(g, fixtureChainID, fixtureAccNum)
	require.NoError(t, err)
	require.True(t, ok, "mainnet signature did not verify — sign-bytes reconstruction is not byte-exact")
}

func TestVerifyRejectsTamper(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(g *ParsedGentx)
		chainID string
	}{
		{"wrong chain-id", func(*ParsedGentx) {}, "osmosis-2"},
		{"tampered memo", func(g *ParsedGentx) { g.Memo += "x" }, fixtureChainID},
		{"tampered moniker", func(g *ParsedGentx) { g.Msg.Description.Moniker = "Evil Labs" }, fixtureChainID},
		{"tampered amount", func(g *ParsedGentx) { g.Msg.Value.Amount = "2000000" }, fixtureChainID},
		{"tampered commission", func(g *ParsedGentx) { g.Msg.Commission.Rate = "0.200000000000000000" }, fixtureChainID},
		{"tampered signature", func(g *ParsedGentx) { g.Signature[0] ^= 0x01 }, fixtureChainID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixture(t)
			tc.mutate(g)
			ok, err := VerifyDirect(g, tc.chainID, fixtureAccNum)
			require.NoError(t, err)
			require.False(t, ok, "tampered gentx verified — verification is not sound")
		})
	}
}

// TestVerifyDirectErrors: inputs that cannot be processed at all return an
// error — distinct from a well-formed signature that simply doesn't verify.
func TestVerifyDirectErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(g *ParsedGentx)
	}{
		{"unsupported key type", func(g *ParsedGentx) { g.Signer.PubKeyTypeURL = "/cosmos.crypto.ed25519.PubKey" }},
		{"truncated pubkey", func(g *ParsedGentx) { g.Signer.PubKey = g.Signer.PubKey[:32] }},
		{"undecodable pubkey", func(g *ParsedGentx) { g.Signer.PubKey[0] = 0x05 }}, // not a valid compressed-point prefix
		{"truncated signature", func(g *ParsedGentx) { g.Signature = g.Signature[:63] }},
		{"unsupported sign mode", func(g *ParsedGentx) { g.Signer.Mode = "SIGN_MODE_LEGACY_AMINO_JSON" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixture(t)
			tc.mutate(g)
			_, err := VerifyDirect(g, fixtureChainID, fixtureAccNum)
			require.Error(t, err, "expected error")
		})
	}
}

// TestVerifyDirectScalarOverflow: an r or s at/above the curve group order is
// not a processing error — it is simply not a valid signature (false, nil).
func TestVerifyDirectScalarOverflow(t *testing.T) {
	halves := []struct {
		name string
		off  int
	}{
		{"r overflow", 0},
		{"s overflow", 32},
	}

	for _, h := range halves {
		t.Run(h.name, func(t *testing.T) {
			g := loadFixture(t)
			for i := h.off; i < h.off+32; i++ {
				g.Signature[i] = 0xFF
			}
			ok, err := VerifyDirect(g, fixtureChainID, fixtureAccNum)
			require.NoError(t, err, "overflow scalar must not be a processing error")
			assert.False(t, ok, "overflow scalar verified")
		})
	}
}

func TestDirectSignBytesDeterministic(t *testing.T) {
	g := loadFixture(t)

	first, err := DirectSignBytes(g, fixtureChainID, fixtureAccNum)
	require.NoError(t, err)
	for i := range 100 {
		got, err := DirectSignBytes(g, fixtureChainID, fixtureAccNum)
		require.NoError(t, err)
		require.Equal(t, first, got, "non-deterministic sign bytes on iteration %d", i)
	}
}

func TestLegacyDecWire(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0.100000000000000000", "100000000000000000"},
		{"1.000000000000000000", "1000000000000000000"},
		{"0.050000000000000000", "50000000000000000"},
		{"0.000000000000000000", "0"},
		{"0", "0"},
		{"1", "1000000000000000000"},
		{"0.2", "200000000000000000"},
	}
	for _, tc := range cases {
		got, err := legacyDecWire(tc.in, "test")
		require.NoError(t, err, "legacyDecWire(%q)", tc.in)
		assert.Equal(t, tc.want, string(got), "legacyDecWire(%q)", tc.in)
	}

	for _, bad := range []string{"", ".", "1.2.3", "-0.1", "0.1234567890123456789", "abc"} {
		_, err := legacyDecWire(bad, "test")
		assert.Error(t, err, "legacyDecWire(%q): expected error", bad)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"not JSON", `{`},
		{"no messages", `{"body":{"messages":[]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"two signatures", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA==","AA=="]}`},
		{"wrong message type", `{"body":{"messages":[{"@type":"/cosmos.bank.v1beta1.MsgSend"}]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"no signer_infos", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[],"fee":{}},"signatures":["AA=="]}`},
		{"extension options", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}],"extension_options":[{}]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"message not an object", `{"body":{"messages":[123]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"bad consensus pubkey base64", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator","pubkey":{"key":"!!!"}}]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"bad account pubkey base64", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"public_key":{"key":"!!!"}}],"fee":{}},"signatures":["AA=="]}`},
		{"bad sequence", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"sequence":"x"}],"fee":{}},"signatures":["AA=="]}`},
		{"bad signature base64", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["!!!"]}`},
		{"bad timeout_height", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}],"timeout_height":"x"},"auth_info":{"signer_infos":[{}],"fee":{}},"signatures":["AA=="]}`},
		{"bad gas_limit", `{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{}],"fee":{"gas_limit":"x"}},"signatures":["AA=="]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.json))
			require.Error(t, err, "expected error")
		})
	}
}
