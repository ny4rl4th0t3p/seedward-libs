package gentxvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture is a real osmosis-1 mainnet gentx signed by a 2-of-2
// LegacyAminoPubKey multisig in amino mode. It verifies only if the StdSignDoc
// bytes are byte-exact (proven independently by the single-sig amino fixture)
// AND the MultiSignature envelope, bitarray, and threshold logic are right.
const multisigFixtureName = "gentx-Stargaze.json"

// TestMultisigOperatorAddress: the fixture's own bech32 addresses are the
// oracle — the SDK derived them from this exact multisig pubkey, so the check
// passes only if our amino-encoded SHA256 derivation is byte-exact.
func TestMultisigOperatorAddress(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	r := CheckOperatorAddress(g, osmosisParams())
	require.True(t, r.OK, "operator_address failed: %s", r.Reason)
}

// TestRunAllMultisigFullPass: with address derivation in place, the multisig
// fixture passes the complete invariant set — no asterisks.
func TestRunAllMultisigFullPass(t *testing.T) {
	raw := readFixtureBytes(t, multisigFixtureName)

	results := RunAll(raw, osmosisParams())
	for _, r := range results {
		assert.True(t, r.OK, "%s failed: %s", r.Invariant, r.Reason)
	}
}

func TestMultisigAddressErrors(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)
	g.Signer.Multisig.Members[0].PubKeyTypeURL = "/cosmos.crypto.sr25519.PubKey"

	r := CheckOperatorAddress(g, osmosisParams())
	assert.False(t, r.OK, "unknown member key type passed operator_address")
}

func TestMultisigDecode(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	ms := g.Signer.Multisig
	require.NotNil(t, ms, "Signer.Multisig is nil")
	assert.Equal(t, legacyAminoPubKeyTypeURL, g.Signer.PubKeyTypeURL)
	assert.Equal(t, "SIGN_MODE_LEGACY_AMINO_JSON", g.Signer.Mode)
	assert.Equal(t, uint32(2), ms.Threshold)
	assert.Len(t, ms.Members, 2)
	assert.Len(t, ms.Modes, 2)
	for i, m := range ms.Members {
		assert.Equal(t, secp256k1PubKeyTypeURL, m.PubKeyTypeURL, "member %d key type", i)
		assert.Len(t, m.PubKey, 33, "member %d pubkey length", i)
	}
	assert.Equal(t, 2, ms.bitCount())
	assert.Equal(t, []int{0, 1}, ms.signerIndices())
}

func TestVerifyMultisigMainnetSignature(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	ok, err := VerifyAminoJSON(g, fixtureChainID, fixtureAccNum)
	require.NoError(t, err)
	require.True(t, ok, "mainnet multisig signature did not verify")
}

func TestCheckSignatureMultisig(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	r := CheckSignature(g, osmosisParams())
	assert.Equal(t, InvSignatureAminoJSON, r.Invariant) //nolint:testifylint // invariant ID constant, not encoded JSON
	assert.True(t, r.OK, "valid multisig fixture failed: %s", r.Reason)
}

func TestVerifyMultisigRejectsTamper(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(g *ParsedGentx)
		chainID string
	}{
		{"wrong chain-id", func(*ParsedGentx) {}, "osmosis-2"},
		{"tampered moniker", func(g *ParsedGentx) { g.Msg.Description.Moniker = "Evil Labs" }, fixtureChainID},
		{"tampered amount", func(g *ParsedGentx) { g.Msg.Value.Amount = "1" }, fixtureChainID},
		// offset 5 lands inside the first component signature's bytes
		{"tampered component signature", func(g *ParsedGentx) { g.Signature[5] ^= 0x01 }, fixtureChainID},
		// only 2 signatures present; raising the threshold makes them insufficient
		{"threshold not met", func(g *ParsedGentx) { g.Signer.Multisig.Threshold = 3 }, fixtureChainID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixtureNamed(t, multisigFixtureName)
			tc.mutate(g)
			ok, err := VerifyAminoJSON(g, tc.chainID, fixtureAccNum)
			require.NoError(t, err)
			require.False(t, ok, "tampered multisig gentx verified — verification is not sound")
		})
	}
}

// TestVerifyMultisigErrors: inputs that cannot be processed return an error.
// The component-mode case is a "multisig DIRECT" rejection — mutated in-test
// because such a gentx cannot exist on a real chain.
func TestVerifyMultisigErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(g *ParsedGentx)
	}{
		{"component mode not amino", func(g *ParsedGentx) { g.Signer.Multisig.Modes[1] = "SIGN_MODE_DIRECT" }},
		{"component key type unsupported", func(g *ParsedGentx) {
			g.Signer.Multisig.Members[0].PubKeyTypeURL = "/cosmos.crypto.ed25519.PubKey"
		}},
		{"malformed MultiSignature envelope", func(g *ParsedGentx) { g.Signature = []byte{0xFF} }},
		{"truncated MultiSignature envelope", func(g *ParsedGentx) { g.Signature = g.Signature[:10] }},
		{"bitarray size mismatch", func(g *ParsedGentx) { g.Signer.Multisig.ExtraBitsStored = 1 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixtureNamed(t, multisigFixtureName)
			tc.mutate(g)
			_, err := VerifyAminoJSON(g, fixtureChainID, fixtureAccNum)
			require.Error(t, err, "expected error")
		})
	}
}

func TestMultisigDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			"no component keys",
			`{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey","threshold":1,"public_keys":[]}}],"fee":{}},"signatures":["AA=="]}`,
		},
		{
			"threshold above key count",
			`{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey","threshold":3,"public_keys":[{"key":"AA=="},{"key":"AA=="}]}}],"fee":{}},"signatures":["AA=="]}`,
		},
		{
			"no mode_infos",
			`{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey","threshold":1,"public_keys":[{"key":"AA=="}]}}],"fee":{}},"signatures":["AA=="]}`,
		},
		{
			"bad bitarray base64",
			`{"body":{"messages":[{"@type":"/cosmos.staking.v1beta1.MsgCreateValidator"}]},"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey","threshold":1,"public_keys":[{"key":"AA=="}]},"mode_info":{"multi":{"bitarray":{"extra_bits_stored":1,"elems":"!!!"},"mode_infos":[{"single":{"mode":"SIGN_MODE_LEGACY_AMINO_JSON"}}]}}}],"fee":{}},"signatures":["AA=="]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.json))
			require.Error(t, err, "expected error")
		})
	}
}
