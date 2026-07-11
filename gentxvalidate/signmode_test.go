package gentxvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckSignatureDispatch: CheckSignature routes by the gentx's declared
// mode — DIRECT reports under signature_direct; modes without a registered
// verifier fail as signature_unsupported_mode, naming the mode.
func TestCheckSignatureDispatch(t *testing.T) {
	t.Run("direct fixture reports signature_direct", func(t *testing.T) {
		g := loadFixture(t)
		r := CheckSignature(g, osmosisParams())
		assert.Equal(t, InvSignatureDirect, r.Invariant)
		assert.True(t, r.OK, "valid DIRECT fixture failed: %s", r.Reason)
	})

	t.Run("amino fixture reports signature_amino_json", func(t *testing.T) {
		g := loadFixtureNamed(t, aminoFixtureName)
		r := CheckSignature(g, osmosisParams())
		assert.Equal(t, InvSignatureAminoJSON, r.Invariant) //nolint:testifylint // invariant ID constant, not encoded JSON
		assert.True(t, r.OK, "valid amino fixture failed: %s", r.Reason)
	})

	t.Run("unknown mode fails naming the mode", func(t *testing.T) {
		g := loadFixture(t)
		g.Signer.Mode = "SIGN_MODE_TEXTUAL"
		r := CheckSignature(g, osmosisParams())
		assert.Equal(t, InvSignatureUnsupportedMode, r.Invariant)
		assert.False(t, r.OK)
		assert.Contains(t, r.Reason, "SIGN_MODE_TEXTUAL", "reason does not name the mode")
	})
}

// TestCheckSignatureDirectUnchanged: the per-mode check keeps its pre-registry
// behavior — it reports under signature_direct even for a non-DIRECT gentx.
func TestCheckSignatureDirectUnchanged(t *testing.T) {
	g := loadFixtureNamed(t, aminoFixtureName)
	r := CheckSignatureDirect(g, osmosisParams())
	assert.Equal(t, InvSignatureDirect, r.Invariant)
	assert.False(t, r.OK)
}

// TestRunAllDispatchesByMode: an amino gentx through RunAll verifies under
// signature_amino_json — registering the mode changed no runner or invariant
// code.
func TestRunAllDispatchesByMode(t *testing.T) {
	raw := readFixtureBytes(t, aminoFixtureName)

	results := RunAll(raw, osmosisParams())
	require.Len(t, results, 10) // well_formed + 8 light + signature dispatch
	last := results[len(results)-1]
	assert.Equal(t, InvSignatureAminoJSON, last.Invariant) //nolint:testifylint // invariant ID constant, not encoded JSON
	for _, r := range results {
		assert.True(t, r.OK, "%s failed on amino fixture: %s", r.Invariant, r.Reason)
	}
}
