package gentxvalidate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainCorpora: every per-chain gentx corpus under testdata, with the launch
// constraints its gentxs actually satisfied. No commission bounds — none of
// these launches declared them at genesis (osmosis-1 includes a 0% validator).
var chainCorpora = []struct {
	dir    string
	params Params
}{
	{"osmosis-1-gentx", Params{ChainID: "osmosis-1", BondDenom: "uosmo", Bech32Prefix: "osmo", MinSelfDelegation: "1"}},
	{"stargaze-1-gentx", Params{ChainID: "stargaze-1", BondDenom: "ustars", Bech32Prefix: "stars", MinSelfDelegation: "1"}},
	{"juno-1-gentx", Params{ChainID: "juno-1", BondDenom: "ujuno", Bech32Prefix: "juno", MinSelfDelegation: "1"}},
}

// TestChainCorpora runs the full invariant set over every gentx of every
// chain corpus — each file is a real mainnet artifact, so every signature
// verification, address derivation, and naturally-occurring field shape is an
// external oracle. The broadest proof this library has.
func TestChainCorpora(t *testing.T) {
	for _, c := range chainCorpora {
		t.Run(c.dir, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join("testdata", c.dir, "*.json"))
			require.NoError(t, err)
			require.NotEmpty(t, files, "corpus %s is empty", c.dir)

			for _, f := range files {
				t.Run(filepath.Base(f), func(t *testing.T) {
					raw, err := os.ReadFile(f)
					require.NoError(t, err)
					for _, r := range RunAll(raw, c.params) {
						assert.True(t, r.OK, "%s failed: %s", r.Invariant, r.Reason)
					}
				})
			}
		})
	}
}

// TestLegacyCorpusRejected: cosmoshub-4's gentxs are 2019-era legacy StdTx
// JSON — out of scope by decision (Seedward coordinates new networks, which
// emit proto JSON). Every file must be rejected cleanly with an error naming
// the legacy format; none may panic or partially decode.
func TestLegacyCorpusRejected(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "cosmoshub-4-gentx", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "cosmoshub-4 corpus is empty")

	p := Params{ChainID: "cosmoshub-4", BondDenom: "uatom", Bech32Prefix: "cosmos"}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			require.NoError(t, err)
			results := RunAll(raw, p)
			require.Len(t, results, 1, "want a single well_formed result")
			assert.Equal(t, InvWellFormed, results[0].Invariant)
			assert.False(t, results[0].OK)
			assert.Contains(t, results[0].Reason, "legacy StdTx", "reason does not identify the legacy format")
		})
	}
}

// TestSparseBitarrayMultisig pins the 2-of-3 fixture explicitly: bitarray
// 0xA0 over 3 bits = 101, so members 0 and 2 signed and member 1 did not —
// the signature→member mapping the 2-of-2 fixture cannot exercise.
func TestSparseBitarrayMultisig(t *testing.T) {
	g := loadFixtureNamed(t, "gentx-iqlusion.json")

	ms := g.Signer.Multisig
	require.NotNil(t, ms, "Signer.Multisig is nil")
	assert.Equal(t, uint32(2), ms.Threshold)
	assert.Len(t, ms.Members, 3)
	assert.Len(t, ms.Modes, 2)
	assert.Equal(t, 3, ms.bitCount())
	assert.Equal(t, []int{0, 2}, ms.signerIndices())

	ok, err := VerifyAminoJSON(g, "osmosis-1", 0)
	require.NoError(t, err)
	require.True(t, ok, "sparse multisig signature did not verify")
}
