package gentxvalidate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			if err != nil {
				t.Fatal(err)
			}
			if len(files) == 0 {
				t.Fatalf("corpus %s is empty", c.dir)
			}

			for _, f := range files {
				t.Run(filepath.Base(f), func(t *testing.T) {
					raw, err := os.ReadFile(f)
					if err != nil {
						t.Fatal(err)
					}
					for _, r := range RunAll(raw, c.params) {
						if !r.OK {
							t.Errorf("%s failed: %s", r.Invariant, r.Reason)
						}
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
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("cosmoshub-4 corpus is empty")
	}

	p := Params{ChainID: "cosmoshub-4", BondDenom: "uatom", Bech32Prefix: "cosmos"}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			results := RunAll(raw, p)
			if len(results) != 1 || results[0].Invariant != InvWellFormed || results[0].OK {
				t.Fatalf("want a single failed well_formed result, got %+v", results)
			}
			if !strings.Contains(results[0].Reason, "legacy StdTx") {
				t.Errorf("reason %q does not identify the legacy format", results[0].Reason)
			}
		})
	}
}

// TestSparseBitarrayMultisig pins the 2-of-3 fixture explicitly: bitarray
// 0xA0 over 3 bits = 101, so members 0 and 2 signed and member 1 did not —
// the signature→member mapping the 2-of-2 fixture cannot exercise.
func TestSparseBitarrayMultisig(t *testing.T) {
	g := loadFixtureNamed(t, "gentx-iqlusion.json")

	ms := g.Signer.Multisig
	if ms == nil {
		t.Fatal("Signer.Multisig is nil")
	}
	if ms.Threshold != 2 || len(ms.Members) != 3 || len(ms.Modes) != 2 {
		t.Errorf("threshold/members/modes = %d/%d/%d, want 2/3/2",
			ms.Threshold, len(ms.Members), len(ms.Modes))
	}
	if got := ms.bitCount(); got != 3 {
		t.Errorf("bitCount = %d, want 3", got)
	}
	if idx := ms.signerIndices(); len(idx) != 2 || idx[0] != 0 || idx[1] != 2 {
		t.Errorf("signerIndices = %v, want [0 2]", idx)
	}

	ok, err := VerifyAminoJSON(g, "osmosis-1", 0)
	if err != nil {
		t.Fatalf("VerifyAminoJSON: %v", err)
	}
	if !ok {
		t.Fatal("sparse multisig signature did not verify")
	}
}
