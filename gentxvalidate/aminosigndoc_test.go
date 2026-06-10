package gentxvalidate

import "testing"

// The fixture is a real osmosis-1 mainnet gentx signed with
// SIGN_MODE_LEGACY_AMINO_JSON by a single secp256k1 key. Same oracle logic as
// the DIRECT fixture: VerifyAminoJSON can only return true if the
// reconstructed StdSignDoc bytes are byte-identical to what the validator's
// wallet signed.
const aminoFixtureName = "gentx-staker_space.json"

func TestVerifyAminoMainnetSignature(t *testing.T) {
	g := loadFixtureNamed(t, aminoFixtureName)

	ok, err := VerifyAminoJSON(g, fixtureChainID, fixtureAccNum)
	if err != nil {
		t.Fatalf("VerifyAminoJSON: %v", err)
	}
	if !ok {
		t.Fatal("mainnet amino signature did not verify — StdSignDoc reconstruction is not byte-exact")
	}
}

func TestVerifyAminoRejectsTamper(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(g *ParsedGentx)
		chainID string
	}{
		{"wrong chain-id", func(*ParsedGentx) {}, "osmosis-2"},
		{"tampered memo", func(g *ParsedGentx) { g.Memo += "x" }, fixtureChainID},
		{"tampered moniker", func(g *ParsedGentx) { g.Msg.Description.Moniker = "Evil Space" }, fixtureChainID},
		{"tampered amount", func(g *ParsedGentx) { g.Msg.Value.Amount = "1" }, fixtureChainID},
		{"tampered commission", func(g *ParsedGentx) { g.Msg.Commission.Rate = "0.070000000000000000" }, fixtureChainID},
		{"tampered signature", func(g *ParsedGentx) { g.Signature[0] ^= 0x01 }, fixtureChainID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixtureNamed(t, aminoFixtureName)
			tc.mutate(g)
			ok, err := VerifyAminoJSON(g, tc.chainID, fixtureAccNum)
			if err != nil {
				t.Fatalf("VerifyAminoJSON: %v", err)
			}
			if ok {
				t.Fatal("tampered amino gentx verified — verification is not sound")
			}
		})
	}
}

func TestAminoSignBytesErrors(t *testing.T) {
	t.Run("rejects non-amino mode", func(t *testing.T) {
		g := loadFixture(t) // DIRECT fixture
		if _, err := AminoSignBytes(g, fixtureChainID, fixtureAccNum); err == nil {
			t.Error("DIRECT-mode gentx accepted")
		}
	})

	t.Run("rejects unknown consensus key type", func(t *testing.T) {
		g := loadFixtureNamed(t, aminoFixtureName)
		g.Msg.ConsensusPubKeyTypeURL = "/cosmos.crypto.sr25519.PubKey"
		if _, err := AminoSignBytes(g, fixtureChainID, fixtureAccNum); err == nil {
			t.Error("unknown consensus key type accepted")
		}
	})
}
