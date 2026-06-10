package gentxvalidate

import "testing"

// The fixture is a real osmosis-1 mainnet gentx signed by a 2-of-2
// LegacyAminoPubKey multisig in amino mode. It verifies only if the StdSignDoc
// bytes are byte-exact (proven independently by the single-sig amino fixture)
// AND the MultiSignature envelope, bitarray, and threshold logic are right —
// the layered-oracle design from the phase 2 plan.
const multisigFixtureName = "gentx-Stargaze.json"

func TestMultisigDecode(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	ms := g.Signer.Multisig
	if ms == nil {
		t.Fatal("Signer.Multisig is nil")
	}
	if g.Signer.PubKeyTypeURL != legacyAminoPubKeyTypeURL {
		t.Errorf("signer type = %q", g.Signer.PubKeyTypeURL)
	}
	if g.Signer.Mode != "SIGN_MODE_LEGACY_AMINO_JSON" {
		t.Errorf("mode = %q", g.Signer.Mode)
	}
	if ms.Threshold != 2 || len(ms.Members) != 2 || len(ms.Modes) != 2 {
		t.Errorf("threshold/members/modes = %d/%d/%d, want 2/2/2",
			ms.Threshold, len(ms.Members), len(ms.Modes))
	}
	for i, m := range ms.Members {
		if m.PubKeyTypeURL != secp256k1PubKeyTypeURL {
			t.Errorf("member %d key type = %q", i, m.PubKeyTypeURL)
		}
		if len(m.PubKey) != 33 {
			t.Errorf("member %d pubkey = %d bytes, want 33", i, len(m.PubKey))
		}
	}
	if got := ms.bitCount(); got != 2 {
		t.Errorf("bitCount = %d, want 2", got)
	}
	if idx := ms.signerIndices(); len(idx) != 2 || idx[0] != 0 || idx[1] != 1 {
		t.Errorf("signerIndices = %v, want [0 1]", idx)
	}
}

func TestVerifyMultisigMainnetSignature(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	ok, err := VerifyAminoJSON(g, fixtureChainID, fixtureAccNum)
	if err != nil {
		t.Fatalf("VerifyAminoJSON: %v", err)
	}
	if !ok {
		t.Fatal("mainnet multisig signature did not verify")
	}
}

func TestCheckSignatureMultisig(t *testing.T) {
	g := loadFixtureNamed(t, multisigFixtureName)

	r := CheckSignature(g, osmosisParams())
	if r.Invariant != InvSignatureAminoJSON {
		t.Errorf("invariant = %q, want %q", r.Invariant, InvSignatureAminoJSON)
	}
	if !r.OK {
		t.Errorf("valid multisig fixture failed: %s", r.Reason)
	}
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
			if err != nil {
				t.Fatalf("VerifyAminoJSON: %v", err)
			}
			if ok {
				t.Fatal("tampered multisig gentx verified — verification is not sound")
			}
		})
	}
}

// TestVerifyMultisigErrors: inputs that cannot be processed return an error.
// The component-mode case is the "multisig DIRECT" rejection from the phase 2
// plan — mutated in-test because such a gentx cannot exist on a real chain.
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
			if _, err := VerifyAminoJSON(g, fixtureChainID, fixtureAccNum); err == nil {
				t.Fatal("expected error")
			}
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
			if _, err := Decode([]byte(tc.json)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
