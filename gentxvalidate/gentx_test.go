package gentxvalidate

import (
	"bytes"
	"os"
	"testing"
)

// The fixture is a real osmosis-1 mainnet gentx. Its signature is the
// strongest possible oracle: VerifyDirect can only return true if the
// reconstructed sign bytes are byte-identical to what the validator's wallet
// signed. The SDK oracle in spike/oracle diagnoses *why* when this fails.
const (
	fixtureChainID = "osmosis-1"
	fixtureAccNum  = 0
)

func loadFixture(t *testing.T) *ParsedGentx {
	t.Helper()
	data, err := os.ReadFile("testdata/gentx-Bi23Labs.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := Decode(data)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return g
}

func TestDecodeFields(t *testing.T) {
	g := loadFixture(t)

	if g.Msg.Description.Moniker != "Bi23 Labs" {
		t.Errorf("moniker = %q", g.Msg.Description.Moniker)
	}
	if g.Msg.Description.SecurityContact != "" {
		t.Errorf("security_contact = %q, want empty", g.Msg.Description.SecurityContact)
	}
	if g.Msg.Commission.Rate != "0.100000000000000000" {
		t.Errorf("rate = %q", g.Msg.Commission.Rate)
	}
	if g.Msg.Value.Denom != "uosmo" || g.Msg.Value.Amount != "1000000" {
		t.Errorf("value = %+v", g.Msg.Value)
	}
	if g.TimeoutHeight != 0 {
		t.Errorf("timeout_height = %d, want 0", g.TimeoutHeight)
	}
	if g.Signer.Mode != "SIGN_MODE_DIRECT" {
		t.Errorf("mode = %q", g.Signer.Mode)
	}
	if g.Signer.Sequence != 0 {
		t.Errorf("sequence = %d, want 0", g.Signer.Sequence)
	}
	if len(g.Signer.PubKey) != 33 {
		t.Errorf("account pubkey length = %d, want 33 (compressed)", len(g.Signer.PubKey))
	}
	if len(g.Msg.ConsensusPubKey) != 32 {
		t.Errorf("consensus pubkey length = %d, want 32 (ed25519)", len(g.Msg.ConsensusPubKey))
	}
	if len(g.Signature) != 64 {
		t.Errorf("signature length = %d, want 64 (r||s)", len(g.Signature))
	}
	if g.Fee.GasLimit != 200000 {
		t.Errorf("gas_limit = %d", g.Fee.GasLimit)
	}
}

func TestVerifyMainnetSignature(t *testing.T) {
	g := loadFixture(t)

	ok, err := VerifyDirect(g, fixtureChainID, fixtureAccNum)
	if err != nil {
		t.Fatalf("VerifyDirect: %v", err)
	}
	if !ok {
		t.Fatal("mainnet signature did not verify — sign-bytes reconstruction is not byte-exact")
	}
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
			if err != nil {
				t.Fatalf("VerifyDirect: %v", err)
			}
			if ok {
				t.Fatal("tampered gentx verified — verification is not sound")
			}
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
			if _, err := VerifyDirect(g, fixtureChainID, fixtureAccNum); err == nil {
				t.Fatal("expected error")
			}
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
			if err != nil {
				t.Fatalf("overflow scalar must not be a processing error: %v", err)
			}
			if ok {
				t.Fatal("overflow scalar verified")
			}
		})
	}
}

func TestDirectSignBytesDeterministic(t *testing.T) {
	g := loadFixture(t)

	first, err := DirectSignBytes(g, fixtureChainID, fixtureAccNum)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		got, err := DirectSignBytes(g, fixtureChainID, fixtureAccNum)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("non-deterministic sign bytes on iteration %d", i)
		}
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
		if err != nil {
			t.Errorf("legacyDecWire(%q): %v", tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("legacyDecWire(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"", ".", "1.2.3", "-0.1", "0.1234567890123456789", "abc"} {
		if _, err := legacyDecWire(bad, "test"); err == nil {
			t.Errorf("legacyDecWire(%q): expected error", bad)
		}
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
			if _, err := Decode([]byte(tc.json)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
