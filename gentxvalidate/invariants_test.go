package gentxvalidate

import (
	"os"
	"strings"
	"testing"
)

// osmosisParams are launch params the mainnet fixture satisfies.
func osmosisParams() Params {
	return Params{
		ChainID:           "osmosis-1",
		BondDenom:         "uosmo",
		Bech32Prefix:      "osmo",
		MinSelfDelegation: "1",
		MinCommissionRate: "0.050000000000000000",
		MaxCommissionRate: "", // no ceiling declared
	}
}

func findResult(t *testing.T, results []Result, invariant string) Result {
	t.Helper()
	for _, r := range results {
		if r.Invariant == invariant {
			return r
		}
	}
	t.Fatalf("no result for invariant %q", invariant)
	return Result{}
}

// TestInvariantsTable: the valid fixture plus one deliberately-broken case per
// invariant (spec §6).
func TestInvariantsTable(t *testing.T) {
	cases := []struct {
		name      string
		invariant string
		mutate    func(g *ParsedGentx)
		params    func(p *Params)
	}{
		{
			name:      "wrong denom",
			invariant: InvBondDenom,
			mutate:    func(g *ParsedGentx) { g.Msg.Value.Denom = "uatom" },
		},
		{
			name:      "self-bond below floor",
			invariant: InvSelfDelegation,
			params:    func(p *Params) { p.MinSelfDelegation = "2000000" }, // fixture bonds 1000000
		},
		{
			name:      "rate above max_rate",
			invariant: InvCommissionConsistency,
			mutate: func(g *ParsedGentx) {
				g.Msg.Commission.Rate = "0.900000000000000000"
				g.Msg.Commission.MaxRate = "0.500000000000000000"
			},
		},
		{
			name:      "max_rate above 1.0",
			invariant: InvCommissionConsistency,
			mutate:    func(g *ParsedGentx) { g.Msg.Commission.MaxRate = "1.100000000000000000" },
		},
		{
			name:      "max_change_rate above max_rate",
			invariant: InvCommissionChangeRate,
			mutate: func(g *ParsedGentx) {
				g.Msg.Commission.MaxRate = "0.100000000000000000"
				g.Msg.Commission.MaxChangeRate = "0.200000000000000000"
			},
		},
		{
			name:      "rate below launch floor",
			invariant: InvCommissionBounds,
			params:    func(p *Params) { p.MinCommissionRate = "0.200000000000000000" }, // fixture rate 0.1
		},
		{
			name:      "rate above launch ceiling",
			invariant: InvCommissionBounds,
			params:    func(p *Params) { p.MaxCommissionRate = "0.050000000000000000" },
		},
		{
			name:      "max_rate above launch ceiling",
			invariant: InvCommissionBounds,
			params: func(p *Params) {
				p.MinCommissionRate = ""
				p.MaxCommissionRate = "0.500000000000000000" // fixture max_rate is 1.0
			},
		},
		{
			name:      "empty moniker",
			invariant: InvMoniker,
			mutate:    func(g *ParsedGentx) { g.Msg.Description.Moniker = "" },
		},
		{
			name:      "moniker too long",
			invariant: InvMoniker,
			mutate:    func(g *ParsedGentx) { g.Msg.Description.Moniker = strings.Repeat("x", 71) },
		},
		{
			name:      "moniker with control character",
			invariant: InvMoniker,
			mutate:    func(g *ParsedGentx) { g.Msg.Description.Moniker = "Bi23\x07Labs" },
		},
		{
			name:      "moniker invalid UTF-8",
			invariant: InvMoniker,
			mutate:    func(g *ParsedGentx) { g.Msg.Description.Moniker = "Bi23\xff" },
		},
		{
			name:      "operator address wrong HRP",
			invariant: InvOperatorAddress,
			params:    func(p *Params) { p.Bech32Prefix = "cosmos" },
		},
		{
			name:      "operator address corrupted",
			invariant: InvOperatorAddress,
			mutate:    func(g *ParsedGentx) { g.Msg.ValidatorAddress = "osmovaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqx0t062" },
		},
		{
			name:      "delegator address not the signer's",
			invariant: InvOperatorAddress,
			mutate: func(g *ParsedGentx) {
				// Valid bech32, right HRP, wrong key: flip a pubkey byte so the
				// derived address no longer matches either encoded address.
				g.Signer.PubKey[10] ^= 0x01
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixture(t)
			p := osmosisParams()
			if tc.mutate != nil {
				tc.mutate(g)
			}
			if tc.params != nil {
				tc.params(&p)
			}

			results := append(lightChecks(g, p), CheckSignatureDirect(g, p))

			r := findResult(t, results, tc.invariant)
			if r.OK {
				t.Errorf("%s passed, want failure", tc.invariant)
			}
			if r.Reason == "" {
				t.Errorf("%s failed without a reason", tc.invariant)
			}

			// Every *other* light invariant must be unaffected by this break —
			// checks are independent by design. (signature_direct may also
			// fail: most mutations change the signed bytes.)
			for _, other := range results {
				if other.Invariant == tc.invariant || other.Invariant == InvSignatureDirect {
					continue
				}
				if !other.OK {
					t.Errorf("unrelated invariant %s also failed: %s", other.Invariant, other.Reason)
				}
			}
		})
	}
}

func TestValidFixturePassesAll(t *testing.T) {
	raw, err := os.ReadFile("testdata/gentx-Bi23Labs.json")
	if err != nil {
		t.Fatal(err)
	}

	results := RunAll(raw, osmosisParams())
	if len(results) != 9 { // well_formed + 7 light + signature_direct
		t.Errorf("got %d results, want 9", len(results))
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("%s failed: %s", r.Invariant, r.Reason)
		}
	}
	if !AllOK(results) {
		t.Error("AllOK = false for the valid fixture")
	}
}

func TestRunLightSubset(t *testing.T) {
	raw, err := os.ReadFile("testdata/gentx-Bi23Labs.json")
	if err != nil {
		t.Fatal(err)
	}

	results := RunLight(raw, osmosisParams())
	if len(results) != 8 { // well_formed + 7 light, no signature
		t.Errorf("got %d results, want 8", len(results))
	}
	for _, r := range results {
		if r.Invariant == InvSignatureDirect {
			t.Error("RunLight must not include signature_direct")
		}
	}
	if !AllOK(results) {
		t.Error("light subset failed on the valid fixture")
	}
}

func TestRunnersRejectMalformed(t *testing.T) {
	for _, runner := range []func([]byte, Params) []Result{RunLight, RunAll} {
		results := runner([]byte("not json"), osmosisParams())
		if len(results) != 1 {
			t.Fatalf("got %d results for malformed input, want 1", len(results))
		}
		if results[0].Invariant != InvWellFormed || results[0].OK {
			t.Errorf("malformed input: got %+v, want failed well_formed", results[0])
		}
	}
}

func TestCheckChainID(t *testing.T) {
	p := osmosisParams()
	if r := CheckChainID("osmosis-1", p); !r.OK {
		t.Errorf("matching chain-id failed: %s", r.Reason)
	}
	if r := CheckChainID("juno-1", p); r.OK {
		t.Error("mismatched chain-id passed")
	}
	if r := CheckChainID("", p); r.OK {
		t.Error("empty claimed chain-id passed")
	}
	if r := CheckChainID("osmosis-1", Params{}); r.OK {
		t.Error("unset launch chain-id passed")
	}
}

// TestParamMisconfiguration: checks that consume Params must fail cleanly —
// never pass — when the launch param they gate on is missing or malformed.
func TestParamMisconfiguration(t *testing.T) {
	cases := []struct {
		name   string
		check  func(g *ParsedGentx, p Params) Result
		params func(p *Params)
	}{
		{"bond denom not set", CheckBondDenom, func(p *Params) { p.BondDenom = "" }},
		{"bech32 prefix not set", CheckOperatorAddress, func(p *Params) { p.Bech32Prefix = "" }},
		{"chain-id not set for signature", CheckSignatureDirect, func(p *Params) { p.ChainID = "" }},
		{"invalid min_self_delegation", CheckSelfDelegation, func(p *Params) { p.MinSelfDelegation = "abc" }},
		{"negative min_self_delegation", CheckSelfDelegation, func(p *Params) { p.MinSelfDelegation = "-1" }},
		{"invalid min_commission_rate", CheckCommissionBounds, func(p *Params) { p.MinCommissionRate = "abc" }},
		{"invalid max_commission_rate", CheckCommissionBounds, func(p *Params) { p.MaxCommissionRate = "abc" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixture(t)
			p := osmosisParams()
			tc.params(&p)

			r := tc.check(g, p)
			if r.OK {
				t.Error("check passed, want failure")
			}
			if r.Reason == "" {
				t.Error("check failed without a reason")
			}
		})
	}
}

// TestSignatureDirectEncodeError: a field that decoded fine but cannot be
// re-encoded (malformed LegacyDec) must surface as a failed result with a
// reason, never a panic.
func TestSignatureDirectEncodeError(t *testing.T) {
	g := loadFixture(t)
	g.Msg.Commission.Rate = "abc"

	r := CheckSignatureDirect(g, osmosisParams())
	if r.OK {
		t.Error("unencodable commission rate passed signature_direct")
	}
	if r.Reason == "" {
		t.Error("failed without a reason")
	}
}

func TestSelfDelegationEdges(t *testing.T) {
	g := loadFixture(t)

	p := osmosisParams()
	p.MinSelfDelegation = "" // launch declares no floor
	if r := CheckSelfDelegation(g, p); !r.OK {
		t.Errorf("no declared floor must pass: %s", r.Reason)
	}

	g.Msg.Value.Amount = "abc"
	if r := CheckSelfDelegation(g, osmosisParams()); r.OK {
		t.Error("invalid self-bond amount passed")
	}
}

// TestSignatureCatchesPlausibleTamper: a tampered gentx that satisfies every
// light invariant still fails the signature — the case that motivates shipping
// verify in the browser.
func TestSignatureCatchesPlausibleTamper(t *testing.T) {
	g := loadFixture(t)
	p := osmosisParams()
	g.Msg.Description.Moniker = "Totally Legit Labs" // a perfectly valid moniker

	for _, r := range lightChecks(g, p) {
		if !r.OK {
			t.Fatalf("light invariant %s rejected the plausible tamper: %s", r.Invariant, r.Reason)
		}
	}
	if r := CheckSignatureDirect(g, p); r.OK {
		t.Fatal("signature_direct passed a tampered gentx")
	}
}
