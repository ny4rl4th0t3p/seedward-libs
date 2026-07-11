package gentxvalidate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.Failf(t, "invariant not found", "no result for invariant %q", invariant)
	return Result{}
}

// TestInvariantsTable: the valid fixture plus one deliberately broken case per
// invariant.
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
			name:      "max_change_rate above launch ceiling",
			invariant: InvCommissionBounds,
			mutate:    func(g *ParsedGentx) { g.Msg.Commission.MaxChangeRate = "0.500000000000000000" }, // ≤ max_rate 1.0, so consistency holds
			params:    func(p *Params) { p.MaxCommissionChangeRate = "0.050000000000000000" },
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
		{
			name:      "consensus pubkey wrong type",
			invariant: InvConsensusPubKey,
			mutate:    func(g *ParsedGentx) { g.Msg.ConsensusPubKeyTypeURL = "/cosmos.crypto.secp256k1.PubKey" },
		},
		{
			name:      "consensus pubkey wrong length",
			invariant: InvConsensusPubKey,
			mutate:    func(g *ParsedGentx) { g.Msg.ConsensusPubKey = g.Msg.ConsensusPubKey[:31] },
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
			assert.False(t, r.OK, "%s passed, want failure", tc.invariant)
			assert.NotEmpty(t, r.Reason, "%s failed without a reason", tc.invariant)

			// Every *other* light invariant must be unaffected by this break —
			// checks are independent by design. (signature_direct may also
			// fail: most mutations change the signed bytes.)
			for _, other := range results {
				if other.Invariant == tc.invariant || other.Invariant == InvSignatureDirect {
					continue
				}
				assert.True(t, other.OK, "unrelated invariant %s also failed: %s", other.Invariant, other.Reason)
			}
		})
	}
}

func TestValidFixturePassesAll(t *testing.T) {
	raw := readFixtureBytes(t, "gentx-Bi23Labs.json")

	results := RunAll(raw, osmosisParams())
	assert.Len(t, results, 10) // well_formed + 8 light + signature_direct
	for _, r := range results {
		assert.True(t, r.OK, "%s failed: %s", r.Invariant, r.Reason)
	}
	assert.True(t, AllOK(results), "AllOK = false for the valid fixture")
}

func TestRunLightSubset(t *testing.T) {
	raw := readFixtureBytes(t, "gentx-Bi23Labs.json")

	results := RunLight(raw, osmosisParams())
	assert.Len(t, results, 9) // well_formed + 8 light, no signature
	for _, r := range results {
		assert.NotEqual(t, InvSignatureDirect, r.Invariant, "RunLight must not include signature_direct")
	}
	assert.True(t, AllOK(results), "light subset failed on the valid fixture")
}

func TestRunnersRejectMalformed(t *testing.T) {
	for _, runner := range []func([]byte, Params) []Result{RunLight, RunAll} {
		results := runner([]byte("not json"), osmosisParams())
		require.Len(t, results, 1)
		assert.Equal(t, InvWellFormed, results[0].Invariant)
		assert.False(t, results[0].OK)
	}
}

func TestCheckChainID(t *testing.T) {
	p := osmosisParams()

	r := CheckChainID("osmosis-1", p)
	assert.True(t, r.OK, "matching chain-id failed: %s", r.Reason)

	assert.False(t, CheckChainID("juno-1", p).OK, "mismatched chain-id passed")
	assert.False(t, CheckChainID("", p).OK, "empty claimed chain-id passed")
	assert.False(t, CheckChainID("osmosis-1", Params{}).OK, "unset launch chain-id passed")
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
		{"invalid max_commission_change_rate", CheckCommissionBounds, func(p *Params) { p.MaxCommissionChangeRate = "abc" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := loadFixture(t)
			p := osmosisParams()
			tc.params(&p)

			r := tc.check(g, p)
			assert.False(t, r.OK, "check passed, want failure")
			assert.NotEmpty(t, r.Reason, "check failed without a reason")
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
	assert.False(t, r.OK, "unencodable commission rate passed signature_direct")
	assert.NotEmpty(t, r.Reason, "failed without a reason")
}

// TestCommissionChangeRateCeiling pins the max_change_rate launch ceiling at the
// boundary (equality passes), over the ceiling (fails), and unset (passes).
func TestCommissionChangeRateCeiling(t *testing.T) {
	g := loadFixture(t)
	p := osmosisParams()
	g.Msg.Commission.MaxChangeRate = "0.050000000000000000"

	p.MaxCommissionChangeRate = "0.050000000000000000" // equal — at the ceiling
	r := CheckCommissionBounds(g, p)
	assert.True(t, r.OK, "max_change_rate at ceiling must pass: %s", r.Reason)

	p.MaxCommissionChangeRate = "0.010000000000000000" // below the gentx's value
	assert.False(t, CheckCommissionBounds(g, p).OK, "max_change_rate above ceiling passed")

	p.MaxCommissionChangeRate = "" // no ceiling declared
	r = CheckCommissionBounds(g, p)
	assert.True(t, r.OK, "no declared change-rate ceiling must pass: %s", r.Reason)
}

// TestConsensusPubKey covers the ed25519/32-byte consensus-key invariant.
func TestConsensusPubKey(t *testing.T) {
	r := CheckConsensusPubKey(loadFixture(t))
	assert.True(t, r.OK, "valid ed25519 consensus pubkey failed: %s", r.Reason)

	wrongType := loadFixture(t)
	wrongType.Msg.ConsensusPubKeyTypeURL = "/cosmos.crypto.secp256k1.PubKey"
	assert.False(t, CheckConsensusPubKey(wrongType).OK, "non-ed25519 consensus pubkey passed")

	wrongLen := loadFixture(t)
	wrongLen.Msg.ConsensusPubKey = wrongLen.Msg.ConsensusPubKey[:31]
	assert.False(t, CheckConsensusPubKey(wrongLen).OK, "31-byte consensus pubkey passed")
}

// TestOperatorAddressEmptyDelegator: modern SDK (v0.50+) gentxs omit
// delegator_address; operator_address must still pass on validator_address alone.
func TestOperatorAddressEmptyDelegator(t *testing.T) {
	g := loadFixture(t)
	g.Msg.DelegatorAddress = ""
	r := CheckOperatorAddress(g, osmosisParams())
	assert.True(t, r.OK, "empty delegator_address must pass (deprecated field): %s", r.Reason)
}

func TestSelfDelegationEdges(t *testing.T) {
	g := loadFixture(t)

	p := osmosisParams()
	p.MinSelfDelegation = "" // launch declares no floor
	r := CheckSelfDelegation(g, p)
	assert.True(t, r.OK, "no declared floor must pass: %s", r.Reason)

	g.Msg.Value.Amount = "abc"
	assert.False(t, CheckSelfDelegation(g, osmosisParams()).OK, "invalid self-bond amount passed")
}

// TestSignatureCatchesPlausibleTamper: a tampered gentx that satisfies every
// light invariant still fails the signature — the case that motivates shipping
// verify in the browser.
func TestSignatureCatchesPlausibleTamper(t *testing.T) {
	g := loadFixture(t)
	p := osmosisParams()
	g.Msg.Description.Moniker = "Totally Legit Labs" // a perfectly valid moniker

	for _, r := range lightChecks(g, p) {
		require.True(t, r.OK, "light invariant %s rejected the plausible tamper: %s", r.Invariant, r.Reason)
	}
	assert.False(t, CheckSignatureDirect(g, p).OK, "signature_direct passed a tampered gentx")
}
