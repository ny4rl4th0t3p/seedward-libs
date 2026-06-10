package gentxvalidate

import (
	"bytes"
	"math/big"
	"unicode"
	"unicode/utf8"
)

// Per-invariant pure functions (spec §3): each takes (ParsedGentx, Params) and
// returns a structured Result. Invariants never panic — malformed input is a
// failed result, not a crash.

const base10 = 10

var decOne = scaledOne() // 1.0 as a ×10¹⁸ scaled integer

func scaledOne() *big.Int {
	one, _ := new(big.Int).SetString("1000000000000000000", base10)
	return one
}

// decValue parses a LegacyDec string into its ×10¹⁸ scaled integer.
func decValue(s, field string) (*big.Int, error) {
	w, err := legacyDecWire(s, field)
	if err != nil {
		return nil, err
	}
	n, _ := new(big.Int).SetString(string(w), base10) // legacyDecWire guarantees digits
	return n, nil
}

// CheckChainID compares a claimed chain-id against the launch's. The gentx
// JSON itself does not carry a chain-id (it is a sign-time input), so this
// check applies to submission envelopes that claim one — coordd's case, the
// porting target for chaincoord's structural check. For the gentx itself the
// chain-id is enforced cryptographically by CheckSignatureDirect.
func CheckChainID(claimed string, p Params) Result {
	if p.ChainID == "" {
		return fail(InvChainID, "params: chain-id not set")
	}
	if claimed != p.ChainID {
		return fail(InvChainID, "chain-id %q, launch expects %q", claimed, p.ChainID)
	}
	return pass(InvChainID)
}

// CheckBondDenom verifies the self-delegation uses the launch's bond denom.
func CheckBondDenom(g *ParsedGentx, p Params) Result {
	if p.BondDenom == "" {
		return fail(InvBondDenom, "params: bond denom not set")
	}
	if g.Msg.Value.Denom != p.BondDenom {
		return fail(InvBondDenom, "denom %q, launch expects %q", g.Msg.Value.Denom, p.BondDenom)
	}
	return pass(InvBondDenom)
}

// CheckSelfDelegation verifies the gentx's self-bond value is at least the
// launch's declared floor (distinct from the validator's own
// min_self_delegation field carried in the message). An empty Params floor
// means the launch declares none — the check passes.
func CheckSelfDelegation(g *ParsedGentx, p Params) Result {
	if p.MinSelfDelegation == "" {
		return pass(InvSelfDelegation)
	}
	floor, ok := new(big.Int).SetString(p.MinSelfDelegation, base10)
	if !ok || floor.Sign() < 0 {
		return fail(InvSelfDelegation, "params: invalid min_self_delegation %q", p.MinSelfDelegation)
	}
	amount, ok := new(big.Int).SetString(g.Msg.Value.Amount, base10)
	if !ok || amount.Sign() < 0 {
		return fail(InvSelfDelegation, "invalid self-bond amount %q", g.Msg.Value.Amount)
	}
	if amount.Cmp(floor) < 0 {
		return fail(InvSelfDelegation, "self-bond %s below launch floor %s", g.Msg.Value.Amount, p.MinSelfDelegation)
	}
	return pass(InvSelfDelegation)
}

// CheckCommissionConsistency verifies rate ≤ max_rate ≤ 1.0 — internal
// consistency the SDK already enforced at gentx creation; cheap
// belt-and-suspenders.
func CheckCommissionConsistency(g *ParsedGentx) Result {
	rate, err := decValue(g.Msg.Commission.Rate, "commission.rate")
	if err != nil {
		return fail(InvCommissionConsistency, "%v", err)
	}
	maxRate, err := decValue(g.Msg.Commission.MaxRate, "commission.max_rate")
	if err != nil {
		return fail(InvCommissionConsistency, "%v", err)
	}
	if rate.Cmp(maxRate) > 0 {
		return fail(InvCommissionConsistency, "rate %s > max_rate %s", g.Msg.Commission.Rate, g.Msg.Commission.MaxRate)
	}
	if maxRate.Cmp(decOne) > 0 {
		return fail(InvCommissionConsistency, "max_rate %s > 1.0", g.Msg.Commission.MaxRate)
	}
	return pass(InvCommissionConsistency)
}

// CheckCommissionChangeRate verifies max_change_rate ≤ max_rate — likewise
// internal consistency.
func CheckCommissionChangeRate(g *ParsedGentx) Result {
	maxChange, err := decValue(g.Msg.Commission.MaxChangeRate, "commission.max_change_rate")
	if err != nil {
		return fail(InvCommissionChangeRate, "%v", err)
	}
	maxRate, err := decValue(g.Msg.Commission.MaxRate, "commission.max_rate")
	if err != nil {
		return fail(InvCommissionChangeRate, "%v", err)
	}
	if maxChange.Cmp(maxRate) > 0 {
		return fail(InvCommissionChangeRate, "max_change_rate %s > max_rate %s", g.Msg.Commission.MaxChangeRate, g.Msg.Commission.MaxRate)
	}
	return pass(InvCommissionChangeRate)
}

// CheckCommissionBounds verifies commission against the launch's declared
// bounds — rate ≥ floor (MinCommissionRate) and, if a ceiling is set,
// rate/max_rate ≤ ceiling. This is the check that consumes Params and actually
// gates; it is not implied by the consistency checks above.
func CheckCommissionBounds(g *ParsedGentx, p Params) Result {
	rate, err := decValue(g.Msg.Commission.Rate, "commission.rate")
	if err != nil {
		return fail(InvCommissionBounds, "%v", err)
	}

	if p.MinCommissionRate != "" {
		floor, err := decValue(p.MinCommissionRate, "params.min_commission_rate")
		if err != nil {
			return fail(InvCommissionBounds, "%v", err)
		}
		if rate.Cmp(floor) < 0 {
			return fail(InvCommissionBounds, "rate %s below launch floor %s", g.Msg.Commission.Rate, p.MinCommissionRate)
		}
	}

	if p.MaxCommissionRate != "" {
		ceil, err := decValue(p.MaxCommissionRate, "params.max_commission_rate")
		if err != nil {
			return fail(InvCommissionBounds, "%v", err)
		}
		if rate.Cmp(ceil) > 0 {
			return fail(InvCommissionBounds, "rate %s above launch ceiling %s", g.Msg.Commission.Rate, p.MaxCommissionRate)
		}
		maxRate, err := decValue(g.Msg.Commission.MaxRate, "commission.max_rate")
		if err != nil {
			return fail(InvCommissionBounds, "%v", err)
		}
		if maxRate.Cmp(ceil) > 0 {
			return fail(InvCommissionBounds, "max_rate %s above launch ceiling %s", g.Msg.Commission.MaxRate, p.MaxCommissionRate)
		}
	}

	return pass(InvCommissionBounds)
}

// CheckMoniker verifies the moniker is non-empty, within the length limit
// (bytes, matching the SDK's measure), valid UTF-8, and free of control
// characters.
func CheckMoniker(g *ParsedGentx, p Params) Result {
	m := g.Msg.Description.Moniker
	if m == "" {
		return fail(InvMoniker, "moniker is empty")
	}
	if limit := p.maxMonikerLen(); len(m) > limit {
		return fail(InvMoniker, "moniker is %d bytes, limit %d", len(m), limit)
	}
	if !utf8.ValidString(m) {
		return fail(InvMoniker, "moniker is not valid UTF-8")
	}
	for _, r := range m {
		if unicode.IsControl(r) {
			return fail(InvMoniker, "moniker contains control character %U", r)
		}
	}
	return pass(InvMoniker)
}

// CheckOperatorAddress verifies both addresses are bech32-valid under the
// launch HRP (account prefix for delegator_address, +"valoper" for
// validator_address) and that both are derived from the signing account's
// pubkey: RIPEMD160(SHA256(secp256k1 pubkey)).
func CheckOperatorAddress(g *ParsedGentx, p Params) Result {
	if p.Bech32Prefix == "" {
		return fail(InvOperatorAddress, "params: bech32 prefix not set")
	}

	valBytes, err := decodeBech32Address(g.Msg.ValidatorAddress, p.Bech32Prefix+"valoper")
	if err != nil {
		return fail(InvOperatorAddress, "validator_address: %v", err)
	}
	delBytes, err := decodeBech32Address(g.Msg.DelegatorAddress, p.Bech32Prefix)
	if err != nil {
		return fail(InvOperatorAddress, "delegator_address: %v", err)
	}

	if g.Signer.PubKeyTypeURL != secp256k1PubKeyTypeURL {
		return fail(InvOperatorAddress, "cannot derive address: unsupported account key type %q", g.Signer.PubKeyTypeURL)
	}
	if len(g.Signer.PubKey) != compressedPubKeyLen {
		return fail(InvOperatorAddress, "account pubkey is %d bytes, want %d (compressed)", len(g.Signer.PubKey), compressedPubKeyLen)
	}
	derived := accountAddressBytes(g.Signer.PubKey)

	if !bytes.Equal(valBytes, derived) {
		return fail(InvOperatorAddress, "validator_address is not derived from the signing account")
	}
	if !bytes.Equal(delBytes, derived) {
		return fail(InvOperatorAddress, "delegator_address is not derived from the signing account")
	}
	return pass(InvOperatorAddress)
}

// CheckSignatureDirect is the heavy signature invariant: SIGN_MODE_DIRECT
// sign-bytes reconstruction over Params.ChainID (account number 0 at genesis)
// verified against the account pubkey. Because the chain-id is inside the
// signed bytes, this also proves the gentx was signed for the launch's chain.
func CheckSignatureDirect(g *ParsedGentx, p Params) Result {
	if p.ChainID == "" {
		return fail(InvSignatureDirect, "params: chain-id not set")
	}
	ok, err := VerifyDirect(g, p.ChainID, 0)
	if err != nil {
		return fail(InvSignatureDirect, "%v", err)
	}
	if !ok {
		return fail(InvSignatureDirect, "signature does not verify for chain-id %q", p.ChainID)
	}
	return pass(InvSignatureDirect)
}
