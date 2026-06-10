package gentxvalidate

// DefaultMaxMonikerLen matches the SDK's staking MaxMonikerLength (bytes).
const DefaultMaxMonikerLen = 70

// Params is the launch's declared constraints — everything the library reads.
// The library never touches the network or chain state.
type Params struct {
	// ChainID the gentx must have been signed for. Consumed by the
	// signature_direct check (sign bytes include it) and by CheckChainID for
	// callers whose submission envelope carries a claimed chain-id.
	ChainID string

	// BondDenom the self-delegation must use (e.g. "uosmo").
	BondDenom string

	// Bech32Prefix is the account HRP (e.g. "osmo"); the operator address is
	// checked under Bech32Prefix+"valoper".
	Bech32Prefix string

	// MinSelfDelegation is the launch's floor for the gentx's self-bond value,
	// as an integer string in the bond denom's base unit. Empty means the
	// launch declares no floor.
	MinSelfDelegation string

	// MinCommissionRate / MaxCommissionRate are the launch's commission bounds
	// as LegacyDec strings (e.g. "0.050000000000000000"). Empty means that
	// bound is not declared. These gate; the internal-consistency checks
	// (rate ≤ max_rate ≤ 1) are belt-and-suspenders the SDK already enforced.
	MinCommissionRate string
	MaxCommissionRate string

	// MaxMonikerLen in bytes (matching the SDK's measure); 0 means
	// DefaultMaxMonikerLen.
	MaxMonikerLen int
}

func (p Params) maxMonikerLen() int {
	if p.MaxMonikerLen <= 0 {
		return DefaultMaxMonikerLen
	}
	return p.MaxMonikerLen
}
