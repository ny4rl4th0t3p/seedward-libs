package gentxvalidate

import "fmt"

// Result is one invariant's outcome: which check ran, whether it passed, and a
// machine-readable reason when it didn't.
type Result struct {
	Invariant string `json:"invariant"`
	OK        bool   `json:"ok"`
	Reason    string `json:"reason,omitempty"`
}

// Invariant IDs. Stable identifiers — consumers (coordd, CLI, web) key on
// these, so they are part of the public API and must not be renamed casually.
const (
	InvWellFormed            = "well_formed"
	InvChainID               = "chain_id"
	InvBondDenom             = "bond_denom"
	InvSelfDelegation        = "self_delegation"
	InvCommissionConsistency = "commission_consistency"
	InvCommissionChangeRate  = "commission_change_rate"
	InvCommissionBounds      = "commission_bounds"
	InvMoniker               = "moniker"
	InvOperatorAddress       = "operator_address"
	InvSignatureDirect       = "signature_direct"
)

func pass(invariant string) Result {
	return Result{Invariant: invariant, OK: true}
}

func fail(invariant, format string, args ...any) Result {
	return Result{Invariant: invariant, OK: false, Reason: fmt.Sprintf(format, args...)}
}

// AllOK reports whether every result passed.
func AllOK(results []Result) bool {
	for _, r := range results {
		if !r.OK {
			return false
		}
	}
	return true
}
