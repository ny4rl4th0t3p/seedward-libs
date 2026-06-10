package gentxvalidate

// Runners compose the per-invariant functions (spec §3). Subset membership is
// a build/runner concern, not a code fork: RunLight is the advisory subset
// (CLI / WASM); RunAll is the server set. Phase 2 extends RunAll with the
// remaining heavy and server-only checks.

// lightChecks runs every light invariant over an already-decoded gentx.
func lightChecks(g *ParsedGentx, p Params) []Result {
	return []Result{
		CheckBondDenom(g, p),
		CheckSelfDelegation(g, p),
		CheckCommissionConsistency(g),
		CheckCommissionChangeRate(g),
		CheckCommissionBounds(g, p),
		CheckMoniker(g, p),
		CheckOperatorAddress(g, p),
	}
}

// RunLight decodes raw and runs the light (advisory) invariant set. A decode
// failure yields a single failed well_formed result — the other invariants
// are meaningless without a parsed gentx.
func RunLight(raw []byte, p Params) []Result {
	g, err := Decode(raw)
	if err != nil {
		return []Result{fail(InvWellFormed, "%v", err)}
	}
	return append([]Result{pass(InvWellFormed)}, lightChecks(g, p)...)
}

// RunAll decodes raw and runs the light set plus the heavy signature check,
// dispatched by the gentx's declared sign mode (spec §5).
func RunAll(raw []byte, p Params) []Result {
	g, err := Decode(raw)
	if err != nil {
		return []Result{fail(InvWellFormed, "%v", err)}
	}
	results := append([]Result{pass(InvWellFormed)}, lightChecks(g, p)...)
	return append(results, CheckSignature(g, p))
}
