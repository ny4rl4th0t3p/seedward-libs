package gentxvalidate

// Sign-mode dispatch: signature verification is pluggable per sign
// mode. Adding a mode is a new signModes entry — invariants and runners do not
// change. The WASM subset stays DIRECT-only by registering fewer modes at
// build time.

// genesisAccountNumber is the account number signed over by a gentx: the
// account does not exist before genesis, so it is always 0.
const genesisAccountNumber = 0

// A modeVerifier verifies a gentx's signature(s) for one sign mode,
// reconstructing that mode's sign bytes over chainID and accountNumber.
// False with a nil error means the signature simply does not verify; an error
// means the input couldn't be processed at all.
type modeVerifier func(g *ParsedGentx, chainID string, accountNumber uint64) (bool, error)

// signModes maps a SignerInfo mode string to its verifier and the invariant ID
// its results report under (per-mode IDs are public API).
var signModes = map[string]struct {
	invariant string
	verify    modeVerifier
}{
	"SIGN_MODE_DIRECT":            {InvSignatureDirect, VerifyDirect},
	"SIGN_MODE_LEGACY_AMINO_JSON": {InvSignatureAminoJSON, VerifyAminoJSON},
}

// CheckSignature is the heavy signature invariant: it dispatches to the
// verifier registered for the gentx's declared sign mode and reports under
// that mode's invariant ID. A mode with no registered verifier is a failed
// signature_unsupported_mode result naming the mode — never a panic.
func CheckSignature(g *ParsedGentx, p Params) Result {
	m, ok := signModes[g.Signer.Mode]
	if !ok {
		return fail(InvSignatureUnsupportedMode, "no verifier for sign mode %q", g.Signer.Mode)
	}
	return checkSignatureMode(g, p, m.invariant, m.verify)
}

// checkSignatureMode shares the Params gating and Result shaping across the
// per-mode signature invariants.
func checkSignatureMode(g *ParsedGentx, p Params, invariant string, verify modeVerifier) Result {
	if p.ChainID == "" {
		return fail(invariant, "params: chain-id not set")
	}
	ok, err := verify(g, p.ChainID, genesisAccountNumber)
	if err != nil {
		return fail(invariant, "%v", err)
	}
	if !ok {
		return fail(invariant, "signature does not verify for chain-id %q", p.ChainID)
	}
	return pass(invariant)
}
