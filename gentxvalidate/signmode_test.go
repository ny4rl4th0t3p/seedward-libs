package gentxvalidate

import (
	"strings"
	"testing"
)

// TestCheckSignatureDispatch: CheckSignature routes by the gentx's declared
// mode — DIRECT reports under signature_direct; modes without a registered
// verifier fail as signature_unsupported_mode, naming the mode.
func TestCheckSignatureDispatch(t *testing.T) {
	t.Run("direct fixture reports signature_direct", func(t *testing.T) {
		g := loadFixture(t)
		r := CheckSignature(g, osmosisParams())
		if r.Invariant != InvSignatureDirect {
			t.Errorf("invariant = %q, want %q", r.Invariant, InvSignatureDirect)
		}
		if !r.OK {
			t.Errorf("valid DIRECT fixture failed: %s", r.Reason)
		}
	})

	t.Run("amino fixture reports signature_amino_json", func(t *testing.T) {
		g := loadFixtureNamed(t, aminoFixtureName)
		r := CheckSignature(g, osmosisParams())
		if r.Invariant != InvSignatureAminoJSON {
			t.Errorf("invariant = %q, want %q", r.Invariant, InvSignatureAminoJSON)
		}
		if !r.OK {
			t.Errorf("valid amino fixture failed: %s", r.Reason)
		}
	})

	t.Run("unknown mode fails naming the mode", func(t *testing.T) {
		g := loadFixture(t)
		g.Signer.Mode = "SIGN_MODE_TEXTUAL"
		r := CheckSignature(g, osmosisParams())
		if r.Invariant != InvSignatureUnsupportedMode || r.OK {
			t.Errorf("got %+v, want failed %s", r, InvSignatureUnsupportedMode)
		}
		if !strings.Contains(r.Reason, "SIGN_MODE_TEXTUAL") {
			t.Errorf("reason %q does not name the mode", r.Reason)
		}
	})
}

// TestCheckSignatureDirectUnchanged: the per-mode check keeps its pre-registry
// behavior — it reports under signature_direct even for a non-DIRECT gentx.
func TestCheckSignatureDirectUnchanged(t *testing.T) {
	g := loadFixtureNamed(t, aminoFixtureName)
	r := CheckSignatureDirect(g, osmosisParams())
	if r.Invariant != InvSignatureDirect || r.OK {
		t.Errorf("got %+v, want failed %s", r, InvSignatureDirect)
	}
}

// TestRunAllDispatchesByMode: an amino gentx through RunAll verifies under
// signature_amino_json — registering the mode changed no runner or invariant
// code (spec §5).
func TestRunAllDispatchesByMode(t *testing.T) {
	raw := readFixtureBytes(t, aminoFixtureName)

	results := RunAll(raw, osmosisParams())
	if len(results) != 9 { // well_formed + 7 light + signature dispatch
		t.Fatalf("got %d results, want 9", len(results))
	}
	last := results[len(results)-1]
	if last.Invariant != InvSignatureAminoJSON {
		t.Errorf("signature slot invariant = %q, want %q", last.Invariant, InvSignatureAminoJSON)
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("%s failed on amino fixture: %s", r.Invariant, r.Reason)
		}
	}
}
