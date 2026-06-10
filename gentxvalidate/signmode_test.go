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

	t.Run("amino fixture unsupported until its verifier registers", func(t *testing.T) {
		g := loadFixtureNamed(t, "gentx-staker_space.json")
		r := CheckSignature(g, osmosisParams())
		if r.Invariant != InvSignatureUnsupportedMode {
			t.Errorf("invariant = %q, want %q", r.Invariant, InvSignatureUnsupportedMode)
		}
		if r.OK {
			t.Error("unregistered mode passed")
		}
		if !strings.Contains(r.Reason, "SIGN_MODE_LEGACY_AMINO_JSON") {
			t.Errorf("reason %q does not name the mode", r.Reason)
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
	g := loadFixtureNamed(t, "gentx-staker_space.json")
	r := CheckSignatureDirect(g, osmosisParams())
	if r.Invariant != InvSignatureDirect || r.OK {
		t.Errorf("got %+v, want failed %s", r, InvSignatureDirect)
	}
}

// TestRunAllDispatchesByMode: an amino gentx through RunAll yields the
// unsupported-mode result (until 2.3 registers the amino verifier) while every
// light invariant still runs.
func TestRunAllDispatchesByMode(t *testing.T) {
	raw := readFixtureBytes(t, "gentx-staker_space.json")

	results := RunAll(raw, osmosisParams())
	if len(results) != 9 { // well_formed + 7 light + signature dispatch
		t.Fatalf("got %d results, want 9", len(results))
	}
	last := results[len(results)-1]
	if last.Invariant != InvSignatureUnsupportedMode || last.OK {
		t.Errorf("signature slot = %+v, want failed %s", last, InvSignatureUnsupportedMode)
	}
	for _, r := range results[:len(results)-1] {
		if !r.OK {
			t.Errorf("light invariant %s failed on amino fixture: %s", r.Invariant, r.Reason)
		}
	}
}
