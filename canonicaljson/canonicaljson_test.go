package canonicaljson_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ny4rl4th0t3p/seedward-libs/canonicaljson"
)

type vector struct {
	Description        string `json:"description"`
	Input              any    `json:"input"`
	Expected           string `json:"expected"`
	ExpectedForSigning string `json:"expected_for_signing"`
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/canonical_json_vectors.json")
	require.NoError(t, err)

	var vectors []vector
	require.NoError(t, json.Unmarshal(data, &vectors))

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			if v.Expected != "" {
				got, err := canonicaljson.Marshal(v.Input)
				require.NoError(t, err)
				assert.Equal(t, v.Expected, string(got))
			}
			if v.ExpectedForSigning != "" {
				got, err := canonicaljson.MarshalForSigning(v.Input)
				require.NoError(t, err)
				assert.Equal(t, v.ExpectedForSigning, string(got))
			}
		})
	}
}

func TestMarshalDeterministic(t *testing.T) {
	input := map[string]any{
		"z":      "last",
		"a":      "first",
		"m":      42,
		"nested": map[string]any{"y": true, "b": false},
	}

	first, err := canonicaljson.Marshal(input)
	require.NoError(t, err)
	for range 100 {
		got, err := canonicaljson.Marshal(input)
		require.NoError(t, err)
		assert.Equal(t, first, got, "canonical output must be deterministic")
	}
}

func TestMarshalForSigningStripsFields(t *testing.T) {
	input := map[string]any{
		"chain_id":         "mychain-1",
		"operator_address": "cosmos1abc",
		"signature":        "shouldberemoved",
		"nonce":            "kept-for-replay",
		"pubkey_b64":       "shouldberemoved",
	}

	got, err := canonicaljson.MarshalForSigning(input)
	require.NoError(t, err)

	// signature and pubkey_b64 are stripped; nonce is KEPT (bound to the signature).
	want := `{"chain_id":"mychain-1","nonce":"kept-for-replay","operator_address":"cosmos1abc"}`
	assert.Equal(t, want, string(got))
}

func TestMarshalForSigningRequiresObject(t *testing.T) {
	_, err := canonicaljson.MarshalForSigning([]int{1, 2, 3})
	require.Error(t, err)
}

// An unmarshalable value (chan/func) must surface as a wrapped error, never a
// panic — the caller-facing contract for both entry points.
func TestMarshalRejectsUnmarshalableValue(t *testing.T) {
	_, err := canonicaljson.Marshal(make(chan int))
	require.Error(t, err)
}

func TestMarshalForSigningRejectsUnmarshalableValue(t *testing.T) {
	_, err := canonicaljson.MarshalForSigning(make(chan int))
	require.Error(t, err)
}
