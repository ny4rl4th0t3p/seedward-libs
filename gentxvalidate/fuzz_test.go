package gentxvalidate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzDecode pins the decoder's core promise: Decode never panics on any input —
// malformed bytes must surface as an error, never a crash — and never returns a
// nil gentx with a nil error. It is seeded from the real mainnet gentx corpus
// (every testdata/*-gentx/*.json), so the fuzzer mutates near structurally-valid
// inputs, where the interesting edge cases in the hand-rolled protobuf/bitarray/
// varint parsing live.
//
// A plain `go test` runs the body against the seed corpus (an always-on
// regression check); the active mutation runs with `go test -fuzz=FuzzDecode`.
func FuzzDecode(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join("testdata", "*-gentx", "*.json"))
	require.NoError(f, err)
	require.NotEmpty(f, seeds, "no corpus seed files found")

	for _, path := range seeds {
		data, err := os.ReadFile(path)
		require.NoError(f, err, "read seed %s", path)
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := Decode(data)
		if err == nil {
			require.NotNil(t, g, "Decode returned a nil gentx with a nil error")
		}
	})
}
