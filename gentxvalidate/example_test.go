package gentxvalidate_test

import (
	"fmt"
	"os"

	"github.com/ny4rl4th0t3p/seedward-libs/gentxvalidate"
)

// ExampleRunAll validates a real osmosis-1 mainnet gentx against its launch's
// declared constraints, running every invariant including signature
// verification.
func ExampleRunAll() {
	raw, err := os.ReadFile("testdata/osmosis-1-gentx/gentx-Bi23Labs.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	results := gentxvalidate.RunAll(raw, gentxvalidate.Params{
		ChainID:           "osmosis-1",
		BondDenom:         "uosmo",
		Bech32Prefix:      "osmo",
		MinSelfDelegation: "1",
		MinCommissionRate: "0.050000000000000000",
	})

	for _, r := range results {
		fmt.Printf("%s ok=%v\n", r.Invariant, r.OK)
	}
	fmt.Println("all ok:", gentxvalidate.AllOK(results))
	// Output:
	// well_formed ok=true
	// bond_denom ok=true
	// self_delegation ok=true
	// commission_consistency ok=true
	// commission_change_rate ok=true
	// commission_bounds ok=true
	// moniker ok=true
	// operator_address ok=true
	// signature_direct ok=true
	// all ok: true
}
