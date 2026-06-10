//go:build js && wasm

// Command gentxvalidate-wasm is the browser build of gentxvalidate. It
// registers two synchronous functions on globalThis:
//
//	seedwardRunLight(gentxJSON, paramsJSON) -> resultsJSON
//	seedwardRunAll(gentxJSON, paramsJSON)   -> resultsJSON
//
// Both take the gentx document and the launch Params as JSON strings and
// return the []Result JSON string. All failures — including internal panics —
// surface as a failed well_formed result; the browser never sees a Go stack
// trace.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/ny4rl4th0t3p/seedward-libs/gentxvalidate"
)

func main() {
	js.Global().Set("seedwardRunLight", runner(gentxvalidate.RunLight))
	js.Global().Set("seedwardRunAll", runner(gentxvalidate.RunAll))
	select {} // keep the Go runtime alive for JS callbacks
}

func runner(run func([]byte, gentxvalidate.Params) []gentxvalidate.Result) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) (out any) {
		defer func() {
			if r := recover(); r != nil {
				out = errorJSON(fmt.Sprintf("internal error: %v", r))
			}
		}()

		if len(args) != 2 {
			return errorJSON("expected (gentxJSON, paramsJSON)")
		}
		var p gentxvalidate.Params
		if err := json.Unmarshal([]byte(args[1].String()), &p); err != nil {
			return errorJSON("invalid params JSON: " + err.Error())
		}

		results := run([]byte(args[0].String()), p)
		bz, err := json.Marshal(results)
		if err != nil {
			return errorJSON("marshal results: " + err.Error())
		}
		return string(bz)
	})
}

func errorJSON(reason string) string {
	bz, _ := json.Marshal([]gentxvalidate.Result{
		{Invariant: gentxvalidate.InvWellFormed, OK: false, Reason: reason},
	})
	return string(bz)
}
