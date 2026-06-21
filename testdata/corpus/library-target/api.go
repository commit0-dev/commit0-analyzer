// Package mylib is the library-target corpus fixture.
// There is no main package; the engine must use exported functions as entry
// points and still find the call path PublicEntryPoint → VulnerableFunc.
//
// Adversarial fixture (c): library-target module (no main).
// Expected: CORPUS-CVE-001 → SYMBOL_REACHABLE via exported-API reachability.
package mylib

import vulnlib "example.com/corpusvulnlib"

// PublicEntryPoint is the library's exported API. It calls VulnerableFunc,
// so the engine must produce SYMBOL_REACHABLE when rooted at exported funcs.
func PublicEntryPoint() string {
	return vulnlib.VulnerableFunc()
}

// SafeEntryPoint is an exported function that does NOT call VulnerableFunc.
func SafeEntryPoint() string {
	return vulnlib.SafeFunc()
}
