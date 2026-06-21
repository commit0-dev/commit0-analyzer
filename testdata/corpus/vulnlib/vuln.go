// Package vulnlib is a synthetic vulnerable library for corpus fixtures.
// It mirrors the structure of plugins/go-reachability/testdata/mods/vulnlib
// but lives here so corpus modules can reference it via relative replace directives.
package vulnlib

import "fmt"

// VulnerableFunc is the seeded vulnerable symbol targeted by corpus advisories.
func VulnerableFunc() string {
	return fmt.Sprintf("vuln called")
}

// SafeFunc is a safe symbol — never flagged as vulnerable.
func SafeFunc() string {
	return "safe"
}

// ExportedAPI is an exported entry point for library-target corpus fixtures.
// Library modules (no main) expose this as their public API so the engine
// can use exported functions as reachability roots.
func ExportedAPI() string {
	return VulnerableFunc()
}
