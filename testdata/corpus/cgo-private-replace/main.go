// Package main is the cgo-private-replace corpus fixture.
// The replace directive in go.mod points to a non-existent local path,
// simulating a private/unavailable dependency. packages.Load will fail (or
// produce an IllTyped package), so the engine must emit UNKNOWN — never a
// silent drop or a false NOT_REACHABLE.
//
// Adversarial fixture (b): non-compiling / private-replace module.
// Expected: CORPUS-CVE-001 → UNKNOWN (load/build error, not silent drop).
package main

import (
	"fmt"

	vulnlib "example.com/corpusvulnlib"
)

func main() {
	fmt.Println(vulnlib.VulnerableFunc())
}
