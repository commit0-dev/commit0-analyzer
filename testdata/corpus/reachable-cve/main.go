// Package main is the reachable-cve corpus fixture.
// It directly calls VulnerableFunc — the engine must produce SYMBOL_REACHABLE.
// Expected: CORPUS-CVE-001 → SYMBOL_REACHABLE (TP).
package main

import (
	"fmt"

	vulnlib "example.com/corpusvulnlib"
)

func main() {
	fmt.Println(vulnlib.VulnerableFunc())
}
