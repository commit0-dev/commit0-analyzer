// Package main is the not-reachable-cve corpus fixture.
// It imports corpusvulnlib but only calls SafeFunc — never VulnerableFunc.
// Expected: CORPUS-CVE-001 → NOT_REACHABLE (TN — correctly suppressed).
package main

import (
	"fmt"

	vulnlib "example.com/corpusvulnlib"
)

func main() {
	fmt.Println(vulnlib.SafeFunc())
}
