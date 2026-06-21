// Package main is the equal-paths corpus fixture.
// PathA and PathB each reach VulnerableFunc in exactly one hop from main.
// The engine must deterministically pick the same path across repeated runs
// (lexicographic BFS tie-break).
//
// Adversarial fixture (d): two equal-length call paths.
// Expected: CORPUS-CVE-001 → SYMBOL_REACHABLE; path is identical across runs.
package main

import (
	"fmt"
	"os"

	vulnlib "example.com/corpusvulnlib"
)

// PathA calls VulnerableFunc in one hop.
func PathA() string { return vulnlib.VulnerableFunc() }

// PathB also calls VulnerableFunc in one hop — same depth as PathA.
func PathB() string { return vulnlib.VulnerableFunc() }

func main() {
	// Both branches kept alive so neither is dead-code eliminated.
	if len(os.Args) > 1 {
		fmt.Println(PathA())
	} else {
		fmt.Println(PathB())
	}
}
