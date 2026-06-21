// Package main provides two equal-length call paths to VulnerableFunc.
// PathA and PathB each call VulnerableFunc in one hop from main.
// TDD case 7: determinism — with two equal-length paths the engine must always
// pick the same one (lexicographic stable sort), verified across N runs.
package main

import (
	"fmt"
	"os"

	"example.com/vulnlib"
)

// PathA calls VulnerableFunc directly — one hop.
func PathA() string {
	return vulnlib.VulnerableFunc()
}

// PathB also calls VulnerableFunc directly — same hop count as PathA.
func PathB() string {
	return vulnlib.VulnerableFunc()
}

func main() {
	// Both paths are exercised so neither is dead-code-eliminated.
	if len(os.Args) > 1 {
		fmt.Println(PathA())
	} else {
		fmt.Println(PathB())
	}
}
