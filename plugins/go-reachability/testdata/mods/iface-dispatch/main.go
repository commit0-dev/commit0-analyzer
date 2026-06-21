// Package main calls VulnerableFunc via a statically-typed interface dispatch.
// VulnDoer is allocated in-program so VTA resolves the call.
// TDD case 4: SYMBOL_REACHABLE (NOT UNKNOWN) — VTA must follow the concrete type.
package main

import (
	"fmt"

	"example.com/vulnlib"
)

func run(d vulnlib.Doer) string {
	return d.Do()
}

func main() {
	// Allocate VulnDoer in-program; VTA sees the concrete type and resolves Do().
	fmt.Println(run(vulnlib.VulnDoer{}))
}
