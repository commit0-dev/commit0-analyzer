// Package main calls vulnlib.Helper which in turn calls VulnerableFunc.
// TDD case 3: SYMBOL_REACHABLE via 2+ hops — main → Helper → VulnerableFunc.
package main

import (
	"fmt"

	"example.com/vulnlib"
)

func main() {
	fmt.Println(vulnlib.Helper())
}
