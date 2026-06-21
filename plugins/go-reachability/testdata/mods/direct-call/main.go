// Package main is a fixture that directly calls the vulnerable function.
// TDD case 1: SYMBOL_REACHABLE — main → VulnerableFunc.
package main

import (
	"fmt"

	"example.com/vulnlib"
)

func main() {
	fmt.Println(vulnlib.VulnerableFunc())
}
