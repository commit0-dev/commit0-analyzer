// Package main imports vulnlib but only calls SafeFunc, never VulnerableFunc.
// TDD case 2: NOT_REACHABLE — VulnerableFunc is imported but not called.
package main

import (
	"fmt"

	"example.com/vulnlib"
)

func main() {
	fmt.Println(vulnlib.SafeFunc())
}
