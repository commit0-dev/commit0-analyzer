// Package main uses vulnlib.SafeFunc so the package is imported and reachable,
// but the advisory has SymbolLevel=false (no named symbols).
// TDD case 6: PACKAGE_REACHABLE — advisory is package-level only.
package main

import (
	"fmt"

	"example.com/vulnlib"
)

func main() {
	fmt.Println(vulnlib.SafeFunc())
}
