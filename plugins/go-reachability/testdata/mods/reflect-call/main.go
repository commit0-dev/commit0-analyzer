// Package main calls VulnerableFunc via reflection so no static call-graph edge exists.
// TDD case 5: UNKNOWN — the engine must detect reflect.Value.Call and surface UNKNOWN,
// asserting that the fallback fired because there was no graph edge (not a found edge).
package main

import (
	"fmt"
	"reflect"

	"example.com/vulnlib"
)

func main() {
	// reflect.ValueOf grabs the function value; Call invokes it at runtime.
	// VTA/CHA produce no edge from main.main → vulnlib.VulnerableFunc here.
	fn := reflect.ValueOf(vulnlib.VulnerableFunc)
	result := fn.Call(nil)
	fmt.Println(result[0].String())
}
