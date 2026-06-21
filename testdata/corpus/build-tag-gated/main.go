// Package main is the build-tag-gated corpus fixture.
// The call to VulnerableFunc is isolated in vuln_linux.go which is gated by
// GOOS=linux. On a non-linux runner (darwin/windows) the file is excluded from
// the build, so the engine cannot trace a call path. The expected result is
// UNKNOWN (never NOT_REACHABLE) because the engine cannot prove absence.
//
// Adversarial fixture (a): build-tag / GOOS-gated reachable vuln.
// Expected: CORPUS-CVE-001 → UNKNOWN (not NOT_REACHABLE) on non-linux runners.
package main

import "fmt"

func main() {
	fmt.Println(safeEntry())
}

// safeEntry is always compiled and never calls VulnerableFunc.
func safeEntry() string {
	return "no vuln here on this platform"
}
