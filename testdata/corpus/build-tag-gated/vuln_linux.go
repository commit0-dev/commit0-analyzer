//go:build linux

// This file only compiles on linux. On any other GOOS the call to
// VulnerableFunc is excluded from the build graph, so the engine cannot
// produce a static call path. The correct result on non-linux runners is
// UNKNOWN (build-config mismatch → cannot prove NOT_REACHABLE).
package main

import vulnlib "example.com/corpusvulnlib"

// linuxVulnEntry calls VulnerableFunc. Only included on GOOS=linux.
func linuxVulnEntry() string {
	return vulnlib.VulnerableFunc()
}
