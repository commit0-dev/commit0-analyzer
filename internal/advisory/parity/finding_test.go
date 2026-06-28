package parity

import "testing"

func TestSameVulnByAliasIntersection(t *testing.T) {
	a := Finding{VulnID: "GO-2024-0001", Aliases: []string{"CVE-2024-1111"}, Package: "github.com/foo/bar"}
	b := Finding{VulnID: "CVE-2024-1111", Package: "github.com/foo/bar"}
	if !sameVuln(a, b) {
		t.Error("findings sharing CVE alias on same package should match")
	}
}

func TestSameVulnRequiresSamePackageWhenBothNamed(t *testing.T) {
	a := Finding{VulnID: "CVE-1", Package: "pkg-a"}
	b := Finding{VulnID: "CVE-1", Package: "pkg-b"}
	if sameVuln(a, b) {
		t.Error("same CVE on different packages must not match")
	}
}

func TestSameVulnLoosensWhenPackageMissing(t *testing.T) {
	a := Finding{VulnID: "CVE-1", Package: "pkg-a"}
	b := Finding{VulnID: "CVE-1"} // no package reported
	if !sameVuln(a, b) {
		t.Error("identifier match should hold when a side omits the package")
	}
}

func TestSameVulnNoSharedID(t *testing.T) {
	a := Finding{VulnID: "CVE-1", Package: "p"}
	b := Finding{VulnID: "CVE-2", Package: "p"}
	if sameVuln(a, b) {
		t.Error("different vulns on same package must not match")
	}
}

func TestNormalizeIDCaseInsensitive(t *testing.T) {
	a := Finding{VulnID: "cve-2024-1"}
	b := Finding{VulnID: "CVE-2024-1"}
	if !identifiersIntersect(a.identifiers(), b.identifiers()) {
		t.Error("identifier comparison must be case-insensitive")
	}
}

func TestReachabilityHelpers(t *testing.T) {
	if !(Finding{Reachability: reachSymbol}).isReachable() {
		t.Error("symbol must be reachable")
	}
	if !(Finding{Reachability: reachPackage}).isReachable() {
		t.Error("package must be reachable")
	}
	if (Finding{Reachability: reachUnknown}).isReachable() {
		t.Error("unknown must not be reachable")
	}
	if !(Finding{Reachability: reachNotReachable}).isNotReachable() {
		t.Error("not_reachable must report isNotReachable")
	}
	if (Finding{Reachability: reachUnknown}).isNotReachable() {
		t.Error("unknown must not report isNotReachable (unknown != safe)")
	}
}
