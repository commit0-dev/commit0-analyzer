package parity

import "testing"

func TestVEXForUnreachablePasses(t *testing.T) {
	// Every COMPLETE, proven NOT_REACHABLE finding must appear in the VEX doc as
	// not_affected — the empirical proof a reachability suppression flows through.
	anst, err := ParseAnst(readFixture(t, "anst.json"))
	if err != nil {
		t.Fatalf("parse anst: %v", err)
	}
	statuses, err := ParseAnstVEX(readFixture(t, "anst-openvex.json"))
	if err != nil {
		t.Fatalf("parse vex: %v", err)
	}
	ok, detail := VEXForUnreachable(anst, statuses)
	if !ok {
		t.Fatalf("VEXForUnreachable = false (%s); GO-2024-0002 is NOT_REACHABLE+not_affected", detail)
	}
}

func TestVEXForUnreachableFailsWhenStatusWrong(t *testing.T) {
	// A proven NOT_REACHABLE finding whose VEX status is anything but not_affected
	// is a hard failure: the suppression did not flow through to the VEX document.
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-1", Package: "p", Reachability: reachNotReachable},
	}
	statuses := map[string]string{"CVE-1": "under_investigation"}
	if ok, _ := VEXForUnreachable(anst, statuses); ok {
		t.Error("under_investigation for a NOT_REACHABLE finding must fail the VEX check")
	}
}

func TestVEXForUnreachableFailsWhenAbsent(t *testing.T) {
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-1", Package: "p", Reachability: reachNotReachable},
	}
	if ok, _ := VEXForUnreachable(anst, map[string]string{}); ok {
		t.Error("a NOT_REACHABLE finding absent from the VEX doc must fail the check")
	}
}

func TestVEXForUnreachableIgnoresIncompleteNotReachable(t *testing.T) {
	// An INCOMPLETE NOT_REACHABLE verdict is not a sound suppression, so it is not
	// expected to be not_affected (anst maps it to under_investigation). It must
	// not be cross-checked as if it were proven safe.
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-1", Package: "p", Reachability: reachNotReachable, Incomplete: true},
	}
	ok, _ := VEXForUnreachable(anst, map[string]string{"CVE-1": "under_investigation"})
	if !ok {
		t.Error("incomplete NOT_REACHABLE must not be required to be not_affected")
	}
}

func TestVEXForUnreachableNoFindingsIsHonestPass(t *testing.T) {
	ok, detail := VEXForUnreachable(nil, map[string]string{})
	if !ok {
		t.Errorf("no NOT_REACHABLE findings should be an honest pass, got %q", detail)
	}
}

func TestKEVTopTierPasses(t *testing.T) {
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-2021-44228", Package: "log4j-core", KEV: true, RiskTier: "critical"},
	}
	if ok, detail := KEVTopTier(anst, "CVE-2021-44228"); !ok {
		t.Errorf("KEVTopTier = false (%s); KEV-listed + critical should pass", detail)
	}
}

func TestKEVTopTierMatchesByAlias(t *testing.T) {
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, KEV: true, RiskTier: "critical"},
	}
	if ok, _ := KEVTopTier(anst, "CVE-2021-44228"); !ok {
		t.Error("KEVTopTier must match by alias")
	}
}

func TestKEVTopTierFailsWithoutFlag(t *testing.T) {
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-2021-44228", KEV: false, RiskTier: "critical"},
	}
	if ok, _ := KEVTopTier(anst, "CVE-2021-44228"); ok {
		t.Error("a KEV dependency without the KEV flag must fail")
	}
}

func TestKEVTopTierFailsWhenNotTopTier(t *testing.T) {
	anst := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-2021-44228", KEV: true, RiskTier: "high"},
	}
	if ok, _ := KEVTopTier(anst, "CVE-2021-44228"); ok {
		t.Error("a KEV dependency not in the top risk tier must fail")
	}
}

func TestKEVTopTierFailsWhenMissed(t *testing.T) {
	if ok, _ := KEVTopTier(nil, "CVE-2021-44228"); ok {
		t.Error("a KEV dependency anst never found must fail (it is a miss)")
	}
}
