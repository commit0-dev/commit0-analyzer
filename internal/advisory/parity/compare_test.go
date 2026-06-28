package parity

import "testing"

// loadCompareInputs parses the commit0-analyzer + osv-scanner fixtures used by the
// comparison tests.
func loadCompareInputs(t *testing.T) (commit0Analyzer, osv []Finding) {
	t.Helper()
	var err error
	if commit0Analyzer, err = ParseCommit0(readFixture(t, "commit0.json")); err != nil {
		t.Fatalf("parse commit0-analyzer: %v", err)
	}
	if osv, err = ParseOSVScanner(readFixture(t, "osv-scanner.json")); err != nil {
		t.Fatalf("parse osv: %v", err)
	}
	return commit0Analyzer, osv
}

func TestCompareClassifies(t *testing.T) {
	commit0Analyzer, osv := loadCompareInputs(t)
	res := Compare("go-fixture", ToolOSVScanner, commit0Analyzer, osv)
	s := Summarize(res)

	if s.Shared != 1 {
		t.Errorf("Shared = %d, want 1", s.Shared)
	}
	if s.SuppressedSound != 1 {
		t.Errorf("SuppressedSound = %d, want 1", s.SuppressedSound)
	}
	if s.FalseNegatives != 1 {
		t.Errorf("FalseNegatives = %d, want 1 (CVE-2024-9999 only-osv)", s.FalseNegatives)
	}
	if s.Commit0Unique != 1 {
		t.Errorf("Commit0Unique = %d, want 1 (GO-2024-0003)", s.Commit0Unique)
	}
	if s.UnknownSurfaced != 0 {
		t.Errorf("UnknownSurfaced = %d, want 0", s.UnknownSurfaced)
	}
}

func TestCompareMissIsNotLaunderedToSuppression(t *testing.T) {
	// The cardinal rule: a comparator finding commit0-analyzer has no record of is a MISS,
	// never a sound suppression. Only a proven NOT_REACHABLE commit0-analyzer record may be
	// classified as suppressed.
	commit0Analyzer, osv := loadCompareInputs(t)
	res := Compare("go-fixture", ToolOSVScanner, commit0Analyzer, osv)

	var miss *Delta
	for i := range res.Deltas {
		if res.Deltas[i].VulnID == "CVE-2024-9999" {
			miss = &res.Deltas[i]
		}
	}
	if miss == nil {
		t.Fatal("expected a delta for CVE-2024-9999")
	}
	if miss.Kind != DeltaMiss {
		t.Fatalf("CVE-2024-9999 classified as %q, want %q (must not be laundered to suppression)", miss.Kind, DeltaMiss)
	}
}

func TestCompareSuppressionRequiresProvenNotReachable(t *testing.T) {
	// An UNKNOWN/incomplete commit0-analyzer record must NOT be classified as a sound
	// suppression — it is surfaced, not proven safe.
	commit0Analyzer := []Finding{
		{Tool: ToolCommit0, VulnID: "CVE-2024-3333", Package: "p", Reachability: reachUnknown, Incomplete: true},
	}
	other := []Finding{{Tool: ToolGrype, VulnID: "CVE-2024-3333", Package: "p"}}
	res := Compare("c", ToolGrype, commit0Analyzer, other)
	if len(res.Deltas) != 1 {
		t.Fatalf("want 1 delta, got %d", len(res.Deltas))
	}
	if res.Deltas[0].Kind != DeltaUnknownSurfaced {
		t.Fatalf("unknown commit0-analyzer record classified as %q, want %q", res.Deltas[0].Kind, DeltaUnknownSurfaced)
	}
}

func TestCompareIncompleteNotReachableIsNotSuppression(t *testing.T) {
	// A NOT_REACHABLE verdict from an INCOMPLETE analysis must NOT be classified
	// as a sound suppression: an incomplete analysis cannot prove unreachability.
	// This mirrors vex.MapStatus, which maps NOT_REACHABLE+incomplete to
	// under_investigation, never not_affected. The harness must be at least as
	// conservative as the product's own VEX guard.
	commit0Analyzer := []Finding{
		{Tool: ToolCommit0, VulnID: "CVE-2024-4444", Package: "p", Reachability: reachNotReachable, Incomplete: true},
	}
	other := []Finding{{Tool: ToolGrype, VulnID: "CVE-2024-4444", Package: "p"}}
	res := Compare("c", ToolGrype, commit0Analyzer, other)
	if len(res.Deltas) != 1 {
		t.Fatalf("want 1 delta, got %d", len(res.Deltas))
	}
	if res.Deltas[0].Kind != DeltaUnknownSurfaced {
		t.Fatalf("incomplete NOT_REACHABLE classified as %q, want %q (must not be a sound suppression)", res.Deltas[0].Kind, DeltaUnknownSurfaced)
	}
}

func TestCompareCompleteNotReachableIsSuppression(t *testing.T) {
	// The complement: a COMPLETE, proven NOT_REACHABLE verdict IS a sound
	// suppression — commit0-analyzer's differentiator, not a miss.
	commit0Analyzer := []Finding{
		{Tool: ToolCommit0, VulnID: "CVE-2024-5555", Package: "p", Reachability: reachNotReachable, Incomplete: false},
	}
	other := []Finding{{Tool: ToolGrype, VulnID: "CVE-2024-5555", Package: "p"}}
	res := Compare("c", ToolGrype, commit0Analyzer, other)
	if len(res.Deltas) != 1 {
		t.Fatalf("want 1 delta, got %d", len(res.Deltas))
	}
	if res.Deltas[0].Kind != DeltaSuppressedSound {
		t.Fatalf("complete NOT_REACHABLE classified as %q, want %q", res.Deltas[0].Kind, DeltaSuppressedSound)
	}
}

func TestCompareDeterministicOrder(t *testing.T) {
	commit0Analyzer, osv := loadCompareInputs(t)
	a := Compare("c", ToolOSVScanner, commit0Analyzer, osv)
	b := Compare("c", ToolOSVScanner, commit0Analyzer, osv)
	if len(a.Deltas) != len(b.Deltas) {
		t.Fatalf("delta counts differ: %d vs %d", len(a.Deltas), len(b.Deltas))
	}
	for i := range a.Deltas {
		if a.Deltas[i] != b.Deltas[i] {
			t.Fatalf("delta %d differs between runs: %+v vs %+v", i, a.Deltas[i], b.Deltas[i])
		}
	}
}

func TestFailClosed(t *testing.T) {
	if FailClosed(0) {
		t.Error("exit 0 must NOT be fail-closed (it is a silent clean)")
	}
	if !FailClosed(3) {
		t.Error("exit 3 must be fail-closed")
	}
	if !FailClosed(1) {
		t.Error("exit 1 (gate failure) must be fail-closed")
	}
}

func TestDeterministic(t *testing.T) {
	if !Deterministic([]byte("x"), []byte("x")) {
		t.Error("identical bytes must be deterministic")
	}
	if Deterministic([]byte("x"), []byte("y")) {
		t.Error("differing bytes must not be deterministic")
	}
}
