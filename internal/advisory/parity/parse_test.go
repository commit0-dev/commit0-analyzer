package parity

import (
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseCommit0(t *testing.T) {
	fs, err := ParseCommit0(readFixture(t, "commit0.json"))
	if err != nil {
		t.Fatalf("ParseCommit0: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	tests := []struct {
		id         string
		reach      string
		incomplete bool
		pkg        string
	}{
		{"GO-2024-0001", reachSymbol, false, "github.com/foo/bar"},
		{"GO-2024-0002", reachNotReachable, false, "github.com/foo/unreachable"},
		{"GO-2024-0003", reachUnknown, true, "github.com/foo/maybe"},
	}
	for i, want := range tests {
		got := fs[i]
		if got.Tool != ToolCommit0 {
			t.Errorf("finding %d: tool = %q, want %q", i, got.Tool, ToolCommit0)
		}
		if got.VulnID != want.id {
			t.Errorf("finding %d: id = %q, want %q", i, got.VulnID, want.id)
		}
		if got.Reachability != want.reach {
			t.Errorf("finding %d (%s): reach = %q, want %q", i, want.id, got.Reachability, want.reach)
		}
		if got.Incomplete != want.incomplete {
			t.Errorf("finding %d (%s): incomplete = %v, want %v", i, want.id, got.Incomplete, want.incomplete)
		}
		if got.Package != want.pkg {
			t.Errorf("finding %d (%s): pkg = %q, want %q", i, want.id, got.Package, want.pkg)
		}
	}
}

func TestParseCommit0UnknownConfidenceIsNotSafe(t *testing.T) {
	// An unrecognized confidence string must never be treated as not-reachable.
	if got := normalizeConfidence("CONFIDENCE_SOMETHING_NEW"); got != reachUnknown {
		t.Fatalf("unknown confidence normalized to %q, want %q (unknown != safe)", got, reachUnknown)
	}
}

// TestParseCommit0IncompleteSignals pins the real incompleteness signal commit0-analyzer emits:
// confidence == CONFIDENCE_UNKNOWN AND/OR properties["synthetic"] == "true".
// commit0-analyzer never emits a properties["incomplete"] key, so the harness must not depend
// on one (depending on a phantom key would silently classify every finding as
// complete and launder an incomplete NOT_REACHABLE into a sound suppression).
func TestParseCommit0IncompleteSignals(t *testing.T) {
	cases := []struct {
		name       string
		json       string
		incomplete bool
		reach      string
	}{
		{
			name:       "unknown confidence is incomplete",
			json:       `[{"advisory":{"id":"CVE-1"},"module":"p","confidence":"CONFIDENCE_UNKNOWN"}]`,
			incomplete: true,
			reach:      reachUnknown,
		},
		{
			name:       "synthetic crash marker is incomplete even without unknown wording",
			json:       `[{"advisory":{"id":"CVE-2"},"module":"plugin","confidence":"CONFIDENCE_SYMBOL_REACHABLE","properties":{"synthetic":"true","cause":"crash"}}]`,
			incomplete: true,
			reach:      reachSymbol,
		},
		{
			name:       "complete not-reachable is not incomplete",
			json:       `[{"advisory":{"id":"CVE-3"},"module":"p","confidence":"CONFIDENCE_NOT_REACHABLE"}]`,
			incomplete: false,
			reach:      reachNotReachable,
		},
		{
			name:       "complete reachable without phantom keys is not incomplete",
			json:       `[{"advisory":{"id":"CVE-4"},"module":"p","confidence":"CONFIDENCE_PACKAGE_REACHABLE","properties":{"risk_tier":"high"}}]`,
			incomplete: false,
			reach:      reachPackage,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := ParseCommit0([]byte(tc.json))
			if err != nil {
				t.Fatalf("ParseCommit0: %v", err)
			}
			if len(fs) != 1 {
				t.Fatalf("want 1 finding, got %d", len(fs))
			}
			if fs[0].Incomplete != tc.incomplete {
				t.Errorf("incomplete = %v, want %v", fs[0].Incomplete, tc.incomplete)
			}
			if fs[0].Reachability != tc.reach {
				t.Errorf("reach = %q, want %q", fs[0].Reachability, tc.reach)
			}
		})
	}
}

// TestParseCommit0KEVAndTier verifies that the KEV flag and risk tier are read from
// the real properties commit0-analyzer stamps (properties["kev"], properties["risk_tier"]),
// so the harness can assert the KEV non-negotiable.
func TestParseCommit0KEVAndTier(t *testing.T) {
	const data = `[{"advisory":{"id":"CVE-2021-44228"},"module":"org.apache.logging.log4j:log4j-core","confidence":"CONFIDENCE_PACKAGE_REACHABLE","properties":{"kev":"true","risk_tier":"critical","risk_score":"99.0"}}]`
	fs, err := ParseCommit0([]byte(data))
	if err != nil {
		t.Fatalf("ParseCommit0: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !fs[0].KEV {
		t.Error("KEV flag not read from properties[\"kev\"]")
	}
	if fs[0].RiskTier != "critical" {
		t.Errorf("RiskTier = %q, want %q", fs[0].RiskTier, "critical")
	}
}

func TestParseCommit0VEX(t *testing.T) {
	statuses, err := ParseCommit0VEX(readFixture(t, "commit0-openvex.json"))
	if err != nil {
		t.Fatalf("ParseCommit0VEX: %v", err)
	}
	// Status is indexed by both the primary id and every alias (normalized).
	if got := statuses["GO-2024-0002"]; got != "not_affected" {
		t.Errorf("GO-2024-0002 status = %q, want not_affected", got)
	}
	if got := statuses["CVE-2024-2222"]; got != "not_affected" {
		t.Errorf("alias CVE-2024-2222 status = %q, want not_affected", got)
	}
	if got := statuses["GO-2024-0001"]; got != "affected" {
		t.Errorf("GO-2024-0001 status = %q, want affected", got)
	}
	if got := statuses["GO-2024-0003"]; got != "under_investigation" {
		t.Errorf("GO-2024-0003 status = %q, want under_investigation", got)
	}
}

func TestParseCommit0VEXRejectsGarbage(t *testing.T) {
	if _, err := ParseCommit0VEX([]byte("not json")); err == nil {
		t.Error("ParseCommit0VEX accepted garbage input")
	}
}

func TestParseOSVScanner(t *testing.T) {
	fs, err := ParseOSVScanner(readFixture(t, "osv-scanner.json"))
	if err != nil {
		t.Fatalf("ParseOSVScanner: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	if fs[0].VulnID != "GHSA-aaaa-bbbb-cccc" || fs[0].Package != "github.com/foo/bar" {
		t.Errorf("first osv finding = %+v", fs[0])
	}
	if fs[0].Tool != ToolOSVScanner {
		t.Errorf("tool = %q, want %q", fs[0].Tool, ToolOSVScanner)
	}
}

func TestParseGrype(t *testing.T) {
	fs, err := ParseGrype(readFixture(t, "grype.json"))
	if err != nil {
		t.Fatalf("ParseGrype: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].VulnID != "CVE-2024-1111" {
		t.Errorf("grype id = %q", fs[0].VulnID)
	}
	if len(fs[0].Aliases) != 1 || fs[0].Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("grype aliases = %v", fs[0].Aliases)
	}
	if fs[1].VulnID != "CVE-2021-44228" {
		t.Errorf("grype[1] id = %q", fs[1].VulnID)
	}
}

func TestParseTrivy(t *testing.T) {
	fs, err := ParseTrivy(readFixture(t, "trivy.json"))
	if err != nil {
		t.Fatalf("ParseTrivy: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].VulnID != "CVE-2024-1111" || fs[0].Package != "github.com/foo/bar" {
		t.Errorf("trivy[0] = %+v", fs[0])
	}
}

func TestParseGovulncheckDedupAndReachable(t *testing.T) {
	fs, err := ParseGovulncheck(readFixture(t, "govulncheck.json"))
	if err != nil {
		t.Fatalf("ParseGovulncheck: %v", err)
	}
	// Two findings share one OSV id → deduped to one.
	if len(fs) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(fs))
	}
	if fs[0].VulnID != "GO-2024-0001" {
		t.Errorf("govulncheck id = %q", fs[0].VulnID)
	}
	if fs[0].Reachability != reachSymbol {
		t.Errorf("govulncheck reach = %q, want %q (call-proven)", fs[0].Reachability, reachSymbol)
	}
	if fs[0].Package != "github.com/foo/bar" {
		t.Errorf("govulncheck pkg = %q", fs[0].Package)
	}
}

func TestParsersRejectGarbage(t *testing.T) {
	garbage := []byte("not json")
	for _, fn := range []struct {
		name string
		p    func([]byte) ([]Finding, error)
	}{
		{"commit0-analyzer", ParseCommit0},
		{"osv-scanner", ParseOSVScanner},
		{"grype", ParseGrype},
		{"trivy", ParseTrivy},
		{"govulncheck", ParseGovulncheck},
	} {
		if _, err := fn.p(garbage); err == nil {
			t.Errorf("%s parser accepted garbage input", fn.name)
		}
	}
}
