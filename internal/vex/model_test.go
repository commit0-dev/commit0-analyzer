package vex

import (
	"testing"
	"time"
)

// fixedTime is the injected timestamp used across VEX tests for reproducibility.
var fixedTime = time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

// TestMapStatus_CardinalSin is the phase's cardinal-sin guard: an UNKNOWN or
// incomplete verdict must NEVER map to not_affected. Only a complete,
// proven NOT_REACHABLE verdict may yield not_affected.
func TestMapStatus_CardinalSin(t *testing.T) {
	cases := []struct {
		name          string
		reach         Reachability
		incomplete    bool
		wantStatus    Status
		wantJustified Justification
	}{
		{"unknown is under_investigation", ReachabilityUnknown, false, StatusUnderInvestigation, ""},
		{"unknown incomplete is under_investigation", ReachabilityUnknown, true, StatusUnderInvestigation, ""},
		{"package reachable is affected", ReachabilityPackageReachable, false, StatusAffected, ""},
		{"symbol reachable is affected", ReachabilitySymbolReachable, false, StatusAffected, ""},
		{"reachable incomplete stays affected", ReachabilitySymbolReachable, true, StatusAffected, ""},
		{
			"not reachable complete is not_affected",
			ReachabilityNotReachable, false, StatusNotAffected, JustificationVulnerableCodeNotInExecutePath,
		},
		{
			"not reachable INCOMPLETE is under_investigation (never not_affected)",
			ReachabilityNotReachable, true, StatusUnderInvestigation, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotJust := MapStatus(tc.reach, tc.incomplete)
			if gotStatus != tc.wantStatus {
				t.Fatalf("status: got %q want %q", gotStatus, tc.wantStatus)
			}
			if gotJust != tc.wantJustified {
				t.Fatalf("justification: got %q want %q", gotJust, tc.wantJustified)
			}
			// Hard invariant: not_affected requires a complete NOT_REACHABLE proof.
			if gotStatus == StatusNotAffected {
				if tc.incomplete {
					t.Fatal("cardinal sin: not_affected emitted for an incomplete analysis")
				}
				if tc.reach != ReachabilityNotReachable {
					t.Fatal("cardinal sin: not_affected emitted without a NOT_REACHABLE verdict")
				}
			}
		})
	}
}

func TestPackageURL(t *testing.T) {
	cases := []struct {
		eco, name, version, want string
	}{
		{"Go", "golang.org/x/net", "v0.17.0", "pkg:golang/golang.org/x/net@v0.17.0"},
		{"Go", "golang.org/x/net", "", "pkg:golang/golang.org/x/net"},
		{"npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"crates.io", "openssl", "0.10.0", "pkg:cargo/openssl@0.10.0"},
		{"PyPI", "requests", "2.0.0", "pkg:pypi/requests@2.0.0"},
		{"Maven", "org.springframework:spring-core", "5.3.0", "pkg:maven/org.springframework/spring-core@5.3.0"},
		{"NuGet", "Newtonsoft.Json", "12.0.0", "pkg:nuget/Newtonsoft.Json@12.0.0"},
		{"Packagist", "monolog/monolog", "2.0.0", "pkg:composer/monolog/monolog@2.0.0"},
		{"RubyGems", "rails", "6.0.0", "pkg:gem/rails@6.0.0"},
		{"Hex", "phoenix", "1.6.0", "pkg:hex/phoenix@1.6.0"},
		{"Pub", "http", "0.13.0", "pkg:pub/http@0.13.0"},
		{"SwiftURL", "Alamofire", "5.0.0", "pkg:swift/Alamofire@5.0.0"},
		{"WeirdUnknown", "thing", "1.0.0", ""},
		{"Go", "", "v1.0.0", ""},
	}
	for _, tc := range cases {
		got := PackageURL(tc.eco, tc.name, tc.version)
		if got != tc.want {
			t.Errorf("PackageURL(%q,%q,%q)=%q want %q", tc.eco, tc.name, tc.version, got, tc.want)
		}
	}
}

func TestBuildDocument_SkipsEmptyVulnAndSorts(t *testing.T) {
	inputs := []StatementInput{
		{VulnID: "CVE-2024-0002", Ecosystem: "npm", PackageName: "lodash", Reachability: ReachabilityUnknown},
		{VulnID: "", Ecosystem: "Go", PackageName: "ignored", Reachability: ReachabilityPackageReachable},
		{VulnID: "CVE-2024-0001", Ecosystem: "Go", PackageName: "golang.org/x/net", Reachability: ReachabilityNotReachable},
	}
	doc := BuildDocument(fixedTime, inputs)
	if len(doc.Statements) != 2 {
		t.Fatalf("want 2 statements (empty vuln skipped), got %d", len(doc.Statements))
	}
	if doc.Statements[0].Vuln.ID != "CVE-2024-0001" || doc.Statements[1].Vuln.ID != "CVE-2024-0002" {
		t.Fatalf("statements not sorted by vuln id: %+v", doc.Statements)
	}
	if doc.Statements[0].Status != StatusNotAffected {
		t.Fatalf("want not_affected for NOT_REACHABLE, got %q", doc.Statements[0].Status)
	}
	if doc.Statements[1].Status != StatusUnderInvestigation {
		t.Fatalf("want under_investigation for UNKNOWN, got %q", doc.Statements[1].Status)
	}
}

func TestBuildDocument_AffectedHasActionStatement(t *testing.T) {
	doc := BuildDocument(fixedTime, []StatementInput{
		{VulnID: "CVE-2024-0003", Ecosystem: "Go", PackageName: "golang.org/x/net", FixedVersion: "v0.17.0", Reachability: ReachabilitySymbolReachable},
		{VulnID: "CVE-2024-0004", Ecosystem: "Go", PackageName: "example.com/x", Reachability: ReachabilityPackageReachable},
	})
	if doc.Statements[0].ActionStatement == "" {
		t.Fatal("affected statement with a fix must carry an action statement")
	}
	if doc.Statements[1].ActionStatement == "" {
		t.Fatal("affected statement without a fix must still carry a non-empty action statement (OpenVEX requirement)")
	}
}
