package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// bundleDir is the testdata directory of OSV-format GHSA records, laid out per
// ecosystem (testdata/ghsa/bundle/<ecosystem>/*.json) exactly like the
// OSVBundleSource cache.
func bundleDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "ghsa", "bundle")
}

// findAdvisory returns the advisory with the given ID, or nil.
func findAdvisory(advs []Advisory, id string) *Advisory {
	for i := range advs {
		if advs[i].ID == id {
			return &advs[i]
		}
	}
	return nil
}

func TestGHSASource_BundleQuery(t *testing.T) {
	// GraphQL disabled (no token, no URL): only the offline bundle floor is used.
	s := NewGHSASource(bundleDir(t))

	advs, err := s.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/foo/bar"}, "v1.0.0")
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	adv := findAdvisory(advs, "GHSA-aaaa-bbbb-cccc")
	if adv == nil {
		t.Fatalf("expected GHSA-aaaa-bbbb-cccc in results, got %d advisories", len(advs))
	}

	// CVE alias populated.
	if !containsString(adv.Aliases, "CVE-2024-0001") {
		t.Errorf("expected CVE-2024-0001 alias, got %v", adv.Aliases)
	}
	// Source attribution is GHSA.
	if !containsString(adv.Sources, SourceGHSA) {
		t.Errorf("expected %q in Sources, got %v", SourceGHSA, adv.Sources)
	}
	// CVSS vector parsed (via P0 ParseCVSS) with a computed v3.1 base score.
	if len(adv.CVSS) == 0 {
		t.Fatalf("expected at least one CVSS metric")
	}
	if adv.CVSS[0].Version != "3.1" {
		t.Errorf("expected CVSS version 3.1, got %q", adv.CVSS[0].Version)
	}
	if adv.CVSS[0].BaseScore < 9.0 {
		t.Errorf("expected critical base score >= 9.0, got %v", adv.CVSS[0].BaseScore)
	}
	if adv.CVSS[0].Source != SourceGHSA {
		t.Errorf("expected CVSS metric source %q, got %q", SourceGHSA, adv.CVSS[0].Source)
	}
	// Severity derived (never downgraded) → Critical.
	if adv.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", adv.Severity)
	}
	// CWEs captured and normalized (sorted ascending by number).
	wantCWEs := []string{"CWE-79", "CWE-89"}
	if len(adv.CWEs) != len(wantCWEs) {
		t.Fatalf("expected CWEs %v, got %v", wantCWEs, adv.CWEs)
	}
	for i, c := range wantCWEs {
		if adv.CWEs[i] != c {
			t.Errorf("CWE[%d]: expected %q, got %q", i, c, adv.CWEs[i])
		}
	}

	// Withdrawn advisory must be filtered out of the results.
	if findAdvisory(advs, "GHSA-with-draw-nnnn") != nil {
		t.Errorf("withdrawn advisory GHSA-with-draw-nnnn must be filtered from results")
	}
}

func TestGHSASource_UnknownEcosystem(t *testing.T) {
	s := NewGHSASource(bundleDir(t))
	advs, err := s.Query(context.Background(),
		Package{Ecosystem: "cocoapods", Name: "AFNetworking"}, "1.0.0")
	if err != nil {
		t.Fatalf("unknown ecosystem must not error, got %v", err)
	}
	if advs != nil {
		t.Errorf("unknown ecosystem must return nil advisories, got %v", advs)
	}
}

func TestGHSASource_UnparseableRangeIncomplete(t *testing.T) {
	// A GIT-range-only record with no versions[] enumeration is undecidable: it
	// must be forwarded with Incomplete=true, never silently dropped.
	s := NewGHSASource(bundleDir(t))
	advs, err := s.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/foo/gitonly"}, "v1.0.0")
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	adv := findAdvisory(advs, "GHSA-git-only-zzzz")
	if adv == nil {
		t.Fatalf("expected GHSA-git-only-zzzz forwarded, got %d advisories", len(advs))
	}
	if !adv.Incomplete {
		t.Errorf("expected Incomplete=true for undecidable GIT-only range")
	}
}

func TestGHSASource_GraphQLQuery(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "ghsa", "graphql", "securityVulnerabilities.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	// cacheDir points at an empty temp dir so the bundle floor contributes nothing
	// and the result is GraphQL-only.
	s := NewGHSASource(t.TempDir(),
		WithGHSAGraphQLURL(srv.URL),
		WithGHSAToken("test-token"))

	advs, err := s.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/foo/baz"}, "v1.2.0")
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("expected Bearer token auth header, got %q", gotAuth)
	}

	adv := findAdvisory(advs, "GHSA-dddd-eeee-ffff")
	if adv == nil {
		t.Fatalf("expected GHSA-dddd-eeee-ffff from GraphQL, got %d advisories", len(advs))
	}
	if !containsString(adv.Aliases, "CVE-2024-9999") {
		t.Errorf("expected CVE-2024-9999 alias, got %v", adv.Aliases)
	}
	if len(adv.CVSS) == 0 || adv.CVSS[0].Vector == "" {
		t.Errorf("expected parsed CVSS vector, got %+v", adv.CVSS)
	}
	if !containsString(adv.CWEs, "CWE-79") {
		t.Errorf("expected CWE-79, got %v", adv.CWEs)
	}
	if adv.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical from score 9.8, got %v", adv.Severity)
	}

	// Withdrawn GraphQL advisory must be filtered.
	if findAdvisory(advs, "GHSA-with-drawn-gql") != nil {
		t.Errorf("withdrawn GraphQL advisory must be filtered from results")
	}
}

func TestGHSASource_GraphQLErrorIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer srv.Close()

	// Bundle floor present + GraphQL requested-and-failing → non-nil error
	// (drives incomplete) while bundle advisories are still returned.
	s := NewGHSASource(bundleDir(t),
		WithGHSAGraphQLURL(srv.URL),
		WithGHSAToken("test-token"))

	advs, err := s.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/foo/bar"}, "v1.0.0")
	if err == nil {
		t.Fatalf("expected non-nil error from failing GraphQL call")
	}
	// Bundle advisory still returned despite GraphQL failure.
	if findAdvisory(advs, "GHSA-aaaa-bbbb-cccc") == nil {
		t.Errorf("bundle advisory must still be returned when GraphQL fails")
	}
}

func TestGHSASource_TokenAbsentSkipsGraphQL(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"securityVulnerabilities":{"pageInfo":{"hasNextPage":false},"nodes":[]}}}`))
	}))
	defer srv.Close()

	// No token anywhere: GraphQL layer must be skipped (degrade, not fail) and the
	// bundle floor must still return results.
	t.Setenv("GITHUB_TOKEN", "")
	s := NewGHSASource(bundleDir(t), WithGHSAGraphQLURL(srv.URL))

	advs, err := s.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/foo/bar"}, "v1.0.0")
	if err != nil {
		t.Fatalf("token-absent path must not error, got %v", err)
	}
	if hits != 0 {
		t.Errorf("GraphQL must not be called without a token, got %d hits", hits)
	}
	if findAdvisory(advs, "GHSA-aaaa-bbbb-cccc") == nil {
		t.Errorf("bundle advisory must still be returned when GraphQL is skipped")
	}
}

func TestParseGHSAVersionRange(t *testing.T) {
	tests := []struct {
		in   string
		want VersionRange
		ok   bool
	}{
		{">= 1.0.0, < 1.5.0", VersionRange{Introduced: "1.0.0", Fixed: "1.5.0"}, true},
		{"< 0.1.11", VersionRange{Fixed: "0.1.11"}, true},
		{"<= 1.0.8", VersionRange{LastAffected: "1.0.8"}, true},
		{">= 4.3.0", VersionRange{Introduced: "4.3.0"}, true},
		{"= 0.2.0", VersionRange{Introduced: "0.2.0", LastAffected: "0.2.0"}, true},
		{"", VersionRange{}, false},
		{"~> 1.2", VersionRange{}, false},
		{"> 1.0.0", VersionRange{}, false},
	}
	for _, tt := range tests {
		got, ok := parseGHSAVersionRange(tt.in)
		if ok != tt.ok {
			t.Errorf("parseGHSAVersionRange(%q): ok=%v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("parseGHSAVersionRange(%q): got %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestToGHSAEcosystem(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{EcosystemGo, "GO", true},
		{EcosystemNPM, "NPM", true},
		{EcosystemPyPI, "PIP", true},
		{EcosystemMaven, "MAVEN", true},
		{EcosystemNuGet, "NUGET", true},
		{EcosystemPackagist, "COMPOSER", true},
		{EcosystemCratesIO, "RUST", true},
		{EcosystemRubyGems, "RUBYGEMS", true},
		{EcosystemPub, "PUB", true},
		{EcosystemHex, "ERLANG", true},
		{EcosystemSwiftURL, "SWIFT", true},
		{"cocoapods", "", false},
	}
	for _, tt := range tests {
		got, ok := toGHSAEcosystem(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("toGHSAEcosystem(%q) = (%q,%v), want (%q,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
