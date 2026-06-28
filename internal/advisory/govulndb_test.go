package advisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFixture reads a testdata OSV JSON file by name.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err, "fixture %s missing", name)
	return data
}

// TestParseOSV_SymbolLevel verifies that a Go advisory OSV record with non-empty
// imports[].symbols parses into an Advisory with SymbolLevel=true and the correct
// symbol list.
func TestParseOSV_SymbolLevel(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	assert.Equal(t, "GO-2024-0001", adv.ID)
	assert.Equal(t, "github.com/example/vulnpkg", adv.Module)
	assert.True(t, adv.SymbolLevel, "should be symbol-level when imports have symbols")

	// Expect symbols from both import paths aggregated.
	symNames := make(map[string]bool)
	for _, s := range adv.Symbols {
		symNames[s.Package+"."+s.Name] = true
	}
	assert.True(t, symNames["github.com/example/vulnpkg.Parse"], "Parse should be present")
	assert.True(t, symNames["github.com/example/vulnpkg.Parser.ParseAll"], "Parser.ParseAll should be present")
	assert.True(t, symNames["github.com/example/vulnpkg/internal.internalHelper"], "internalHelper should be present")

	// Aliases must be propagated.
	assert.Contains(t, adv.Aliases, "CVE-2024-99001")
	assert.Contains(t, adv.Aliases, "GHSA-xxxx-yyyy-0001")

	// Source attribution.
	assert.Contains(t, adv.Sources, SourceGoVulnDB)
}

// TestParseOSV_PackageLevel verifies that a Go advisory with empty symbols lists
// parses with SymbolLevel=false.
func TestParseOSV_PackageLevel(t *testing.T) {
	data := loadFixture(t, "GO-2024-0002.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	assert.Equal(t, "GO-2024-0002", adv.ID)
	assert.False(t, adv.SymbolLevel, "should be package-level when no symbols")
	assert.Empty(t, adv.Symbols)
}

// TestVersionRangeFiltering_AffectedVersion verifies that a version within the
// affected range is matched.
func TestVersionRangeFiltering_AffectedVersion(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// v1.0.0 is in [0, 1.2.3) — should be affected.
	assert.True(t, adv.AffectsVersion("v1.0.0"), "v1.0.0 should be affected (in range [0,1.2.3))")
}

// TestVersionRangeFiltering_FixedVersion verifies that a version at or past the
// fixed boundary is NOT matched.
func TestVersionRangeFiltering_FixedVersion(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// v1.2.3 is the fixed version — should NOT be affected.
	assert.False(t, adv.AffectsVersion("v1.2.3"), "v1.2.3 is fixed — should not be affected")
	// v2.0.0 is well past the fix — should NOT be affected.
	assert.False(t, adv.AffectsVersion("v2.0.0"), "v2.0.0 should not be affected")
}

// TestVersionRangeFiltering_IntroducedVersion verifies version-range filtering
// with a non-zero introduced boundary.
func TestVersionRangeFiltering_IntroducedVersion(t *testing.T) {
	data := loadFixture(t, "GO-2024-0003.json")
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// v0.9.0 is before introduced — should NOT be affected.
	assert.False(t, adv.AffectsVersion("v0.9.0"), "v0.9.0 is before introduced v1.0.0")
	// v1.2.0 is in [1.0.0, 1.5.0) — should be affected.
	assert.True(t, adv.AffectsVersion("v1.2.0"), "v1.2.0 should be affected")
	// v1.5.0 is the fixed version — should NOT be affected.
	assert.False(t, adv.AffectsVersion("v1.5.0"), "v1.5.0 is fixed")
}

// TestGoVulnDBClient_Query exercises the client using an entirely local (offline)
// directory of OSV JSON files — no network calls.
func TestGoVulnDBClient_Query(t *testing.T) {
	// Build a small in-memory DB directory from our fixtures.
	dbDir := t.TempDir()
	for _, name := range []string{"GO-2024-0001.json", "GO-2024-0002.json", "GO-2024-0003.json"} {
		data := loadFixture(t, name)
		err := os.WriteFile(filepath.Join(dbDir, name), data, 0o644)
		require.NoError(t, err)
	}

	client := &goVulnDBClient{dbDir: dbDir}
	ctx := context.Background()

	// Query for github.com/example/vulnpkg at v1.0.0 — expect GO-2024-0001.
	advisories, err := client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advisories, 1)
	assert.Equal(t, "GO-2024-0001", advisories[0].ID)
	assert.True(t, advisories[0].SymbolLevel)

	// Query for github.com/example/vulnpkg at fixed version — expect nothing.
	advisories, err = client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.2.3")
	require.NoError(t, err)
	assert.Empty(t, advisories)

	// Query for github.com/example/pkgonly at v1.0.0 — expect GO-2024-0002, package-level.
	advisories, err = client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkgonly"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advisories, 1)
	assert.Equal(t, "GO-2024-0002", advisories[0].ID)
	assert.False(t, advisories[0].SymbolLevel)

	// Query for a module with no advisories.
	advisories, err = client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/safe"}, "v1.0.0")
	require.NoError(t, err)
	assert.Empty(t, advisories)
}

// TestParseOSV_WithdrawnTimestamp verifies that parseOSVRecord surfaces the
// withdrawn timestamp on the Advisory when the OSV record carries a "withdrawn" field.
func TestParseOSV_WithdrawnTimestamp(t *testing.T) {
	data := loadFixture(t, "GO-2025-3408.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	assert.Equal(t, "GO-2025-3408", adv.ID)
	// The withdrawn timestamp must be propagated so the Query-level skip is
	// clean and testable — callers can inspect Withdrawn to understand why an
	// advisory was excluded.
	assert.Equal(t, "2025-02-05T23:01:18Z", adv.Withdrawn,
		"Withdrawn timestamp must be propagated from OSV record")
}

// TestGoVulnDBClient_Query_WithdrawnExcluded proves that a withdrawn advisory is
// excluded from Query results even when its version range and symbols would
// otherwise match the queried module+version. This matches govulncheck behaviour
// and prevents false-positive CI failures.
func TestGoVulnDBClient_Query_WithdrawnExcluded(t *testing.T) {
	dbDir := t.TempDir()

	// GO-2025-3408 is withdrawn; it covers github.com/example/vulnpkg [0, 2.0.0).
	// v1.0.0 would normally match — but Query must exclude it.
	data := loadFixture(t, "GO-2025-3408.json")
	err := os.WriteFile(filepath.Join(dbDir, "GO-2025-3408.json"), data, 0o644)
	require.NoError(t, err)

	client := &goVulnDBClient{dbDir: dbDir}
	ctx := context.Background()

	advisories, err := client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	assert.Empty(t, advisories,
		"withdrawn advisory GO-2025-3408 must not appear in Query results")
}

// TestGoVulnDBClient_Query_NonWithdrawnStillReturned is a regression guard
// ensuring that the withdrawn-exclusion logic does not accidentally filter
// non-withdrawn advisories that cover the same module.
func TestGoVulnDBClient_Query_NonWithdrawnStillReturned(t *testing.T) {
	dbDir := t.TempDir()

	// GO-2024-0001 is NOT withdrawn; covers github.com/example/vulnpkg [0, 1.2.3).
	// GO-2025-3408 IS withdrawn; covers github.com/example/vulnpkg [0, 2.0.0).
	for _, name := range []string{"GO-2024-0001.json", "GO-2025-3408.json"} {
		data := loadFixture(t, name)
		err := os.WriteFile(filepath.Join(dbDir, name), data, 0o644)
		require.NoError(t, err)
	}

	client := &goVulnDBClient{dbDir: dbDir}
	ctx := context.Background()

	// v1.0.0 is in [0, 1.2.3) for GO-2024-0001 (active) and in [0, 2.0.0) for
	// GO-2025-3408 (withdrawn). Only the non-withdrawn one must be returned.
	advisories, err := client.Query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advisories, 1, "only the non-withdrawn advisory should be returned")
	assert.Equal(t, "GO-2024-0001", advisories[0].ID)
}

// TestExtractVersionRanges_MultiPair verifies that an events array with multiple
// introduced/fixed pairs produces one VersionRange per pair (none dropped).
// OSV semantics: [{introduced:0},{fixed:1.2.0},{introduced:2.0.0},{fixed:2.1.0}]
// → two disjoint ranges [0,1.2.0) and [2.0.0,2.1.0).
func TestExtractVersionRanges_MultiPair(t *testing.T) {
	events := []osvEvent{
		{Introduced: "0"},
		{Fixed: "1.2.0"},
		{Introduced: "2.0.0"},
		{Fixed: "2.1.0"},
	}
	got := extractVersionRanges(events)
	require.Len(t, got, 2, "two disjoint ranges expected")
	assert.Equal(t, VersionRange{Introduced: "", Fixed: "1.2.0"}, got[0])
	assert.Equal(t, VersionRange{Introduced: "2.0.0", Fixed: "2.1.0"}, got[1])
}

// TestExtractVersionRanges_LastAffectedInclusive verifies that a last_affected event
// closes the range with an inclusive upper bound.
func TestExtractVersionRanges_LastAffectedInclusive(t *testing.T) {
	events := []osvEvent{
		{Introduced: "0"},
		{LastAffected: "1.2.0"},
	}
	got := extractVersionRanges(events)
	require.Len(t, got, 1)
	assert.Equal(t, VersionRange{Introduced: "", LastAffected: "1.2.0"}, got[0])
}

// TestExtractVersionRanges_SinglePairUnchanged verifies that a simple single-pair
// events list still produces exactly one VersionRange (regression guard).
func TestExtractVersionRanges_SinglePairUnchanged(t *testing.T) {
	events := []osvEvent{
		{Introduced: "0"},
		{Fixed: "1.5.0"},
	}
	got := extractVersionRanges(events)
	require.Len(t, got, 1)
	assert.Equal(t, VersionRange{Introduced: "", Fixed: "1.5.0"}, got[0])
}

// TestExtractVersionRanges_OpenEnded verifies that an introduced event with no
// closing fixed/last_affected produces an open-ended range.
func TestExtractVersionRanges_OpenEnded(t *testing.T) {
	events := []osvEvent{
		{Introduced: "1.0.0"},
	}
	got := extractVersionRanges(events)
	require.Len(t, got, 1)
	assert.Equal(t, VersionRange{Introduced: "1.0.0"}, got[0])
}

// TestAffectsVersion_MultiPair_Go verifies that Advisory.AffectsVersion correctly
// handles two disjoint ranges for the Go ecosystem:
//   - 1.1.0 is in [0, 1.2.0)        → affected
//   - 1.5.0 is between the ranges    → NOT affected
//   - 2.0.5 is in [2.0.0, 2.1.0)    → affected
//   - 2.5.0 is past the upper range  → NOT affected
func TestAffectsVersion_MultiPair_Go(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemGo,
		VersionRanges: []VersionRange{
			{Introduced: "", Fixed: "1.2.0"},
			{Introduced: "2.0.0", Fixed: "2.1.0"},
		},
	}

	assert.True(t, adv.AffectsVersion("v1.1.0"), "v1.1.0 in [0,1.2.0) must be affected")
	assert.False(t, adv.AffectsVersion("v1.5.0"), "v1.5.0 between ranges must NOT be affected")
	assert.True(t, adv.AffectsVersion("v2.0.5"), "v2.0.5 in [2.0.0,2.1.0) must be affected")
	assert.False(t, adv.AffectsVersion("v2.5.0"), "v2.5.0 past upper range must NOT be affected")
}

// TestAffectsVersion_LastAffected_Go verifies inclusive upper bound semantics for the
// Go ecosystem: last_affected version itself IS affected, one patch above is NOT.
func TestAffectsVersion_LastAffected_Go(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemGo,
		VersionRanges: []VersionRange{
			{Introduced: "", LastAffected: "1.2.0"},
		},
	}

	assert.True(t, adv.AffectsVersion("v1.2.0"), "v1.2.0 (last_affected) must be affected (inclusive)")
	assert.False(t, adv.AffectsVersion("v1.2.1"), "v1.2.1 above last_affected must NOT be affected")
	assert.True(t, adv.AffectsVersion("v1.0.0"), "v1.0.0 below last_affected must be affected")
}

// TestAffectsVersion_MultiPair_ParsedFromOSV verifies end-to-end parsing of a
// multi-pair OSV JSON record for the Go ecosystem.
func TestAffectsVersion_MultiPair_ParsedFromOSV(t *testing.T) {
	// Synthesize an OSV record with two disjoint ranges in a single SEMVER block.
	rawJSON := []byte(`{
		"id": "TEST-MULTI-0001",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/example/multipkg"},
			"ranges": [{
				"type": "SEMVER",
				"events": [
					{"introduced": "0"},
					{"fixed": "1.2.0"},
					{"introduced": "2.0.0"},
					{"fixed": "2.1.0"}
				]
			}]
		}]
	}`)

	adv, err := parseOSVRecord(rawJSON, EcosystemGo)
	require.NoError(t, err)
	require.Len(t, adv.VersionRanges, 2, "two disjoint ranges must be parsed")

	assert.True(t, adv.AffectsVersion("v1.1.0"), "v1.1.0 in [0,1.2.0) must be affected")
	assert.False(t, adv.AffectsVersion("v1.5.0"), "v1.5.0 between ranges must NOT be affected")
	assert.True(t, adv.AffectsVersion("v2.0.5"), "v2.0.5 in [2.0.0,2.1.0) must be affected")
	assert.False(t, adv.AffectsVersion("v2.5.0"), "v2.5.0 past upper range must NOT be affected")
}

// TestAffectsVersion_LastAffected_ParsedFromOSV verifies end-to-end parsing of a
// last_affected bound from OSV JSON for the Go ecosystem.
func TestAffectsVersion_LastAffected_ParsedFromOSV(t *testing.T) {
	rawJSON := []byte(`{
		"id": "TEST-LASTAFFECTED-0001",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/example/lastpkg"},
			"ranges": [{
				"type": "SEMVER",
				"events": [
					{"introduced": "0"},
					{"last_affected": "1.2.0"}
				]
			}]
		}]
	}`)

	adv, err := parseOSVRecord(rawJSON, EcosystemGo)
	require.NoError(t, err)
	require.Len(t, adv.VersionRanges, 1)

	assert.True(t, adv.AffectsVersion("v1.2.0"), "v1.2.0 (last_affected inclusive) must be affected")
	assert.False(t, adv.AffectsVersion("v1.2.1"), "v1.2.1 above last_affected must NOT be affected")
}

// ─── AffectsVersionV tri-state tests ─────────────────────────────────────────

// TestAffectsVersionV_Go verifies that the tri-state comparator correctly
// classifies Go versions: affected, not-affected, and undecidable (unparseable).
func TestAffectsVersionV_Go(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemGo,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "1.2.0"},
		},
	}

	cases := []struct {
		version string
		want    VersionVerdict
		label   string
	}{
		{"v1.1.0", VersionAffected, "v1.1.0 in [1.0.0,1.2.0) must be Affected"},
		{"v1.2.0", VersionNotAffected, "v1.2.0 at Fixed must be NotAffected (exclusive upper)"},
		{"v0.9.0", VersionNotAffected, "v0.9.0 below Introduced must be NotAffected"},
		{"not-a-version", VersionUndecidable, "unparseable version must be Undecidable, NOT NotAffected"},
		{"", VersionUndecidable, "empty version must be Undecidable, NOT NotAffected"},
		{"1.1.0", VersionUndecidable, "missing v-prefix is unparseable for Go semver → Undecidable"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := adv.AffectsVersionV(tc.version)
			if got != tc.want {
				t.Errorf("AffectsVersionV(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

// TestAffectsVersionV_NPM verifies tri-state comparator for the npm ecosystem.
func TestAffectsVersionV_NPM(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemNPM,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "1.5.0"},
		},
	}

	cases := []struct {
		version string
		want    VersionVerdict
		label   string
	}{
		{"1.2.0", VersionAffected, "1.2.0 in [1.0.0,1.5.0) must be Affected"},
		{"1.5.0", VersionNotAffected, "1.5.0 at Fixed must be NotAffected (exclusive)"},
		{"0.9.0", VersionNotAffected, "0.9.0 below Introduced must be NotAffected"},
		{"not-a-version", VersionUndecidable, "unparseable npm version must be Undecidable"},
		{"", VersionUndecidable, "empty npm version must be Undecidable"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := adv.AffectsVersionV(tc.version)
			if got != tc.want {
				t.Errorf("AffectsVersionV(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

// TestAffectsVersionV_CratesIO verifies that crates.io uses Go-semver comparison
// (SemVer 2.0.0) and that an unparseable version returns Undecidable.
func TestAffectsVersionV_CratesIO(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemCratesIO,
		VersionRanges: []VersionRange{
			{Introduced: "0.1.0", Fixed: "0.2.0"},
		},
	}

	cases := []struct {
		version string
		want    VersionVerdict
		label   string
	}{
		{"v0.1.5", VersionAffected, "v0.1.5 in [0.1.0,0.2.0) must be Affected"},
		{"v0.2.0", VersionNotAffected, "v0.2.0 at Fixed must be NotAffected"},
		{"not-a-version", VersionUndecidable, "unparseable crates.io version must be Undecidable"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := adv.AffectsVersionV(tc.version)
			if got != tc.want {
				t.Errorf("AffectsVersionV(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

// TestAffectsVersionV_UnknownEcosystem verifies that an unrecognised ecosystem
// always returns Undecidable (never NotAffected), even for a "valid" semver string.
// This is critical: an unknown ecosystem must never silently drop an advisory.
func TestAffectsVersionV_UnknownEcosystem(t *testing.T) {
	adv := &Advisory{
		Ecosystem: "UnknownEcosystem",
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	got := adv.AffectsVersionV("v1.5.0")
	if got != VersionUndecidable {
		t.Errorf("AffectsVersionV on unknown ecosystem got %v, want VersionUndecidable", got)
	}
}

// TestAffectsVersionV_PyPI verifies PEP 440 routing in AffectsVersionV for PyPI advisories.
// The PEP 440 comparator is now implemented in pep440.go; this test was previously a
// placeholder guard (expecting Undecidable while unimplemented). It now verifies correct
// PEP 440 semantics: parse errors → Undecidable; valid versions → Affected/NotAffected.
func TestAffectsVersionV_PyPI_Undecidable(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemPyPI,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	// PEP 440 is now implemented: 1.5.0 is inside [1.0.0, 2.0.0).
	if got := adv.AffectsVersionV("1.5.0"); got != VersionAffected {
		t.Errorf("AffectsVersionV on PyPI: 1.5.0 in [1.0.0,2.0.0) got %v, want VersionAffected", got)
	}
	// An unparseable version must still return Undecidable, never NotAffected.
	if got := adv.AffectsVersionV(""); got != VersionUndecidable {
		t.Errorf("AffectsVersionV on PyPI: empty version got %v, want VersionUndecidable", got)
	}
	if got := adv.AffectsVersionV("garbage"); got != VersionUndecidable {
		t.Errorf("AffectsVersionV on PyPI: garbage version got %v, want VersionUndecidable", got)
	}
}

// TestAffectsVersionV_Maven_Undecidable verifies the tri-state Maven comparator:
// inside the range → Affected; outside → NotAffected; unparseable → Undecidable.
func TestAffectsVersionV_Maven_Undecidable(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemMaven,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	// 1.5.0 is inside [1.0.0, 2.0.0) → must be Affected.
	if got := adv.AffectsVersionV("1.5.0"); got != VersionAffected {
		t.Errorf("AffectsVersionV on Maven: 1.5.0 in [1.0.0,2.0.0) got %v, want VersionAffected", got)
	}
	// 2.5.0 is above Fixed (exclusive) → must be NotAffected.
	if got := adv.AffectsVersionV("2.5.0"); got != VersionNotAffected {
		t.Errorf("AffectsVersionV on Maven: 2.5.0 above [1.0.0,2.0.0) got %v, want VersionNotAffected", got)
	}
	// An unparseable version must return Undecidable, never NotAffected.
	if got := adv.AffectsVersionV(""); got != VersionUndecidable {
		t.Errorf("AffectsVersionV on Maven: empty version got %v, want VersionUndecidable", got)
	}
}

// TestAffectsVersionV_EmptyRanges verifies the no-ranges cases. An advisory with no
// version constraint at all (no ranges, no versions) cannot identify any affected
// version → NotAffected. An advisory that had a non-version (GIT) range but no
// versions[] fallback is genuinely undecidable → Undecidable (forwarded as UNKNOWN).
func TestAffectsVersionV_EmptyRanges(t *testing.T) {
	// No ranges and no versions at all → NotAffected (degenerate record).
	empty := &Advisory{Ecosystem: EcosystemGo, VersionRanges: nil}
	if got := empty.AffectsVersionV("v1.0.0"); got != VersionNotAffected {
		t.Errorf("AffectsVersionV with no version constraint got %v, want VersionNotAffected", got)
	}
	// A GIT-range-only entry (UndecidableRanges set, no versions) → Undecidable.
	git := &Advisory{Ecosystem: EcosystemGo, VersionRanges: nil, UndecidableRanges: true}
	if got := git.AffectsVersionV("v1.0.0"); got != VersionUndecidable {
		t.Errorf("AffectsVersionV with a GIT-only range got %v, want VersionUndecidable", got)
	}
}

// TestAffectsVersionV_GoNPMRegression verifies that AffectsVersionV and AffectsVersion
// agree on matched + not-matched valid versions for Go and npm (no regression for existing
// callers that still use the bool form).
func TestAffectsVersionV_GoNPMRegression(t *testing.T) {
	goAdv := &Advisory{
		Ecosystem: EcosystemGo,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "1.3.0"},
		},
	}
	npmAdv := &Advisory{
		Ecosystem: EcosystemNPM,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "1.3.0"},
		},
	}

	goHits := []string{"v1.0.0", "v1.1.0", "v1.2.9"}
	goMiss := []string{"v1.3.0", "v0.9.9", "v2.0.0"}
	npmHits := []string{"1.0.0", "1.1.0", "1.2.9"}
	npmMiss := []string{"1.3.0", "0.9.9", "2.0.0"}

	for _, v := range goHits {
		if goAdv.AffectsVersionV(v) != VersionAffected {
			t.Errorf("Go: AffectsVersionV(%q) should be Affected", v)
		}
		if !goAdv.AffectsVersion(v) {
			t.Errorf("Go regression: AffectsVersion(%q) should be true", v)
		}
	}
	for _, v := range goMiss {
		if goAdv.AffectsVersionV(v) != VersionNotAffected {
			t.Errorf("Go: AffectsVersionV(%q) should be NotAffected", v)
		}
		if goAdv.AffectsVersion(v) {
			t.Errorf("Go regression: AffectsVersion(%q) should be false", v)
		}
	}
	for _, v := range npmHits {
		if npmAdv.AffectsVersionV(v) != VersionAffected {
			t.Errorf("npm: AffectsVersionV(%q) should be Affected", v)
		}
	}
	for _, v := range npmMiss {
		if npmAdv.AffectsVersionV(v) != VersionNotAffected {
			t.Errorf("npm: AffectsVersionV(%q) should be NotAffected", v)
		}
	}
}

// TestOSVLookup_UndecidableMarksIncomplete verifies that advisoryIndex.lookup
// sets Incomplete=true on an advisory when AffectsVersionV returns Undecidable,
// rather than silently dropping the advisory (which would be a false negative).
func TestOSVLookup_UndecidableMarksIncomplete(t *testing.T) {
	// Build an index with a single Go advisory in range [1.0.0, 2.0.0).
	adv := Advisory{
		ID:    "TEST-UNDECIDABLE-0001",
		Module: "github.com/example/pkg",
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}
	idx := &advisoryIndex{
		byName: map[string][]Advisory{
			"github.com/example/pkg": {adv},
		},
	}

	pkg := Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkg"}

	// Valid version in range: should be Affected, Incomplete=false.
	results := idx.lookup(pkg, "v1.5.0", []string{"test-source"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for affected version, got %d", len(results))
	}
	if results[0].Incomplete {
		t.Error("Affected advisory must NOT be marked Incomplete")
	}

	// Unparseable version: must appear in results with Incomplete=true (not dropped).
	results = idx.lookup(pkg, "not-a-semver", []string{"test-source"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for undecidable version (must not drop), got %d", len(results))
	}
	if !results[0].Incomplete {
		t.Error("Undecidable advisory must be marked Incomplete=true")
	}

	// Version clearly outside range: should be dropped (only safe drop).
	results = idx.lookup(pkg, "v3.0.0", []string{"test-source"})
	if len(results) != 0 {
		t.Errorf("NotAffected version should be dropped, got %d results", len(results))
	}
}

// TestDirSourceQuery_UndecidableMarksIncomplete verifies that dirSource.query
// marks an advisory Incomplete=true for an unparseable version rather than dropping it.
func TestDirSourceQuery_UndecidableMarksIncomplete(t *testing.T) {
	// Write a minimal OSV advisory to a temp dir.
	dir := t.TempDir()
	rawJSON := []byte(`{
		"id": "GO-UNDECIDABLE-TEST-0001",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/example/testpkg"},
			"ranges": [{
				"type": "SEMVER",
				"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
			}]
		}]
	}`)
	err := os.WriteFile(filepath.Join(dir, "GO-UNDECIDABLE-TEST-0001.json"), rawJSON, 0600)
	if err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ds := &dirSource{dir: dir, sources: []string{"test-source"}}
	pkg := Package{Ecosystem: EcosystemGo, Name: "github.com/example/testpkg"}

	// Valid version in range.
	results, err := ds.query(t.Context(), pkg, "v1.0.0")
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for affected version, got %d", len(results))
	}
	if results[0].Incomplete {
		t.Error("Affected advisory must NOT be marked Incomplete")
	}

	// Unparseable version: must appear with Incomplete=true, not be dropped.
	results, err = ds.query(t.Context(), pkg, "not-a-semver")
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for undecidable version (must not drop), got %d", len(results))
	}
	if !results[0].Incomplete {
		t.Error("Undecidable advisory must be marked Incomplete=true")
	}
}

// ─── PyPI ECOSYSTEM range type regression (litellm false-positive fix) ───────

// TestParseOSVRecord_PyPI_EcosystemRangeType is the regression test encoding the
// mlflow/litellm false-positive bug: OSV PyPI records use range type "ECOSYSTEM"
// (not "SEMVER"). Before the fix, ECOSYSTEM ranges were silently skipped, leaving
// VersionRanges empty → AffectsVersionV returned VersionUndecidable → advisory
// was kept with Incomplete=true for every queried version → 585 false positives.
//
// Contract after fix:
//   - ECOSYSTEM-typed ranges MUST be parsed into VersionRanges.
//   - A version above the fixed bound (e.g. mlflow 3.14.0 vs fixed 2.10.0) MUST
//     return VersionNotAffected and MUST NOT appear in query results.
//   - A version inside the range (e.g. mlflow 2.5.0) MUST return VersionAffected.
func TestParseOSVRecord_PyPI_EcosystemRangeType(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "PYPI-MLFLOW-TEST.json")
	adv, err := parseOSVRecord(data, EcosystemPyPI)
	require.NoError(t, err)

	// The ECOSYSTEM range [0, 2.10.0) must be parsed into VersionRanges.
	require.NotEmpty(t, adv.VersionRanges,
		"ECOSYSTEM-typed OSV ranges must be parsed into VersionRanges (was being silently skipped)")
	assert.Equal(t, "mlflow", adv.Module)

	// mlflow 3.14.0 is ABOVE fixed=2.10.0 → must be NotAffected (the false-positive case).
	adv.Ecosystem = EcosystemPyPI
	verdict := adv.AffectsVersionV(canonical("3.14.0")) // canonical → "v3.14.0"
	assert.Equal(t, VersionNotAffected, verdict,
		"mlflow 3.14.0 >= fixed 2.10.0: must be VersionNotAffected, not VersionUndecidable")

	// mlflow 2.5.0 is inside [0, 2.10.0) → must be Affected (true positive must survive).
	verdict = adv.AffectsVersionV(canonical("2.5.0"))
	assert.Equal(t, VersionAffected, verdict,
		"mlflow 2.5.0 in [0, 2.10.0): must be VersionAffected")

	// mlflow 2.10.0 is at the fixed boundary (exclusive) → must be NotAffected.
	verdict = adv.AffectsVersionV(canonical("2.10.0"))
	assert.Equal(t, VersionNotAffected, verdict,
		"mlflow 2.10.0 == fixed 2.10.0 (exclusive bound): must be VersionNotAffected")
}

// TestParseOSVRecord_PyPI_LastAffected verifies that an ECOSYSTEM range with
// last_affected (inclusive upper bound) is also correctly parsed. The case:
// GHSA-43c4-9qgj-x742, last_affected=2.14.1 — mlflow 3.14.0 must NOT match.
func TestParseOSVRecord_PyPI_LastAffected(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "PYPI-LAST-AFFECTED-TEST.json")
	adv, err := parseOSVRecord(data, EcosystemPyPI)
	require.NoError(t, err)

	require.NotEmpty(t, adv.VersionRanges,
		"ECOSYSTEM ranges with last_affected must be parsed")
	assert.Equal(t, "2.14.1", adv.VersionRanges[0].LastAffected,
		"last_affected value must be preserved in VersionRange")

	adv.Ecosystem = EcosystemPyPI

	// 3.14.0 > 2.14.1 (inclusive upper) → NotAffected.
	verdict := adv.AffectsVersionV(canonical("3.14.0"))
	assert.Equal(t, VersionNotAffected, verdict,
		"mlflow 3.14.0 > last_affected 2.14.1: must be VersionNotAffected")

	// 2.14.1 == last_affected (inclusive) → Affected.
	verdict = adv.AffectsVersionV(canonical("2.14.1"))
	assert.Equal(t, VersionAffected, verdict,
		"mlflow 2.14.1 == last_affected 2.14.1 (inclusive): must be VersionAffected")

	// 1.0.0 < last_affected → Affected.
	verdict = adv.AffectsVersionV(canonical("1.0.0"))
	assert.Equal(t, VersionAffected, verdict,
		"mlflow 1.0.0 < last_affected 2.14.1: must be VersionAffected")
}

// TestDirSource_Query_PyPI_EcosystemRangeDrop verifies the full query path:
// a PyPI advisory with ECOSYSTEM ranges must drop out-of-range versions
// and return in-range versions, through dirSource.query.
func TestDirSource_Query_PyPI_EcosystemRangeDrop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := loadFixture(t, "PYPI-MLFLOW-TEST.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-MLFLOW-TEST.json"), data, 0o644))

	ds := &dirSource{dir: dir, sources: []string{"test"}}
	ctx := context.Background()
	pkg := Package{Ecosystem: EcosystemPyPI, Name: "mlflow"}

	// 3.14.0 is above fixed 2.10.0 → must NOT appear in results (the false-positive case).
	results, err := ds.query(ctx, pkg, "3.14.0")
	require.NoError(t, err)
	assert.Empty(t, results,
		"mlflow@3.14.0 must be dropped: it is above fixed=2.10.0 (was a false positive before fix)")

	// 2.5.0 is inside [0, 2.10.0) → must appear as VersionAffected (true positive).
	results, err = ds.query(ctx, pkg, "2.5.0")
	require.NoError(t, err)
	require.Len(t, results, 1,
		"mlflow@2.5.0 must match: it is inside [0, 2.10.0)")
	assert.False(t, results[0].Incomplete,
		"true-positive result must not be marked Incomplete")

	// 2.10.0 is the fixed boundary (exclusive) → must NOT appear.
	results, err = ds.query(ctx, pkg, "2.10.0")
	require.NoError(t, err)
	assert.Empty(t, results,
		"mlflow@2.10.0 must be dropped: it equals fixed=2.10.0 (exclusive bound)")
}

// TestParseOSVRecord_PyPI_Severity verifies that CVSS_V3 severity data from the
// OSV severity[] array is parsed and stored on the Advisory.Severity field.
// The fixture PYPI-MLFLOW-TEST.json carries a CVSS:3.1 score with base score 9.8
// (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) → maps to SeverityCritical.
func TestParseOSVRecord_PyPI_Severity(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "PYPI-MLFLOW-TEST.json")
	adv, err := parseOSVRecord(data, EcosystemPyPI)
	require.NoError(t, err)

	// CVSS base score 9.8 → Critical.
	assert.Equal(t, SeverityCritical, adv.Severity,
		"CVSS:3.1 score 9.8 must map to SeverityCritical")
}

// TestParseOSVRecord_PyPI_SeverityHigh verifies that a CVSS_V3 score in the High
// band (7.0–8.9) maps to SeverityHigh. GHSA-43c4-9qgj-x742 has a score of 7.5
// (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
func TestParseOSVRecord_PyPI_SeverityHigh(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "PYPI-LAST-AFFECTED-TEST.json")
	adv, err := parseOSVRecord(data, EcosystemPyPI)
	require.NoError(t, err)

	assert.Equal(t, SeverityHigh, adv.Severity,
		"CVSS:3.1 score 7.5 must map to SeverityHigh")
}

// TestParseOSVRecord_NoSeverity verifies that an OSV record without a severity
// array leaves Severity at SeverityUnspecified (the zero value).
func TestParseOSVRecord_NoSeverity(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "GO-2024-0001.json") // has no severity[]
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	assert.Equal(t, SeverityUnspecified, adv.Severity,
		"advisory without severity array must have SeverityUnspecified")
}

// TestParseOSVRecord_CVSSMetricsPopulated verifies that parseOSVRecord parses the
// OSV severity[] CVSS vectors into Advisory.CVSS losslessly via the exact ParseCVSS
// engine. The fixture carries a CVSS:3.1 vector whose exact base score is 7.0
// (raw 6.92256, exact CVSS Roundup → 7.0), which the legacy round-half-up path
// would have undershot to 6.9 — i.e. SeverityMedium instead of the spec-correct
// SeverityHigh.
func TestParseOSVRecord_CVSSMetricsPopulated(t *testing.T) {
	t.Parallel()

	data := loadFixture(t, "GO-CVSS-ROUNDING-TEST.json")
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	require.Len(t, adv.CVSS, 1, "CVSS metric must be populated from severity[]")
	assert.Equal(t, "3.1", adv.CVSS[0].Version)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", adv.CVSS[0].Vector,
		"vector must be captured losslessly")
	assert.InDelta(t, 7.0, adv.CVSS[0].BaseScore, 0.001,
		"exact CVSS Roundup must yield 7.0, not the legacy round-half-up 6.9")
	assert.Equal(t, SeverityHigh, adv.Severity,
		"exact base score 7.0 must map to SeverityHigh (round-half-up would undershoot to Medium)")
}

// TestParseOSVRecord_SeverityParity verifies that records with NO CVSS vector
// derive the EXACT same Severity through the new severityFromMetrics path as the
// pre-existing textual / no-severity fallback produced.
func TestParseOSVRecord_SeverityParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fixture  string
		eco      string
		expected Severity
	}{
		{"textual HIGH only", "GO-TEXT-SEVERITY-TEST.json", EcosystemGo, SeverityHigh},
		{"no severity at all", "GO-2024-0001.json", EcosystemGo, SeverityUnspecified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			adv, err := parseOSVRecord(loadFixture(t, tt.fixture), tt.eco)
			require.NoError(t, err)
			assert.Empty(t, adv.CVSS, "no CVSS vector → no metrics")
			assert.Equal(t, tt.expected, adv.Severity)
		})
	}
}

// TestToProto verifies that an internal Advisory converts cleanly to *anstv1.Advisory.
func TestToProto(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")
	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	proto := adv.ToProto()
	require.NotNil(t, proto)

	assert.Equal(t, adv.ID, proto.GetId())
	assert.Equal(t, adv.Module, proto.GetModule())
	assert.Equal(t, adv.SymbolLevel, proto.GetSymbolLevel())
	assert.Contains(t, proto.GetSources(), SourceGoVulnDB)

	// Verify symbols round-trip.
	protoSyms := make(map[string]bool)
	for _, ps := range proto.GetSymbols() {
		protoSyms[ps.GetPackage()+"."+ps.GetName()] = true
	}
	for _, s := range adv.Symbols {
		key := s.Package + "." + s.Name
		assert.True(t, protoSyms[key], "symbol %s missing from proto", key)
	}
}
