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
