package advisory

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// makeAdvisory builds a minimal Advisory for table tests.
func makeAdvisory(id string, aliases []string, symbolLevel bool, sources []string, versionRanges []VersionRange) Advisory {
	if versionRanges == nil {
		versionRanges = []VersionRange{{Introduced: "", Fixed: "v9.9.9"}}
	}
	return Advisory{
		ID:            id,
		Aliases:       aliases,
		SymbolLevel:   symbolLevel,
		Sources:       sources,
		VersionRanges: versionRanges,
		Module:        "github.com/example/pkg",
		Ecosystem:     EcosystemGo,
	}
}

// ─── merge tests ─────────────────────────────────────────────────────────────

// TestMerge_SameIDFromTwoSources verifies that the same advisory ID appearing
// from two sources merges into a single advisory with union Sources.
func TestMerge_SameIDFromTwoSources(t *testing.T) {
	a := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)
	b := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, false, []string{SourceOSV}, nil)

	merged := mergeAdvisories([]Advisory{a, b})
	require.Len(t, merged, 1, "same ID from two sources must produce exactly one advisory")

	got := merged[0]
	assert.Equal(t, "GO-2024-0001", got.ID)
	assert.True(t, got.SymbolLevel, "symbol-level advisory must be preferred over package-level")
	assert.ElementsMatch(t, []string{SourceGoVulnDB, SourceOSV}, got.Sources,
		"Sources must be union of all contributing sources")
	assert.Contains(t, got.Aliases, "CVE-2024-99001",
		"Aliases must include the CVE alias")
}

// TestMerge_AliasMerge verifies that two advisories with different IDs but a
// shared alias (CVE/GHSA overlap) collapse into one merged advisory.
// GO-DB advisory has symbol-level data; OSV has only the CVE alias.
func TestMerge_AliasMerge(t *testing.T) {
	// GO-DB entry: GO-2024-0001 with CVE-2024-99001, symbol-level
	goDB := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001", "GHSA-xxxx-yyyy-0001"}, true, []string{SourceGoVulnDB}, nil)
	// OSV entry: different ID but same CVE alias, package-level
	osv := makeAdvisory("GHSA-xxxx-yyyy-0001", []string{"CVE-2024-99001"}, false, []string{SourceOSV}, nil)

	merged := mergeAdvisories([]Advisory{goDB, osv})
	require.Len(t, merged, 1, "alias-connected advisories must merge into one")

	got := merged[0]
	// The symbol-level representative wins (GO-2024-0001).
	assert.Equal(t, "GO-2024-0001", got.ID, "symbol-level representative ID must be preserved")
	assert.True(t, got.SymbolLevel, "symbol-level must be retained after merge")
	assert.ElementsMatch(t, []string{SourceGoVulnDB, SourceOSV}, got.Sources)
	// Aliases must include all IDs from both advisories.
	assert.Contains(t, got.Aliases, "CVE-2024-99001")
	assert.Contains(t, got.Aliases, "GHSA-xxxx-yyyy-0001")
}

// TestMerge_DistinctAdvisoriesUnchanged verifies that advisories with no ID or
// alias overlap each remain as separate entries.
func TestMerge_DistinctAdvisoriesUnchanged(t *testing.T) {
	a := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)
	b := makeAdvisory("GO-2024-0002", []string{"CVE-2024-99002"}, false, []string{SourceOSV}, nil)

	merged := mergeAdvisories([]Advisory{a, b})
	require.Len(t, merged, 2, "distinct advisories must remain separate")
}

// TestMerge_Deterministic verifies that mergeAdvisories produces a stable,
// lexicographically-sorted output regardless of input order.
func TestMerge_Deterministic(t *testing.T) {
	a := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)
	b := makeAdvisory("GO-2024-0002", []string{"CVE-2024-99002"}, false, []string{SourceOSV}, nil)
	c := makeAdvisory("GO-2024-0003", []string{"CVE-2024-99003"}, true, []string{SourceGoVulnDB}, nil)

	order1 := mergeAdvisories([]Advisory{a, b, c})
	order2 := mergeAdvisories([]Advisory{c, a, b})
	order3 := mergeAdvisories([]Advisory{b, c, a})

	require.Equal(t, order1, order2, "output must be deterministic regardless of input order")
	require.Equal(t, order1, order3, "output must be deterministic regardless of input order")

	// Must be lexicographically sorted by ID.
	for i := 1; i < len(order1); i++ {
		assert.Less(t, order1[i-1].ID, order1[i].ID, "output must be sorted by ID")
	}
}

// TestMerge_ThreeWayAliasChain verifies that a three-advisory alias chain
// (A aliases B, B aliases C, A and C share no direct alias) collapses to one
// merged advisory. Pairwise set-intersection is sufficient for this case.
func TestMerge_ThreeWayAliasChain(t *testing.T) {
	// A: GO-2024-0001 with alias CVE-A
	a := makeAdvisory("GO-2024-0001", []string{"CVE-A"}, true, []string{SourceGoVulnDB}, nil)
	// B: GHSA-b with aliases CVE-A (connects to A) and CVE-B (connects to C)
	b := makeAdvisory("GHSA-0002", []string{"CVE-A", "CVE-B"}, false, []string{SourceOSV}, nil)
	// C: GHSA-c with alias CVE-B (connects to B, transitively to A)
	c := makeAdvisory("GHSA-0003", []string{"CVE-B"}, false, []string{SourceOSV}, nil)

	merged := mergeAdvisories([]Advisory{a, b, c})
	require.Len(t, merged, 1, "three-way alias chain must collapse to one advisory")

	got := merged[0]
	assert.Equal(t, "GO-2024-0001", got.ID, "symbol-level representative must be used")
	assert.True(t, got.SymbolLevel)
	assert.ElementsMatch(t, []string{SourceGoVulnDB, SourceOSV}, got.Sources)
	// All aliases from all three must be unioned.
	assert.Contains(t, got.Aliases, "CVE-A")
	assert.Contains(t, got.Aliases, "CVE-B")
	assert.Contains(t, got.Aliases, "GHSA-0002")
	assert.Contains(t, got.Aliases, "GHSA-0003")
}

// TestMerge_SymbolLevelPreferenceOverVersionRange verifies the tie-break rule:
// when two advisories are both symbol-level (or both package-level), the one
// with a wider (or earlier-introduced) version range wins.
func TestMerge_SymbolLevelPreferenceOverVersionRange(t *testing.T) {
	// Both symbol-level; a has wider range (Introduced="") while b starts at v1.0.0.
	a := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB},
		[]VersionRange{{Introduced: "", Fixed: "v2.0.0"}})
	b := makeAdvisory("GHSA-xxxx", []string{"CVE-2024-99001"}, true, []string{SourceOSV},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v2.0.0"}})

	merged := mergeAdvisories([]Advisory{a, b})
	require.Len(t, merged, 1)

	// a has wider range (lower Introduced); a's ID should be the representative.
	got := merged[0]
	assert.Equal(t, "GO-2024-0001", got.ID, "wider-range advisory must be the representative")
}

// TestMerge_Empty verifies that mergeAdvisories handles an empty input gracefully.
func TestMerge_Empty(t *testing.T) {
	merged := mergeAdvisories(nil)
	assert.Empty(t, merged)

	merged = mergeAdvisories([]Advisory{})
	assert.Empty(t, merged)
}

// ─── MultiSource tests ────────────────────────────────────────────────────────

// staticSource is a Source implementation for tests that returns a fixed result.
type staticSource struct {
	advs []Advisory
	err  error
}

func (s *staticSource) Query(_ context.Context, _ Package, _ string) ([]Advisory, error) {
	return s.advs, s.err
}

// TestMultiSource_BothSucceed verifies that MultiSource fans out to both sources
// and merges the results.
func TestMultiSource_BothSucceed(t *testing.T) {
	goAdv := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)
	osvAdv := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, false, []string{SourceOSV}, nil)

	ms := NewMultiSource(
		NamedSource{Name: SourceGoVulnDB, S: &staticSource{advs: []Advisory{goAdv}}},
		NamedSource{Name: SourceOSV, S: &staticSource{advs: []Advisory{osvAdv}}},
	)

	advs, err := ms.Query(context.Background(), Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1, "same CVE from two sources must merge to one")

	got := advs[0]
	assert.True(t, got.SymbolLevel, "symbol-level must win")
	assert.ElementsMatch(t, []string{SourceGoVulnDB, SourceOSV}, got.Sources)
}

// TestMultiSource_SecondarySourceFails verifies the "degrade, not abort" rule:
// when one source errors, the other source's results are still returned, and the
// error is a *SourcesIncompleteError listing the failed source.
func TestMultiSource_SecondarySourceFails(t *testing.T) {
	goAdv := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)

	ms := NewMultiSource(
		NamedSource{Name: SourceGoVulnDB, S: &staticSource{advs: []Advisory{goAdv}}},
		NamedSource{Name: SourceOSV, S: &staticSource{err: errors.New("OSV network error")}},
	)

	advs, err := ms.Query(context.Background(), Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkg"}, "v1.0.0")

	// The error must be a *SourcesIncompleteError — the CLI uses this to warn + mark incomplete.
	var incompleteErr *SourcesIncompleteError
	require.True(t, errors.As(err, &incompleteErr),
		"a source failure must return *SourcesIncompleteError, got: %T %v", err, err)
	assert.Contains(t, incompleteErr.FailedSources, SourceOSV,
		"FailedSources must list the failed source name")

	// The successful source's advisories must still be returned.
	require.Len(t, advs, 1, "successful source's advisories must be returned despite secondary failure")
	assert.Equal(t, "GO-2024-0001", advs[0].ID)
}

// TestMultiSource_AllSourcesFail verifies that when ALL sources fail, MultiSource
// returns an empty slice and a *SourcesIncompleteError listing all failed sources.
func TestMultiSource_AllSourcesFail(t *testing.T) {
	ms := NewMultiSource(
		NamedSource{Name: SourceGoVulnDB, S: &staticSource{err: errors.New("go-vuln-db error")}},
		NamedSource{Name: SourceOSV, S: &staticSource{err: errors.New("OSV error")}},
	)

	advs, err := ms.Query(context.Background(), Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkg"}, "v1.0.0")

	var incompleteErr *SourcesIncompleteError
	require.True(t, errors.As(err, &incompleteErr))
	assert.ElementsMatch(t, []string{SourceGoVulnDB, SourceOSV}, incompleteErr.FailedSources)
	assert.Empty(t, advs)
}

// TestMultiSource_SingleSource verifies that a MultiSource with a single source
// works correctly (no spurious merge side-effects).
func TestMultiSource_SingleSource(t *testing.T) {
	goAdv := makeAdvisory("GO-2024-0001", []string{"CVE-2024-99001"}, true, []string{SourceGoVulnDB}, nil)
	ms := NewMultiSource(
		NamedSource{Name: SourceGoVulnDB, S: &staticSource{advs: []Advisory{goAdv}}},
	)

	advs, err := ms.Query(context.Background(), Package{Ecosystem: EcosystemGo, Name: "github.com/example/pkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1)
	assert.Equal(t, "GO-2024-0001", advs[0].ID)
}

// ─── SourcesIncompleteError tests ────────────────────────────────────────────

// TestSourcesIncompleteError_Error verifies the human-readable error message
// lists all failed source names.
func TestSourcesIncompleteError_Error(t *testing.T) {
	e := &SourcesIncompleteError{
		FailedSources: []string{SourceOSV, SourceGoVulnDB},
		Errors:        []error{errors.New("network timeout"), errors.New("parse error")},
	}
	msg := e.Error()
	assert.Contains(t, msg, SourceOSV)
	assert.Contains(t, msg, SourceGoVulnDB)
}
