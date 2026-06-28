package advisory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── severity resolution ──────────────────────────────────────────────────────

// TestResolveGroup_SeverityHighestWins verifies that when sources disagree on
// severity, the merged advisory keeps the HIGHEST severity (fail-safe) and the
// losing severities are recorded in SourceMeta — never silently dropped.
func TestResolveGroup_SeverityHighestWins(t *testing.T) {
	ghsa := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-5555"}, false, []string{SourceGHSA}, nil)
	ghsa.Severity = SeverityHigh
	osv := makeAdvisory("OSV-0001", []string{"CVE-2024-5555"}, false, []string{SourceOSV}, nil)
	osv.Severity = SeverityMedium

	merged := mergeAdvisories([]Advisory{osv, ghsa})
	require.Len(t, merged, 1)

	got := merged[0]
	assert.Equal(t, SeverityHigh, got.Severity, "highest severity must win (never silently downgrade)")

	// Both source severities must be recorded in SourceMeta.
	bySource := map[string]Severity{}
	for _, c := range got.SourceMeta {
		bySource[c.Name] = c.Severity
	}
	assert.Equal(t, SeverityHigh, bySource[SourceGHSA])
	assert.Equal(t, SeverityMedium, bySource[SourceOSV])

	// The conflict string exposes the spread, sorted, deterministically.
	assert.Equal(t, "ghsa:HIGH,osv.dev:MEDIUM", severityConflictString(got.SourceMeta))
}

// TestSeverityConflictString_NoConflictWhenEqual verifies that identical
// severities across sources produce no conflict string (nothing to report).
func TestSeverityConflictString_NoConflictWhenEqual(t *testing.T) {
	meta := []SourceContribution{
		{Name: SourceGHSA, Severity: SeverityHigh},
		{Name: SourceOSV, Severity: SeverityHigh},
	}
	assert.Empty(t, severityConflictString(meta), "no conflict when all sources agree")
}

// TestSeverityConflictString_SingleSourceEmpty verifies a single source can
// never be a conflict.
func TestSeverityConflictString_SingleSourceEmpty(t *testing.T) {
	meta := []SourceContribution{{Name: SourceGHSA, Severity: SeverityHigh}}
	assert.Empty(t, severityConflictString(meta))
}

// ─── version-range union ──────────────────────────────────────────────────────

// TestResolveGroup_VersionRangeUnion verifies that affected ranges are UNIONED
// across sources (broader coverage = fail-safe), never narrowed to the
// representative's range alone.
func TestResolveGroup_VersionRangeUnion(t *testing.T) {
	// Source A: affected [v1.0.0, v1.5.0). Source B: affected [v1.5.0, v2.0.0).
	// Neither alone covers v1.7.0; the union must.
	a := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-6666"}, true, []string{SourceGHSA},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v1.5.0"}})
	b := makeAdvisory("OSV-0002", []string{"CVE-2024-6666"}, false, []string{SourceOSV},
		[]VersionRange{{Introduced: "v1.5.0", Fixed: "v2.0.0"}})

	merged := mergeAdvisories([]Advisory{a, b})
	require.Len(t, merged, 1)
	got := merged[0]

	assert.Equal(t, VersionAffected, got.AffectsVersionV("v1.2.0"), "covered by source A range")
	assert.Equal(t, VersionAffected, got.AffectsVersionV("v1.7.0"), "covered by source B range (union)")
	assert.Equal(t, VersionNotAffected, got.AffectsVersionV("v2.1.0"), "outside both ranges")
}

// TestResolveGroup_VersionRangeUnionDeterministic verifies the unioned ranges
// are identical regardless of input order.
func TestResolveGroup_VersionRangeUnionDeterministic(t *testing.T) {
	a := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-6667"}, false, []string{SourceGHSA},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v1.5.0"}})
	b := makeAdvisory("OSV-0003", []string{"CVE-2024-6667"}, false, []string{SourceOSV},
		[]VersionRange{{Introduced: "v1.5.0", Fixed: "v2.0.0"}})

	order1 := mergeAdvisories([]Advisory{a, b})
	order2 := mergeAdvisories([]Advisory{b, a})
	assert.Equal(t, order1[0].VersionRanges, order2[0].VersionRanges,
		"unioned ranges must be deterministic regardless of input order")
}

// TestResolveGroup_UndecidableUnionIncomplete verifies that when any source's
// ranges are undecidable, the merged advisory is marked Incomplete — never
// narrowed in a way that could drop coverage (unknown ≠ safe).
func TestResolveGroup_UndecidableUnionIncomplete(t *testing.T) {
	good := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-7777"}, false, []string{SourceGHSA},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v2.0.0"}})
	bad := makeAdvisory("OSV-0004", []string{"CVE-2024-7777"}, false, []string{SourceOSV},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v2.0.0"}})
	bad.UndecidableRanges = true
	bad.Incomplete = true

	merged := mergeAdvisories([]Advisory{good, bad})
	require.Len(t, merged, 1)
	assert.True(t, merged[0].Incomplete, "an undecidable contributing source makes the merge incomplete")
}

// TestResolveGroup_FixVersionsAllRecorded verifies that every source's fix
// version survives the union (the earliest fix is preserved for remediation).
func TestResolveGroup_FixVersionsAllRecorded(t *testing.T) {
	early := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-8888"}, false, []string{SourceGHSA},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v1.4.0"}})
	late := makeAdvisory("OSV-0005", []string{"CVE-2024-8888"}, false, []string{SourceOSV},
		[]VersionRange{{Introduced: "v1.0.0", Fixed: "v1.9.0"}})

	merged := mergeAdvisories([]Advisory{early, late})
	require.Len(t, merged, 1)

	fixed := map[string]struct{}{}
	for _, r := range merged[0].VersionRanges {
		fixed[r.Fixed] = struct{}{}
	}
	assert.Contains(t, fixed, "v1.4.0", "earliest fix must be recorded")
	assert.Contains(t, fixed, "v1.9.0", "later fix must be recorded too")
	assert.Equal(t, "v1.4.0", lowestFixedVersion(merged[0]), "lowest fixed version is the earliest known fix")
}

// ─── withdrawn quorum ─────────────────────────────────────────────────────────

// TestResolveGroup_WithdrawnPartialStaysLive verifies that a single
// non-withdrawn source keeps the advisory LIVE even when another source
// withdrew it (partial withdrawal never silences a live CVE).
func TestResolveGroup_WithdrawnPartialStaysLive(t *testing.T) {
	withdrawn := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-9999"}, false, []string{SourceGHSA}, nil)
	withdrawn.Withdrawn = "2024-01-01T00:00:00Z"
	live := makeAdvisory("OSV-0006", []string{"CVE-2024-9999"}, false, []string{SourceOSV}, nil)

	merged := mergeAdvisories([]Advisory{withdrawn, live})
	require.Len(t, merged, 1)
	assert.Empty(t, merged[0].Withdrawn, "a single live source keeps the advisory live")
}

// TestResolveGroup_WithdrawnUnanimous verifies that an advisory is withdrawn
// only when EVERY contributing source withdrew it.
func TestResolveGroup_WithdrawnUnanimous(t *testing.T) {
	a := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-9998"}, false, []string{SourceGHSA}, nil)
	a.Withdrawn = "2024-01-01T00:00:00Z"
	b := makeAdvisory("OSV-0007", []string{"CVE-2024-9998"}, false, []string{SourceOSV}, nil)
	b.Withdrawn = "2024-02-01T00:00:00Z"

	merged := mergeAdvisories([]Advisory{a, b})
	require.Len(t, merged, 1)
	assert.NotEmpty(t, merged[0].Withdrawn, "unanimous withdrawal suppresses the advisory")
}

// ─── provenance ───────────────────────────────────────────────────────────────

// TestProvenanceString_Deterministic verifies the provenance summary is stable
// regardless of SourceMeta ordering.
func TestProvenanceString_Deterministic(t *testing.T) {
	meta1 := []SourceContribution{
		{Name: SourceGHSA, Severity: SeverityHigh, Vector: "CVSS:3.1/AV:N", SnapshotAge: "72h"},
		{Name: SourceOSV, Severity: SeverityMedium, SnapshotAge: "100h"},
	}
	meta2 := []SourceContribution{
		{Name: SourceOSV, Severity: SeverityMedium, SnapshotAge: "100h"},
		{Name: SourceGHSA, Severity: SeverityHigh, Vector: "CVSS:3.1/AV:N", SnapshotAge: "72h"},
	}
	got1 := provenanceString(meta1)
	got2 := provenanceString(meta2)
	assert.Equal(t, got1, got2, "provenance must be order-independent")
	assert.Contains(t, got1, "ghsa HIGH")
	assert.Contains(t, got1, "osv.dev MEDIUM")
	assert.Contains(t, got1, "CVSS:3.1/AV:N")
	// Age is wall-clock-relative; it must never appear in the rendered provenance,
	// or two otherwise-identical scans produce non-byte-identical SARIF.
	assert.NotContains(t, got1, "72h", "provenance must not embed snapshot age")
}

// TestResolveGroup_SourceMetaDeterministic verifies SourceMeta built by the merge
// is sorted by source name and identical regardless of input order.
func TestResolveGroup_SourceMetaDeterministic(t *testing.T) {
	a := makeAdvisory("GHSA-aaaa", []string{"CVE-2024-4444"}, false, []string{SourceGHSA}, nil)
	a.Severity = SeverityHigh
	b := makeAdvisory("OSV-0008", []string{"CVE-2024-4444"}, false, []string{SourceOSV}, nil)
	b.Severity = SeverityLow

	order1 := mergeAdvisories([]Advisory{a, b})
	order2 := mergeAdvisories([]Advisory{b, a})
	require.Len(t, order1, 1)
	assert.Equal(t, order1[0].SourceMeta, order2[0].SourceMeta, "SourceMeta must be deterministic")

	// Sorted by name: ghsa before osv.dev.
	require.Len(t, order1[0].SourceMeta, 2)
	assert.Equal(t, SourceGHSA, order1[0].SourceMeta[0].Name)
	assert.Equal(t, SourceOSV, order1[0].SourceMeta[1].Name)
}

// ─── freshness SLA ────────────────────────────────────────────────────────────

// TestFreshnessSLA_SoftWarnsHardIncomplete verifies the freshness policy:
// a source older than the soft threshold is tagged stale (warn-only by default);
// older than the hard threshold marks the result incomplete ONLY when the policy
// opts into hard-incomplete (default warn-only, no surprise exit-3).
func TestFreshnessSLA_SoftWarnsHardIncomplete(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	meta := []SourceContribution{
		{Name: SourceGHSA, FetchedAt: now.Add(-100 * time.Hour).Format(time.RFC3339)}, // stale, not hard
		{Name: SourceOSV, FetchedAt: now.Add(-1000 * time.Hour).Format(time.RFC3339)}, // past hard
		{Name: SourceNVD, FetchedAt: now.Add(-1 * time.Hour).Format(time.RFC3339)},    // fresh
	}

	// Warn-only policy: soft 72h, hard 720h, HardIncomplete=false (default).
	warnOnly := FreshnessSLA{Soft: 72 * time.Hour, Hard: 720 * time.Hour}
	stale, incomplete := warnOnly.Evaluate(meta, now)
	assert.Equal(t, []string{SourceGHSA, SourceOSV}, stale, "both stale sources tagged, sorted")
	assert.False(t, incomplete, "default warn-only never marks incomplete")

	// Strict policy: hard threshold drives incomplete.
	strict := FreshnessSLA{Soft: 72 * time.Hour, Hard: 720 * time.Hour, HardIncomplete: true}
	_, incompleteStrict := strict.Evaluate(meta, now)
	assert.True(t, incompleteStrict, "a source past the hard threshold marks incomplete under strict policy")
}

// TestFreshnessSLA_SnapshotAgeFallback verifies the SLA can use SnapshotAge when
// FetchedAt is absent.
func TestFreshnessSLA_SnapshotAgeFallback(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	meta := []SourceContribution{
		{Name: SourceOSV, SnapshotAge: "100h"},
		{Name: SourceGHSA, SnapshotAge: "1h"},
	}
	sla := FreshnessSLA{Soft: 72 * time.Hour}
	stale, _ := sla.Evaluate(meta, now)
	assert.Equal(t, []string{SourceOSV}, stale)
}

// TestFreshnessSLA_UnparseableAgeIgnored verifies a source whose age cannot be
// determined is not falsely reported stale (it is simply unassessable here; the
// caller surfaces missing freshness elsewhere).
func TestFreshnessSLA_UnparseableAgeIgnored(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	meta := []SourceContribution{{Name: SourceOSV}}
	sla := FreshnessSLA{Soft: 72 * time.Hour, Hard: 720 * time.Hour, HardIncomplete: true}
	stale, incomplete := sla.Evaluate(meta, now)
	assert.Empty(t, stale)
	assert.False(t, incomplete)
}

// TestStaleSourceString verifies the stale-source property string is sorted and
// comma-joined for deterministic output.
func TestStaleSourceString(t *testing.T) {
	assert.Empty(t, staleSourceString(nil))
	assert.Equal(t, "ghsa,osv.dev", staleSourceString([]string{SourceOSV, SourceGHSA}))
}

// ─── severity label ───────────────────────────────────────────────────────────

func TestSeverityLabel(t *testing.T) {
	assert.Equal(t, "UNSPECIFIED", severityLabel(SeverityUnspecified))
	assert.Equal(t, "LOW", severityLabel(SeverityLow))
	assert.Equal(t, "MEDIUM", severityLabel(SeverityMedium))
	assert.Equal(t, "HIGH", severityLabel(SeverityHigh))
	assert.Equal(t, "CRITICAL", severityLabel(SeverityCritical))
}
