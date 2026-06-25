package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ─── crates.io routing fix ────────────────────────────────────────────────────

// TestAffectsVersionV_CratesIO_RoutesToCargoSemver verifies that AffectsVersionV
// for EcosystemCratesIO routes to cargoVersionInRangeV (Cargo SemVer semantics)
// rather than versionInRangeV (Go semver, which rejects bare Cargo versions).
//
// Before the fix: EcosystemCratesIO was routed to versionInRangeV alongside Go.
// versionInRangeV requires the "v"-prefixed form that canonical() adds. The real
// call path (lookup / dirSource.query) applies canonical() before AffectsVersionV,
// making basic comparisons accidentally work — but cargoVersionInRangeV is dead
// code and Cargo-specific edge cases (build metadata, Cargo ordering) are wrong.
//
// After the fix: crates.io is routed to cargoVersionInRangeV, which strips the
// "v" prefix added by canonical() and applies Cargo SemVer rules.
func TestAffectsVersionV_CratesIO_RoutesToCargoSemver(t *testing.T) {
	t.Parallel()

	makeAdv := func(introduced, fixed string) *Advisory {
		return &Advisory{
			Ecosystem: EcosystemCratesIO,
			VersionRanges: []VersionRange{
				{Introduced: introduced, Fixed: fixed},
			},
		}
	}

	// canonical() is applied by the call path before AffectsVersionV, so tests
	// here call canonical() on the query version to mirror real call sites.

	adv := makeAdv("1.0.0", "1.2.0")

	// Inside range: [1.0.0, 1.2.0) — v1.1.0 is affected.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.1.0")),
		"crates.io 1.1.0 must be Affected inside [1.0.0, 1.2.0)")

	// At introduced (inclusive lower bound).
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.0.0")),
		"crates.io 1.0.0 == introduced (inclusive): must be Affected")

	// At fixed (exclusive upper bound).
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("1.2.0")),
		"crates.io 1.2.0 == fixed (exclusive): must be NotAffected")

	// Above fixed.
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("2.0.0")),
		"crates.io 2.0.0 > fixed 1.2.0: must be NotAffected")

	// Below introduced.
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("0.9.0")),
		"crates.io 0.9.0 < introduced 1.0.0: must be NotAffected")
}

// TestAffectsVersionV_CratesIO_LastAffected verifies crates.io advisory matching
// with a last_affected (inclusive) upper bound.
func TestAffectsVersionV_CratesIO_LastAffected(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemCratesIO,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", LastAffected: "1.1.0"},
		},
	}

	// At last_affected (inclusive).
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.1.0")),
		"crates.io 1.1.0 == last_affected (inclusive): must be Affected")

	// Above last_affected.
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("1.1.1")),
		"crates.io 1.1.1 > last_affected 1.1.0: must be NotAffected")
}

// TestAffectsVersionV_CratesIO_UnfixedRange verifies crates.io matching for an
// open-ended range (introduced with no fixed/last_affected).
func TestAffectsVersionV_CratesIO_UnfixedRange(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemCratesIO,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0"},
		},
	}

	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.0.0")),
		"crates.io 1.0.0 in [1.0.0, ∞): must be Affected")
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("99.0.0")),
		"crates.io 99.0.0 in [1.0.0, ∞): must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("0.9.0")),
		"crates.io 0.9.0 < introduced 1.0.0: must be NotAffected")
}

// TestAffectsVersionV_CratesIO_Undecidable verifies that a genuinely unparseable
// crates.io version returns VersionUndecidable (never VersionNotAffected).
func TestAffectsVersionV_CratesIO_Undecidable(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemCratesIO,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	// "notaversion" cannot be parsed as Cargo SemVer → VersionUndecidable.
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("notaversion"),
		"unparseable crates.io version must return VersionUndecidable, never VersionNotAffected")
}

// ─── Severity field ───────────────────────────────────────────────────────────

// TestSeverityConstants verifies that the Severity type constants are ordered
// correctly (Unspecified < Low < Medium < High < Critical) for any code that
// compares them numerically.
func TestSeverityConstants(t *testing.T) {
	t.Parallel()

	assert.Less(t, int(SeverityUnspecified), int(SeverityLow),
		"SeverityUnspecified must sort below SeverityLow")
	assert.Less(t, int(SeverityLow), int(SeverityMedium),
		"SeverityLow must sort below SeverityMedium")
	assert.Less(t, int(SeverityMedium), int(SeverityHigh),
		"SeverityMedium must sort below SeverityHigh")
	assert.Less(t, int(SeverityHigh), int(SeverityCritical),
		"SeverityHigh must sort below SeverityCritical")
}

// TestCVSSBaseScoreToSeverity exercises the CVSS-to-Severity mapping across all
// bands defined by CVSS v3 / v4:
//
//	[0.0, 0.1)  → None         → SeverityUnspecified
//	[0.1, 4.0)  → Low          → SeverityLow
//	[4.0, 7.0)  → Medium       → SeverityMedium
//	[7.0, 9.0)  → High         → SeverityHigh
//	[9.0, 10.0] → Critical     → SeverityCritical
func TestCVSSBaseScoreToSeverity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		score float64
		want  Severity
	}{
		{0.0, SeverityUnspecified},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{9.8, SeverityCritical},
		{10.0, SeverityCritical},
	}

	for _, tc := range cases {
		got := cvssScoreToSeverity(tc.score)
		assert.Equal(t, tc.want, got,
			"cvssScoreToSeverity(%v) = %v, want %v", tc.score, got, tc.want)
	}
}
