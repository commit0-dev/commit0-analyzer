package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSwiftVersionInRangeV covers SwiftURL SemVer 2.0 semantics for the OSV
// introduced/fixed/last_affected event model.
//
// SwiftPM enforces strict SemVer 2.0 — versions never carry a "v" prefix in
// Package.resolved, but canonical() may add one upstream; the comparator strips it.
//
// Boundary rules:
//   - [Introduced, Fixed)       — introduced inclusive, fixed exclusive.
//   - [Introduced, LastAffected] — introduced inclusive, last_affected inclusive.
//   - Prerelease ordering: SemVer §11.1 — release beats prerelease of same
//     major.minor.patch (1.0.0 > 1.0.0-alpha).
func TestSwiftVersionInRangeV(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		version    string
		introduced string // empty = since the beginning
		fixed      string // empty = unfixed / open upper bound
		lastAff    string // empty = not used
		want       VersionVerdict
	}{
		// ── Basic boundary: fixed is exclusive ─────────────────────────────────
		{name: "fixed_boundary_exact", version: "2.42.0", introduced: "", fixed: "2.42.0", want: VersionNotAffected},
		{name: "just_below_fixed", version: "2.41.9", introduced: "", fixed: "2.42.0", want: VersionAffected},
		{name: "just_above_fixed", version: "2.43.0", introduced: "", fixed: "2.42.0", want: VersionNotAffected},

		// ── With introduced bound (mirrors real GHSA-7fj7-39wj-c64f range) ────
		{name: "in_range_with_intro", version: "2.41.0", introduced: "2.41.0", fixed: "2.42.0", want: VersionAffected},
		{name: "at_introduced_inclusive", version: "2.41.0", introduced: "2.41.0", fixed: "2.42.0", want: VersionAffected},
		{name: "before_introduced", version: "2.40.9", introduced: "2.41.0", fixed: "2.42.0", want: VersionNotAffected},
		{name: "at_fixed_exclusive", version: "2.42.0", introduced: "2.41.0", fixed: "2.42.0", want: VersionNotAffected},

		// ── Open upper bound (unfixed) ────────────────────────────────────────
		{name: "unfixed_high_version", version: "99.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_at_introduced", version: "1.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_before_intro", version: "0.9.9", introduced: "1.0.0", fixed: "", want: VersionNotAffected},

		// ── Open lower bound ──────────────────────────────────────────────────
		{name: "no_lower_bound_low_ver", version: "0.0.1", introduced: "", fixed: "1.0.0", want: VersionAffected},
		{name: "no_lower_bound_at_fixed", version: "1.0.0", introduced: "", fixed: "1.0.0", want: VersionNotAffected},

		// ── Both bounds empty ─────────────────────────────────────────────────
		{name: "both_empty_all_affected", version: "2.41.0", introduced: "", fixed: "", want: VersionAffected},
		{name: "both_empty_zero_version", version: "0.0.0", introduced: "", fixed: "", want: VersionAffected},

		// ── LastAffected (inclusive upper bound) ──────────────────────────────
		{name: "lastaffected_at_bound", version: "2.41.0", introduced: "", lastAff: "2.41.0", want: VersionAffected},
		{name: "lastaffected_above_bound", version: "2.41.1", introduced: "", lastAff: "2.41.0", want: VersionNotAffected},
		{name: "lastaffected_below_bound", version: "2.40.0", introduced: "", lastAff: "2.41.0", want: VersionAffected},

		// ── Prerelease ordering ───────────────────────────────────────────────
		{name: "prerelease_below_release", version: "1.0.0-beta.1", introduced: "", fixed: "1.0.0", want: VersionAffected},
		{name: "release_at_fixed", version: "1.0.0", introduced: "", fixed: "1.0.0", want: VersionNotAffected},
		{name: "prerelease_before_introduced", version: "0.9.0-rc.1", introduced: "1.0.0", fixed: "", want: VersionNotAffected},

		// ── v-prefix stripping (canonical() may add "v" upstream) ─────────────
		{name: "v_prefix_in_range", version: "v2.41.0", introduced: "2.41.0", fixed: "2.42.0", want: VersionAffected},
		{name: "v_prefix_at_fixed", version: "v2.42.0", introduced: "2.41.0", fixed: "2.42.0", want: VersionNotAffected},

		// ── Invalid / undecidable versions ───────────────────────────────────
		{name: "empty_version", version: "", introduced: "1.0.0", fixed: "2.0.0", want: VersionUndecidable},
		{name: "non_semver_version", version: "not-a-version", introduced: "1.0.0", fixed: "2.0.0", want: VersionUndecidable},
		{name: "invalid_introduced", version: "1.5.0", introduced: "bad", fixed: "2.0.0", want: VersionUndecidable},
		{name: "invalid_fixed", version: "1.5.0", introduced: "1.0.0", fixed: "bad", want: VersionUndecidable},
		{name: "invalid_lastaffected", version: "1.5.0", introduced: "", lastAff: "not-valid", want: VersionUndecidable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := VersionRange{
				Introduced:   tc.introduced,
				Fixed:        tc.fixed,
				LastAffected: tc.lastAff,
			}
			got := swiftVersionInRangeV(tc.version, r)
			assert.Equal(t, tc.want, got,
				"swiftVersionInRangeV(%q, {Introduced:%q, Fixed:%q, LastAffected:%q})",
				tc.version, tc.introduced, tc.fixed, tc.lastAff)
		})
	}
}

// TestSwiftVersionComparatorRegistered verifies that the SwiftURL comparator is
// registered in the shared registry so it can be looked up at query time.
func TestSwiftVersionComparatorRegistered(t *testing.T) {
	fn := lookupComparator(EcosystemSwiftURL)
	assert.NotNil(t, fn, "SwiftURL comparator must be registered via init()")
}
