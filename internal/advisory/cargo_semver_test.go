package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCargoVersionInRangeV covers crates.io semver semantics for the OSV
// introduced/fixed event model.  Cargo versions never carry a "v" prefix.
//
// Boundary rule: [Introduced, Fixed) — introduced inclusive, fixed exclusive.
// Prerelease ordering: a release version beats a prerelease of the same
// [major.minor.patch] tuple (1.0.0 > 1.0.0-alpha per SemVer §11.1).
func TestCargoVersionInRangeV(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		version    string
		introduced string // empty = since the beginning
		fixed      string // empty = unfixed / open upper bound
		lastAff    string // empty = not used
		want       VersionVerdict
	}{
		// ── Basic boundary: fixed is exclusive ──────────────────────────────
		{name: "fixed_boundary_exact", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		{name: "just_below_fixed", version: "1.2.2", introduced: "", fixed: "1.2.3", want: VersionAffected},
		{name: "just_above_fixed", version: "1.2.4", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── With introduced bound ────────────────────────────────────────────
		{name: "in_range_with_intro", version: "1.1.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "at_introduced_inclusive", version: "1.0.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "before_introduced", version: "0.9.9", introduced: "1.0.0", fixed: "1.2.0", want: VersionNotAffected},

		// ── Open upper bound (unfixed) ───────────────────────────────────────
		{name: "unfixed_high_version", version: "99.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_at_introduced", version: "1.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_before_intro", version: "0.9.9", introduced: "1.0.0", fixed: "", want: VersionNotAffected},

		// ── Open lower bound ────────────────────────────────────────────────
		{name: "no_lower_bound_low_ver", version: "0.0.1", introduced: "", fixed: "1.0.0", want: VersionAffected},
		{name: "no_lower_bound_at_fixed", version: "1.0.0", introduced: "", fixed: "1.0.0", want: VersionNotAffected},

		// ── Both bounds empty ────────────────────────────────────────────────
		{name: "both_empty_all_affected", version: "1.2.3", introduced: "", fixed: "", want: VersionAffected},
		{name: "both_empty_zero_version", version: "0.0.0", introduced: "", fixed: "", want: VersionAffected},

		// ── Patch ordering ───────────────────────────────────────────────────
		{name: "patch_ordering_in_range", version: "1.0.10", introduced: "", fixed: "1.0.11", want: VersionAffected},
		{name: "patch_ordering_at_fixed", version: "1.0.11", introduced: "", fixed: "1.0.11", want: VersionNotAffected},
		{name: "patch_ordering_above_fixed", version: "1.0.12", introduced: "", fixed: "1.0.11", want: VersionNotAffected},

		// ── Major version ordering ───────────────────────────────────────────
		{name: "major_above_fixed", version: "2.0.0", introduced: "", fixed: "1.5.0", want: VersionNotAffected},
		{name: "major_below_introduced", version: "0.9.0", introduced: "1.0.0", fixed: "1.5.0", want: VersionNotAffected},

		// ── Prerelease ordering (SemVer §11.1: release beats prerelease) ─────
		// A prerelease of the FIXED version is still in the affected range because
		// "1.2.3-alpha" < "1.2.3" (release), so it is strictly less than fixed.
		{name: "prerelease_of_fixed_is_affected", version: "1.2.3-alpha.1", introduced: "", fixed: "1.2.3", want: VersionAffected},
		// A release version at exact fixed boundary is not affected.
		{name: "release_at_fixed_not_affected", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// Prerelease of version ABOVE fixed is outside the range.
		{name: "prerelease_above_fixed_not_affected", version: "1.2.4-beta.0", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// A prerelease at exactly the introduced bound is still within range (inclusive).
		{name: "prerelease_at_introduced", version: "1.0.0-alpha", introduced: "1.0.0-alpha", fixed: "1.0.0", want: VersionAffected},
		// A prerelease below the introduced bound is not affected.
		{name: "prerelease_below_introduced", version: "1.0.0-alpha", introduced: "1.0.0", fixed: "2.0.0", want: VersionNotAffected},
		// Fixed-boundary exclusivity with prerelease introduced bound.
		{name: "prerelease_range_lower_open", version: "0.3.0", introduced: "0.2.0-beta", fixed: "0.4.0", want: VersionAffected},

		// ── LastAffected (inclusive upper bound) ─────────────────────────────
		{name: "last_affected_at_bound", version: "1.2.3", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},
		{name: "last_affected_above_bound", version: "1.2.4", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionNotAffected},
		{name: "last_affected_below_bound", version: "1.2.2", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},

		// ── Parse errors → VersionUndecidable ───────────────────────────────
		// An empty query version is unparseable.
		{name: "empty_version_undecidable", version: "", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		// A non-semver string is unparseable.
		{name: "garbage_version_undecidable", version: "not-a-version", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		// A malformed Introduced bound is unparseable.
		{name: "bad_introduced_undecidable", version: "1.0.0", introduced: "bad", fixed: "2.0.0", want: VersionUndecidable},
		// A malformed Fixed bound is unparseable.
		{name: "bad_fixed_undecidable", version: "1.0.0", introduced: "0.1.0", fixed: "nope", want: VersionUndecidable},
		// A malformed LastAffected bound is unparseable.
		{name: "bad_last_affected_undecidable", version: "1.0.0", introduced: "", fixed: "", lastAff: "nope", want: VersionUndecidable},
		// A v-prefixed version (Go convention) must NOT be accepted by the Cargo
		// comparator — Cargo versions never carry a "v" prefix, so the input is
		// malformed and must return VersionUndecidable rather than silently matching.
		{name: "v_prefix_undecidable", version: "v1.0.0", introduced: "", fixed: "2.0.0", want: VersionUndecidable},
		// A partial version (only major.minor) is not valid SemVer.
		{name: "partial_version_undecidable", version: "1.2", introduced: "", fixed: "1.3.0", want: VersionUndecidable},

		// ── Real-world crates.io advisory shapes ─────────────────────────────
		// time crate RUSTSEC-2020-0071: >=0.1.0, <0.1.43 | >=0.2.0, <0.2.23
		// First range only (second tested separately).
		{name: "time_crate_in_range", version: "0.1.23", introduced: "0.1.0", fixed: "0.1.43", want: VersionAffected},
		{name: "time_crate_at_fix", version: "0.1.43", introduced: "0.1.0", fixed: "0.1.43", want: VersionNotAffected},
		{name: "time_crate_before_intro", version: "0.0.9", introduced: "0.1.0", fixed: "0.1.43", want: VersionNotAffected},
		// openssl 0.x unbounded range (no fix yet as of some advisories).
		{name: "unbounded_upper_current_vuln", version: "0.10.55", introduced: "0.10.0", fixed: "", want: VersionAffected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := VersionRange{
				Introduced:   tc.introduced,
				Fixed:        tc.fixed,
				LastAffected: tc.lastAff,
			}
			got := cargoVersionInRangeV(tc.version, r)
			assert.Equal(t, tc.want, got, "cargoVersionInRangeV(%q, intro=%q fixed=%q lastAff=%q)",
				tc.version, tc.introduced, tc.fixed, tc.lastAff)
		})
	}
}

// TestCargoVersionInRangeVMultiRange verifies multi-range OR logic and the
// Undecidable propagation invariant directly against cargoVersionInRangeV.
// (Advisory.AffectsVersionV routing for EcosystemCratesIO is wired in Phase 1;
// this node only owns the comparator function itself.)
func TestCargoVersionInRangeVMultiRange(t *testing.T) {
	t.Parallel()

	// time crate RUSTSEC-2020-0071: >=0.1.0,<0.1.43 | >=0.2.0,<0.2.23
	ranges := []VersionRange{
		{Introduced: "0.1.0", Fixed: "0.1.43"},
		{Introduced: "0.2.0", Fixed: "0.2.23"},
	}

	cargoInRanges := func(ver string, rs []VersionRange) VersionVerdict {
		hasUndecidable := false
		for _, r := range rs {
			switch v := cargoVersionInRangeV(ver, r); v {
			case VersionAffected:
				return VersionAffected
			case VersionUndecidable:
				hasUndecidable = true
			}
		}
		if hasUndecidable {
			return VersionUndecidable
		}
		return VersionNotAffected
	}

	assert.Equal(t, VersionAffected, cargoInRanges("0.1.23", ranges), "in first range")
	assert.Equal(t, VersionAffected, cargoInRanges("0.2.10", ranges), "in second range")
	assert.Equal(t, VersionNotAffected, cargoInRanges("0.1.43", ranges), "at fixed of first range")
	assert.Equal(t, VersionNotAffected, cargoInRanges("0.2.23", ranges), "at fixed of second range")
	assert.Equal(t, VersionNotAffected, cargoInRanges("0.3.0", ranges), "above both ranges")
	assert.Equal(t, VersionNotAffected, cargoInRanges("0.0.9", ranges), "below both ranges")

	// Undecidable propagation: bad bound in the only range → Undecidable.
	badRange := []VersionRange{{Introduced: "0.1.0", Fixed: "bad-version"}}
	assert.Equal(t, VersionUndecidable, cargoInRanges("0.1.5", badRange),
		"bad fixed bound must yield Undecidable, never NotAffected")

	// Multi-range: first range Undecidable, second Affected → Affected wins
	// (Affected short-circuits, matching the AffectsVersionV loop contract).
	mixedRanges := []VersionRange{
		{Introduced: "bad", Fixed: "1.0.0"}, // Undecidable
		{Introduced: "0.5.0", Fixed: "1.5.0"}, // 1.0.0 is in [0.5.0, 1.5.0)
	}
	assert.Equal(t, VersionAffected, cargoInRanges("1.0.0", mixedRanges),
		"Affected range short-circuits even when another range is Undecidable")
}
