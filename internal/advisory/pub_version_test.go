package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPubVersionInRangeV covers Pub (Dart/Flutter) SemVer 2.0 semantics for
// the OSV introduced/fixed/last_affected event model.
//
// Dart/Flutter versions on pub.dev are bare SemVer (no "v" prefix), but
// canonical() may add one upstream; pubVersionInRangeV strips it.
//
// The caret constraint (^1.2.3) appears only in pubspec.yaml at authoring time
// and is resolved to exact versions in pubspec.lock; the comparator operates
// against those exact resolved versions, so no caret handling is needed here.
//
// Boundary rules:
//   - [Introduced, Fixed)  — introduced inclusive, fixed exclusive.
//   - [Introduced, LastAffected] — introduced inclusive, last_affected inclusive.
//   - Prerelease ordering: SemVer §11.1 — release beats prerelease of same
//     major.minor.patch (1.0.0 > 1.0.0-beta).
func TestPubVersionInRangeV(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		version    string
		introduced string // empty = since the beginning
		fixed      string // empty = unfixed / open upper bound
		lastAff    string // empty = not used
		want       VersionVerdict
	}{
		// ── Basic boundary: fixed is exclusive ────────────────────────────────
		{name: "fixed_boundary_exact", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		{name: "just_below_fixed", version: "1.2.2", introduced: "", fixed: "1.2.3", want: VersionAffected},
		{name: "just_above_fixed", version: "1.2.4", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── With introduced bound ─────────────────────────────────────────────
		{name: "in_range_with_intro", version: "1.1.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "at_introduced_inclusive", version: "1.0.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "before_introduced", version: "0.9.9", introduced: "1.0.0", fixed: "1.2.0", want: VersionNotAffected},

		// ── Open upper bound (unfixed) ────────────────────────────────────────
		{name: "unfixed_high_version", version: "99.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_at_introduced", version: "1.0.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		{name: "unfixed_before_intro", version: "0.9.9", introduced: "1.0.0", fixed: "", want: VersionNotAffected},

		// ── Open lower bound ──────────────────────────────────────────────────
		{name: "no_lower_bound_low_ver", version: "0.0.1", introduced: "", fixed: "1.0.0", want: VersionAffected},
		{name: "no_lower_bound_at_fixed", version: "1.0.0", introduced: "", fixed: "1.0.0", want: VersionNotAffected},

		// ── Both bounds empty ─────────────────────────────────────────────────
		{name: "both_empty_all_affected", version: "1.2.3", introduced: "", fixed: "", want: VersionAffected},
		{name: "both_empty_zero_version", version: "0.0.0", introduced: "", fixed: "", want: VersionAffected},

		// ── Patch ordering ────────────────────────────────────────────────────
		{name: "patch_ordering_in_range", version: "1.0.10", introduced: "", fixed: "1.0.11", want: VersionAffected},
		{name: "patch_ordering_at_fixed", version: "1.0.11", introduced: "", fixed: "1.0.11", want: VersionNotAffected},
		{name: "patch_ordering_above_fixed", version: "1.0.12", introduced: "", fixed: "1.0.11", want: VersionNotAffected},

		// ── Major version ordering ────────────────────────────────────────────
		{name: "major_above_fixed", version: "2.0.0", introduced: "", fixed: "1.5.0", want: VersionNotAffected},
		{name: "major_below_introduced", version: "0.9.0", introduced: "1.0.0", fixed: "1.5.0", want: VersionNotAffected},

		// ── Pre-1.0 packages (Dart treats 0.MINOR.PATCH as breaking in caret
		//    constraints, but the comparator operates on raw SemVer ordering,
		//    which is identical regardless of major version).
		{name: "pre_1_0_in_range", version: "0.3.2", introduced: "0.3.0", fixed: "0.4.0", want: VersionAffected},
		{name: "pre_1_0_at_fixed", version: "0.4.0", introduced: "0.3.0", fixed: "0.4.0", want: VersionNotAffected},
		{name: "pre_1_0_before_intro", version: "0.2.9", introduced: "0.3.0", fixed: "0.4.0", want: VersionNotAffected},

		// ── Prerelease ordering (SemVer §11.1: release beats prerelease) ──────
		// Prerelease of the fixed version is still in the range because
		// "1.2.3-beta.1" < "1.2.3" (release), so strictly less than fixed.
		{name: "prerelease_of_fixed_is_affected", version: "1.2.3-beta.1", introduced: "", fixed: "1.2.3", want: VersionAffected},
		// Release at exact fixed boundary is not affected.
		{name: "release_at_fixed_not_affected", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// Prerelease above fixed is outside the range.
		{name: "prerelease_above_fixed_not_affected", version: "1.2.4-dev.0", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// Prerelease at exactly the introduced bound is within range (inclusive).
		{name: "prerelease_at_introduced", version: "1.0.0-alpha", introduced: "1.0.0-alpha", fixed: "1.0.0", want: VersionAffected},
		// Prerelease below the introduced bound is not affected.
		{name: "prerelease_below_introduced", version: "1.0.0-alpha", introduced: "1.0.0", fixed: "2.0.0", want: VersionNotAffected},

		// ── LastAffected (inclusive upper bound) ──────────────────────────────
		{name: "last_affected_at_bound", version: "1.2.3", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},
		{name: "last_affected_above_bound", version: "1.2.4", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionNotAffected},
		{name: "last_affected_below_bound", version: "1.2.2", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},

		// ── v-prefixed versions: stripped by the comparator ───────────────────
		// canonical() may add a "v" prefix upstream; pubVersionInRangeV strips it.
		{name: "v_prefixed_version_stripped_affected", version: "v1.1.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "v_prefixed_version_stripped_not_affected", version: "v2.0.0", introduced: "1.0.0", fixed: "1.5.0", want: VersionNotAffected},
		{name: "v_prefixed_at_fixed_not_affected", version: "v1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── Parse errors → VersionUndecidable (NEVER VersionNotAffected) ──────
		// Contract: any parse failure must yield Undecidable so callers emit
		// UNKNOWN + incomplete=true instead of silently dropping the advisory.
		{name: "empty_version_undecidable", version: "", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		{name: "garbage_version_undecidable", version: "not-a-version", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		{name: "bad_introduced_undecidable", version: "1.0.0", introduced: "bad", fixed: "2.0.0", want: VersionUndecidable},
		{name: "bad_fixed_undecidable", version: "1.0.0", introduced: "0.1.0", fixed: "nope", want: VersionUndecidable},
		{name: "bad_last_affected_undecidable", version: "1.0.0", introduced: "", fixed: "", lastAff: "nope", want: VersionUndecidable},
		{name: "partial_version_undecidable", version: "1.2", introduced: "", fixed: "1.3.0", want: VersionUndecidable},

		// ── Build metadata ordering (the fix for pub_semver correctness) ────────
		// Pub (pub_semver) treats build metadata as SIGNIFICANT and ORDERED,
		// unlike SemVer 2.0 / Cargo which discard it.
		//   • A version WITHOUT build sorts BEFORE the same version WITH build.
		//   • Build identifier lists are compared the same way as pre-release
		//     lists: numeric identifiers numerically, others lexically (ASCII),
		//     numeric < alphanumeric, longer list wins when all prior equal.

		// 1.2.3 < 1.2.3+1  (no-build before with-build)
		{name: "build_no_build_before_with_build", version: "1.2.3", introduced: "1.2.3+1", fixed: "", want: VersionNotAffected},
		// THE BUG CASE: installed=1.2.3+1, fixed=1.2.3+2  → 1.2.3+1 < 1.2.3+2 → Affected
		{name: "build_bug_installed_1_fixed_2", version: "1.2.3+1", introduced: "", fixed: "1.2.3+2", want: VersionAffected},
		// installed=1.2.3+2 == fixed=1.2.3+2 → exclusive → NotAffected
		{name: "build_at_fixed_not_affected", version: "1.2.3+2", introduced: "", fixed: "1.2.3+2", want: VersionNotAffected},
		// 1.2.3+3 < 1.2.3+5 (numeric comparison of build ids)
		{name: "build_numeric_3_lt_5", version: "1.2.3+3", introduced: "", fixed: "1.2.3+5", want: VersionAffected},
		// 1.2.3+1 < 1.2.3+1.1 (longer list wins)
		{name: "build_shorter_list_lt_longer", version: "1.2.3+1", introduced: "", fixed: "1.2.3+1.1", want: VersionAffected},
		// installed=1.2.3+1, fixed=1.2.3 (no build) → 1.2.3+1 > 1.2.3 → installed ≥ fixed → NotAffected
		{name: "build_installed_with_build_fixed_no_build", version: "1.2.3+1", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── Real-world Pub advisory shapes ────────────────────────────────────
		// dart_sass advisory (hypothetical shape matching OSV Pub records):
		// affected range: >=1.0.0, <1.57.0
		{name: "dart_sass_in_range", version: "1.56.0", introduced: "1.0.0", fixed: "1.57.0", want: VersionAffected},
		{name: "dart_sass_at_fix", version: "1.57.0", introduced: "1.0.0", fixed: "1.57.0", want: VersionNotAffected},
		{name: "dart_sass_before_intro", version: "0.9.9", introduced: "1.0.0", fixed: "1.57.0", want: VersionNotAffected},
		// Unbounded upper range (no fix yet).
		{name: "unbounded_upper_current_vuln", version: "2.5.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		// Flutter package with prerelease dev tag.
		{name: "flutter_prerelease_dev_rc", version: "3.10.0-0.3.pre", introduced: "3.10.0-0.3.pre", fixed: "3.10.0", want: VersionAffected},
		{name: "flutter_release_beats_pre", version: "3.10.0", introduced: "3.10.0-0.3.pre", fixed: "3.10.0", want: VersionNotAffected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := VersionRange{
				Introduced:   tc.introduced,
				Fixed:        tc.fixed,
				LastAffected: tc.lastAff,
			}
			got := pubVersionInRangeV(tc.version, r)
			assert.Equal(t, tc.want, got,
				"pubVersionInRangeV(%q, intro=%q fixed=%q lastAff=%q)",
				tc.version, tc.introduced, tc.fixed, tc.lastAff)
		})
	}
}

// TestPubVersionInRangeV_MultiRange verifies multi-range OR logic and the
// Undecidable propagation invariant directly against pubVersionInRangeV.
func TestPubVersionInRangeV_MultiRange(t *testing.T) {
	t.Parallel()

	// Hypothetical two-range advisory: >=1.0.0,<1.2.0 | >=2.0.0,<2.1.0
	ranges := []VersionRange{
		{Introduced: "1.0.0", Fixed: "1.2.0"},
		{Introduced: "2.0.0", Fixed: "2.1.0"},
	}

	pubInRanges := func(ver string, rs []VersionRange) VersionVerdict {
		hasUndecidable := false
		for _, r := range rs {
			switch v := pubVersionInRangeV(ver, r); v {
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

	assert.Equal(t, VersionAffected, pubInRanges("1.1.0", ranges), "in first range")
	assert.Equal(t, VersionAffected, pubInRanges("2.0.5", ranges), "in second range")
	assert.Equal(t, VersionNotAffected, pubInRanges("1.2.0", ranges), "at fixed of first range")
	assert.Equal(t, VersionNotAffected, pubInRanges("2.1.0", ranges), "at fixed of second range")
	assert.Equal(t, VersionNotAffected, pubInRanges("3.0.0", ranges), "above both ranges")
	assert.Equal(t, VersionNotAffected, pubInRanges("0.9.0", ranges), "below both ranges")

	// Undecidable propagation: bad bound → Undecidable, never NotAffected.
	badRange := []VersionRange{{Introduced: "1.0.0", Fixed: "bad-version"}}
	assert.Equal(t, VersionUndecidable, pubInRanges("1.0.5", badRange),
		"bad fixed bound must yield Undecidable, never NotAffected")

	// Affected short-circuits even when another range is Undecidable.
	mixedRanges := []VersionRange{
		{Introduced: "bad", Fixed: "1.0.0"},   // Undecidable
		{Introduced: "0.5.0", Fixed: "1.5.0"}, // 1.0.0 is in [0.5.0, 1.5.0)
	}
	assert.Equal(t, VersionAffected, pubInRanges("1.0.0", mixedRanges),
		"Affected range short-circuits even when another range is Undecidable")
}

// TestPubComparatorRegistered verifies that the Pub ecosystem is registered in
// the comparator registry after package init(), and that AffectsVersionV routes
// through it correctly.
func TestPubComparatorRegistered(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, lookupComparator(EcosystemPub),
		"EcosystemPub must have a registered comparator after init()")

	adv := &Advisory{
		Ecosystem:     EcosystemPub,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	// AffectsVersionV with a bare version (no "v" prefix, as Pub uses).
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("1.5.0"),
		"Pub 1.5.0 inside [1.0.0, 2.0.0) must route to Affected via the registry")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.0.0"),
		"Pub 2.0.0 == fixed (exclusive) must route to NotAffected via the registry")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("0.9.0"),
		"Pub 0.9.0 < introduced 1.0.0 must route to NotAffected via the registry")
	// canonical() may add "v" prefix; the comparator must handle it.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.5.0")),
		"v-prefixed Pub version must be handled after canonical() normalization")
	// Unparseable version must not silently become NotAffected.
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("not-a-semver"),
		"unparseable Pub version must propagate as VersionUndecidable")
}
