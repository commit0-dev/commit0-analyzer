package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHexVersionInRangeV covers Hex (Elixir/Erlang) SemVer 2.0 semantics for
// the OSV introduced/fixed/last_affected event model.
//
// Hex enforces strict SemVer 2.0 — versions never carry a "v" prefix in the
// Hex registry, but canonical() may add one upstream; the comparator strips it.
//
// Boundary rules:
//   - [Introduced, Fixed)  — introduced inclusive, fixed exclusive.
//   - [Introduced, LastAffected] — introduced inclusive, last_affected inclusive.
//   - Prerelease ordering: SemVer §11.1 — release beats prerelease of same
//     major.minor.patch (1.0.0 > 1.0.0-alpha).
func TestHexVersionInRangeV(t *testing.T) {
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
		{name: "fixed_boundary_exact", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		{name: "just_below_fixed", version: "1.2.2", introduced: "", fixed: "1.2.3", want: VersionAffected},
		{name: "just_above_fixed", version: "1.2.4", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── With introduced bound ──────────────────────────────────────────────
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

		// ── Prerelease ordering (SemVer §11.1: release beats prerelease) ──────
		// Prerelease of the fixed version is still in the range because
		// "1.2.3-alpha" < "1.2.3" (release), so it is strictly less than fixed.
		{name: "prerelease_of_fixed_is_affected", version: "1.2.3-alpha.1", introduced: "", fixed: "1.2.3", want: VersionAffected},
		// Release at exact fixed boundary is not affected.
		{name: "release_at_fixed_not_affected", version: "1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// Prerelease above fixed is outside the range.
		{name: "prerelease_above_fixed_not_affected", version: "1.2.4-beta.0", introduced: "", fixed: "1.2.3", want: VersionNotAffected},
		// Prerelease at exactly the introduced bound is still within range (inclusive).
		{name: "prerelease_at_introduced", version: "1.0.0-alpha", introduced: "1.0.0-alpha", fixed: "1.0.0", want: VersionAffected},
		// Prerelease below the introduced bound is not affected.
		{name: "prerelease_below_introduced", version: "1.0.0-alpha", introduced: "1.0.0", fixed: "2.0.0", want: VersionNotAffected},

		// ── LastAffected (inclusive upper bound) ──────────────────────────────
		{name: "last_affected_at_bound", version: "1.2.3", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},
		{name: "last_affected_above_bound", version: "1.2.4", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionNotAffected},
		{name: "last_affected_below_bound", version: "1.2.2", introduced: "", fixed: "", lastAff: "1.2.3", want: VersionAffected},

		// ── v-prefixed versions: stripped by the comparator ───────────────────
		// canonical() may add a "v" prefix upstream; hexVersionInRangeV strips it.
		{name: "v_prefixed_version_stripped_affected", version: "v1.1.0", introduced: "1.0.0", fixed: "1.2.0", want: VersionAffected},
		{name: "v_prefixed_version_stripped_not_affected", version: "v2.0.0", introduced: "1.0.0", fixed: "1.5.0", want: VersionNotAffected},
		{name: "v_prefixed_at_fixed_not_affected", version: "v1.2.3", introduced: "", fixed: "1.2.3", want: VersionNotAffected},

		// ── Parse errors → VersionUndecidable ────────────────────────────────
		// An empty query version is unparseable.
		{name: "empty_version_undecidable", version: "", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		// A non-semver string is unparseable.
		{name: "garbage_version_undecidable", version: "not-a-version", introduced: "", fixed: "1.0.0", want: VersionUndecidable},
		// A malformed Introduced bound is undecidable.
		{name: "bad_introduced_undecidable", version: "1.0.0", introduced: "bad", fixed: "2.0.0", want: VersionUndecidable},
		// A malformed Fixed bound is undecidable.
		{name: "bad_fixed_undecidable", version: "1.0.0", introduced: "0.1.0", fixed: "nope", want: VersionUndecidable},
		// A malformed LastAffected bound is undecidable.
		{name: "bad_last_affected_undecidable", version: "1.0.0", introduced: "", fixed: "", lastAff: "nope", want: VersionUndecidable},
		// A partial version (only major.minor) is not valid SemVer.
		{name: "partial_version_undecidable", version: "1.2", introduced: "", fixed: "1.3.0", want: VersionUndecidable},

		// ── Real-world Hex advisory shapes ────────────────────────────────────
		// Tesla HTTP client advisory (CVE-2026-48595 from research report):
		// affected range: >=0.1.0, <0.1.9 (hypothetical example shape).
		{name: "tesla_in_range", version: "0.1.5", introduced: "0.1.0", fixed: "0.1.9", want: VersionAffected},
		{name: "tesla_at_fix", version: "0.1.9", introduced: "0.1.0", fixed: "0.1.9", want: VersionNotAffected},
		{name: "tesla_before_intro", version: "0.0.9", introduced: "0.1.0", fixed: "0.1.9", want: VersionNotAffected},
		// Unbounded upper range (no fix yet).
		{name: "unbounded_upper_current_vuln", version: "2.5.0", introduced: "1.0.0", fixed: "", want: VersionAffected},
		// Common Hex version shape: three-part with minor prerelease tags.
		{name: "phoenix_style_prerelease_rc", version: "1.7.0-rc.0", introduced: "1.7.0-rc.0", fixed: "1.7.0", want: VersionAffected},
		{name: "phoenix_style_release_beats_rc", version: "1.7.0", introduced: "1.7.0-rc.0", fixed: "1.7.0", want: VersionNotAffected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := VersionRange{
				Introduced:   tc.introduced,
				Fixed:        tc.fixed,
				LastAffected: tc.lastAff,
			}
			got := hexVersionInRangeV(tc.version, r)
			assert.Equal(t, tc.want, got,
				"hexVersionInRangeV(%q, intro=%q fixed=%q lastAff=%q)",
				tc.version, tc.introduced, tc.fixed, tc.lastAff)
		})
	}
}

// TestHexVersionInRangeV_MultiRange verifies multi-range OR logic and the
// Undecidable propagation invariant directly against hexVersionInRangeV.
func TestHexVersionInRangeV_MultiRange(t *testing.T) {
	t.Parallel()

	// Hypothetical two-range advisory: >=1.0.0,<1.2.0 | >=2.0.0,<2.1.0
	ranges := []VersionRange{
		{Introduced: "1.0.0", Fixed: "1.2.0"},
		{Introduced: "2.0.0", Fixed: "2.1.0"},
	}

	hexInRanges := func(ver string, rs []VersionRange) VersionVerdict {
		hasUndecidable := false
		for _, r := range rs {
			switch v := hexVersionInRangeV(ver, r); v {
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

	assert.Equal(t, VersionAffected, hexInRanges("1.1.0", ranges), "in first range")
	assert.Equal(t, VersionAffected, hexInRanges("2.0.5", ranges), "in second range")
	assert.Equal(t, VersionNotAffected, hexInRanges("1.2.0", ranges), "at fixed of first range")
	assert.Equal(t, VersionNotAffected, hexInRanges("2.1.0", ranges), "at fixed of second range")
	assert.Equal(t, VersionNotAffected, hexInRanges("3.0.0", ranges), "above both ranges")
	assert.Equal(t, VersionNotAffected, hexInRanges("0.9.0", ranges), "below both ranges")

	// Undecidable propagation: bad bound → Undecidable, never NotAffected.
	badRange := []VersionRange{{Introduced: "1.0.0", Fixed: "bad-version"}}
	assert.Equal(t, VersionUndecidable, hexInRanges("1.0.5", badRange),
		"bad fixed bound must yield Undecidable, never NotAffected")

	// Affected short-circuits even when another range is Undecidable.
	mixedRanges := []VersionRange{
		{Introduced: "bad", Fixed: "1.0.0"},      // Undecidable
		{Introduced: "0.5.0", Fixed: "1.5.0"},    // 1.0.0 is in [0.5.0, 1.5.0)
	}
	assert.Equal(t, VersionAffected, hexInRanges("1.0.0", mixedRanges),
		"Affected range short-circuits even when another range is Undecidable")
}

// TestHexComparatorRegistered verifies that the Hex ecosystem is registered in
// the comparator registry after package init(), and that AffectsVersionV routes
// through it correctly.
func TestHexComparatorRegistered(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, lookupComparator(EcosystemHex),
		"EcosystemHex must have a registered comparator after init()")

	adv := &Advisory{
		Ecosystem:     EcosystemHex,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	// AffectsVersionV with a bare version (no "v" prefix, as Hex uses).
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("1.5.0"),
		"Hex 1.5.0 inside [1.0.0, 2.0.0) must route to Affected via the registry")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.0.0"),
		"Hex 2.0.0 == fixed (exclusive) must route to NotAffected via the registry")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("0.9.0"),
		"Hex 0.9.0 < introduced 1.0.0 must route to NotAffected via the registry")
	// canonical() may add "v" prefix; the comparator must handle it.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.5.0")),
		"v-prefixed Hex version must be handled after canonical() normalization")
	// Unparseable version must not silently become NotAffected.
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("not-a-semver"),
		"unparseable Hex version must propagate as VersionUndecidable")
}
