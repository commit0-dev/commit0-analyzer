package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── parseGemVersion ───────────────────────────────────────────────────────────

// TestParseGemVersion_Valid confirms that well-formed Gem::Version strings are
// parsed into the expected segment sequences.
func TestParseGemVersion_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  []gemSegment
	}{
		// Plain numeric versions.
		{
			name:  "single_zero",
			input: "0",
			want:  []gemSegment{{isStr: false, num: 0}},
		},
		{
			name:  "empty_is_zero",
			input: "",
			want:  []gemSegment{{isStr: false, num: 0}},
		},
		{
			name:  "single_digit",
			input: "1",
			want:  []gemSegment{{isStr: false, num: 1}},
		},
		{
			name:  "two_parts",
			input: "1.2",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 2},
			},
		},
		{
			name:  "three_parts",
			input: "1.2.3",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 2},
				{isStr: false, num: 3},
			},
		},
		{
			name:  "four_parts",
			input: "7.1.3.1",
			want: []gemSegment{
				{isStr: false, num: 7},
				{isStr: false, num: 1},
				{isStr: false, num: 3},
				{isStr: false, num: 1},
			},
		},

		// Letter (pre-release) segments.
		{
			name:  "pre_dot_beta",
			input: "1.0.0.beta",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 0},
				{isStr: false, num: 0},
				{isStr: true, str: "beta"},
			},
		},
		{
			name:  "pre_dot_rc1",
			input: "1.0.0.rc1",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 0},
				{isStr: false, num: 0},
				{isStr: true, str: "rc"},
				{isStr: false, num: 1},
			},
		},
		{
			name:  "pre_dot_pre",
			input: "1.2.3.pre",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 2},
				{isStr: false, num: 3},
				{isStr: true, str: "pre"},
			},
		},
		{
			name:  "pre_adjacent_alpha",
			input: "1.0.0a",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 0},
				{isStr: false, num: 0},
				{isStr: true, str: "a"},
			},
		},
		{
			name:  "pre_adjacent_rc1",
			input: "1.8.2.a10",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 8},
				{isStr: false, num: 2},
				{isStr: true, str: "a"},
				{isStr: false, num: 10},
			},
		},

		// OSV canonical "v" prefix must be stripped.
		{
			name:  "v_prefix",
			input: "v1.2.3",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 2},
				{isStr: false, num: 3},
			},
		},
		{
			name:  "V_prefix_uppercase",
			input: "V2.0.0",
			want: []gemSegment{
				{isStr: false, num: 2},
				{isStr: false, num: 0},
				{isStr: false, num: 0},
			},
		},
		{
			name:  "v_prefix_with_pre",
			input: "v1.0.0.beta",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 0},
				{isStr: false, num: 0},
				{isStr: true, str: "beta"},
			},
		},

		// Leading/trailing whitespace.
		{
			name:  "whitespace_around",
			input: "  1.2.3  ",
			want: []gemSegment{
				{isStr: false, num: 1},
				{isStr: false, num: 2},
				{isStr: false, num: 3},
			},
		},

		// Real-world RubyGems versions seen in OSV advisories.
		{
			name:  "actionpack_fixed",
			input: "7.1.3.1",
			want: []gemSegment{
				{isStr: false, num: 7},
				{isStr: false, num: 1},
				{isStr: false, num: 3},
				{isStr: false, num: 1},
			},
		},
		{
			name:  "rails_six",
			input: "6.1.7.7",
			want: []gemSegment{
				{isStr: false, num: 6},
				{isStr: false, num: 1},
				{isStr: false, num: 7},
				{isStr: false, num: 7},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseGemVersion(tc.input)
			require.NoErrorf(t, err, "parseGemVersion(%q) must not error", tc.input)
			assert.Equalf(t, tc.want, got, "parseGemVersion(%q)", tc.input)
		})
	}
}

// TestParseGemVersion_Invalid confirms that characters outside the allowed set
// (digits, ASCII letters, dots) return an error — never a silent default.
func TestParseGemVersion_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{name: "plus_suffix", input: "1.0.0+build"},
		{name: "tilde_operator", input: "~> 1.2"},
		{name: "pipe", input: "1.0|2.0"},
		{name: "hash_suffix", input: "1.0#beta"},
		{name: "underscore", input: "1_0_0"},
		{name: "dash_separator", input: "1-2-3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseGemVersion(tc.input)
			assert.Errorf(t, err, "parseGemVersion(%q) must return an error", tc.input)
		})
	}
}

// ── compareGemVersions ────────────────────────────────────────────────────────

// TestCompareGemVersions covers the core ordering rules, matching the
// assertions from the RubyGems test suite (test_gem_version.rb).
func TestCompareGemVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
		want int // negative=a<b, 0=equal, positive=a>b
	}{
		// Equivalences.
		{"equal_1.0_vs_1.0.0", "1.0", "1.0.0", 0},    // trailing zero-padding
		{"equal_1.0.0_vs_1.0.0", "1.0.0", "1.0.0", 0},
		{"equal_0_vs_0", "0", "0", 0},

		// Pure numeric ordering.
		{"numeric_lt", "1.0.0", "1.0.1", -1},
		{"numeric_gt", "1.0.1", "1.0.0", 1},
		{"major_lt", "1.9.9", "2.0.0", -1},
		{"major_gt", "2.0.0", "1.9.9", 1},
		{"four_part_lt", "7.1.3.0", "7.1.3.1", -1},
		{"four_part_gt", "7.1.3.1", "7.1.3.0", 1},

		// Core pre-release invariant: letter segment < integer segment.
		// These map to Gem::Version test assertions:
		//   assert_equal( 1, v("1.0")   <=> v("1.0.a"))   → 1.0 > 1.0.a
		//   assert_equal(-1, v("1.0.a") <=> v("1.0"))     → 1.0.a < 1.0
		{"pre_lt_release_beta", "1.0.0.beta", "1.0.0", -1},
		{"release_gt_pre_beta", "1.0.0", "1.0.0.beta", 1},
		{"pre_lt_release_a", "1.0.a", "1.0", -1},
		{"release_gt_pre_a", "1.0", "1.0.a", 1},
		{"pre_lt_release_182", "1.8.2.a", "1.8.2", -1},
		{"release_gt_pre_182", "1.8.2", "1.8.2.a", 1},
		{"pre_lt_release_rc", "1.0.0.rc1", "1.0.0", -1},
		{"pre_lt_release_pre", "1.0.0.pre", "1.0.0", -1},
		{"pre_lt_release_alpha", "1.0.0.alpha", "1.0.0", -1},

		// Pre-release ordering among themselves (lexicographic string segments).
		// assert_equal(1, v("1.8.2.b") <=> v("1.8.2.a"))
		{"pre_b_gt_a", "1.8.2.b", "1.8.2.a", 1},
		{"pre_a_lt_b", "1.8.2.a", "1.8.2.b", -1},
		{"pre_alpha_lt_beta", "1.0.0.alpha", "1.0.0.beta", -1},
		{"pre_beta_lt_rc", "1.0.0.beta", "1.0.0.rc", -1},
		{"pre_rc_lt_release", "1.0.0.rc", "1.0.0", -1},
		// Pre-release with a numeric suffix.
		// assert_equal(1, v("1.8.2.a10") <=> v("1.8.2.a9"))
		{"pre_a10_gt_a9", "1.8.2.a10", "1.8.2.a9", 1},
		{"pre_rc1_lt_rc2", "1.0.0.rc1", "1.0.0.rc2", -1},
		{"pre_rc2_lt_release", "1.0.0.rc2", "1.0.0", -1},

		// "v" prefix (OSV canonical form) must not affect ordering.
		{"v_prefix_equal", "v1.2.3", "1.2.3", 0},
		{"v_prefix_lt", "v1.2.2", "1.2.3", -1},

		// Canonical-segments equivalences: trailing zeros in the numeric prefix
		// must be stripped before comparing, matching Gem::Version#canonical_segments.
		// 1.0.0.beta1 → canonical [1,"beta",1]; 1.0.beta1 → canonical [1,"beta",1]
		{"canonical_extra_zeros_before_beta1", "1.0.0.beta1", "1.0.beta1", 0},
		// Symmetric
		{"canonical_extra_zeros_before_beta1_rev", "1.0.beta1", "1.0.0.beta1", 0},
		// 1.2.0 → canonical [1,2]; 1.2 → canonical [1,2]
		{"canonical_trailing_zero_numeric", "1.2.0", "1.2", 0},
		// 1 → canonical [1]; 1.0.0 → canonical [1]
		{"canonical_single_vs_triple_zero", "1", "1.0.0", 0},
		// 1.0.0.rc1 == 1.0.rc1
		{"canonical_extra_zeros_before_rc1", "1.0.0.rc1", "1.0.rc1", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := parseGemVersion(tc.a)
			require.NoErrorf(t, err, "parseGemVersion(%q)", tc.a)
			b, err := parseGemVersion(tc.b)
			require.NoErrorf(t, err, "parseGemVersion(%q)", tc.b)

			got := compareGemVersions(a, b)
			switch {
			case tc.want < 0:
				assert.Lessf(t, got, 0,
					"compareGemVersions(%q, %q) must be negative (got %d)", tc.a, tc.b, got)
			case tc.want > 0:
				assert.Greaterf(t, got, 0,
					"compareGemVersions(%q, %q) must be positive (got %d)", tc.a, tc.b, got)
			default:
				assert.Zerof(t, got,
					"compareGemVersions(%q, %q) must be zero (got %d)", tc.a, tc.b, got)
			}
		})
	}
}

// ── rubyGemsVersionInRangeV (tri-state comparator) ───────────────────────────

// TestRubyGemsVersionInRangeV_AffectedRange verifies versions that fall inside
// a [Introduced, Fixed) range return VersionAffected.
func TestRubyGemsVersionInRangeV_AffectedRange(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		r       VersionRange
	}{
		{
			name:    "inside_simple_range",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "at_introduced_inclusive",
			version: "7.1.0",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		{
			name:    "just_below_fixed",
			version: "7.1.3.0",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		{
			name:    "no_upper_bound",
			version: "99.0.0",
			r:       VersionRange{Introduced: "1.0.0"},
		},
		{
			name:    "last_affected_inclusive",
			version: "2.3.0",
			r:       VersionRange{Introduced: "2.0.0", LastAffected: "2.3.0"},
		},
		{
			name:    "last_affected_inside",
			version: "2.1.0",
			r:       VersionRange{Introduced: "2.0.0", LastAffected: "2.3.0"},
		},
		// Pre-release inside range: 7.1.0 ≤ 7.1.0.beta is FALSE (beta < 7.1.0),
		// so this case checks that a release version properly falls in range.
		{
			name:    "four_part_version_in_range",
			version: "7.1.3.0",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		// Real-world actionpack CVE range.
		{
			name:    "actionpack_affected",
			version: "7.1.2",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		// OSV "v" prefix on the query version must work.
		{
			name:    "v_prefix_query",
			version: "v1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		// Range bug: introduced and installed differ only in trailing zeros of the
		// numeric prefix (1.0.0.beta1 vs 1.0.beta1).  After canonical_segments
		// both are [1,"beta",1], so installed == introduced (inclusive lower bound)
		// and installed < fixed (1.0.0), so the advisory must fire as Affected.
		{
			name:    "canonical_range_bug_extra_zeros_beta",
			version: "1.0.beta1",
			r:       VersionRange{Introduced: "1.0.0.beta1", Fixed: "1.0.0"},
		},
		// Symmetric: introduced has fewer zeros than installed.
		{
			name:    "canonical_range_bug_fewer_zeros_beta",
			version: "1.0.0.beta1",
			r:       VersionRange{Introduced: "1.0.beta1", Fixed: "1.0.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, VersionAffected,
				rubyGemsVersionInRangeV(tc.version, tc.r),
				"version %q in range %+v should be VersionAffected", tc.version, tc.r)
		})
	}
}

// TestRubyGemsVersionInRangeV_NotAffected verifies versions that fall outside
// any bound return VersionNotAffected.
func TestRubyGemsVersionInRangeV_NotAffected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		r       VersionRange
	}{
		{
			name:    "below_introduced",
			version: "0.9.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "at_fixed_exclusive",
			version: "2.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "above_fixed",
			version: "3.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "above_last_affected",
			version: "2.4.0",
			r:       VersionRange{Introduced: "2.0.0", LastAffected: "2.3.0"},
		},
		// Pre-release invariant: a pre-release version is < its base release.
		// 7.1.0.beta < 7.1.0 means it's BELOW the introduced bound of 7.1.0.
		{
			name:    "prerelease_below_introduced",
			version: "7.1.0.beta",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		{
			name:    "prerelease_rc_below_introduced",
			version: "7.1.0.rc1",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		// Fixed version itself is NOT affected (exclusive bound).
		{
			name:    "actionpack_fixed_not_affected",
			version: "7.1.3.1",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
		{
			name:    "four_part_above_fixed",
			version: "7.1.3.2",
			r:       VersionRange{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, VersionNotAffected,
				rubyGemsVersionInRangeV(tc.version, tc.r),
				"version %q vs range %+v should be VersionNotAffected", tc.version, tc.r)
		})
	}
}

// TestRubyGemsVersionInRangeV_Undecidable confirms that a parse error on the
// query version or any range bound returns VersionUndecidable — never
// VersionNotAffected.  A parse error must NEVER silently drop an advisory.
func TestRubyGemsVersionInRangeV_Undecidable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		r       VersionRange
	}{
		{
			name:    "bad_query_version",
			version: "not-a-version",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "bad_introduced",
			version: "1.5.0",
			r:       VersionRange{Introduced: "bad!", Fixed: "2.0.0"},
		},
		{
			name:    "bad_fixed",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "bad!"},
		},
		{
			name:    "bad_last_affected",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", LastAffected: "bad!"},
		},
		{
			name:    "tilde_operator_in_query",
			version: "~> 1.2",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "plus_build_metadata",
			version: "1.0.0+build.1",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rubyGemsVersionInRangeV(tc.version, tc.r)
			assert.Equal(t, VersionUndecidable, got,
				"version %q vs range %+v: parse error must propagate as VersionUndecidable, got %v",
				tc.version, tc.r, got)
		})
	}
}

// TestRubyGemsVersionInRangeV_EmptyRange checks the edge case where all range
// bounds are absent (Introduced="", Fixed="", LastAffected=""), which means
// "all versions are affected".
func TestRubyGemsVersionInRangeV_EmptyRange(t *testing.T) {
	t.Parallel()

	r := VersionRange{}
	for _, v := range []string{"0", "1.0.0", "99.99.99", "1.0.0.beta"} {
		assert.Equal(t, VersionAffected,
			rubyGemsVersionInRangeV(v, r),
			"empty range must treat all parseable versions as VersionAffected (%q)", v)
	}
}

// ── registry integration ──────────────────────────────────────────────────────

// TestRubyGemsComparatorRegistered verifies that the init() in
// rubygems_version.go successfully registers a comparator for EcosystemRubyGems.
func TestRubyGemsComparatorRegistered(t *testing.T) {
	t.Parallel()

	cmp := lookupComparator(EcosystemRubyGems)
	assert.NotNilf(t, cmp, "EcosystemRubyGems must have a registered comparator after package init()")
}

// TestRubyGemsAffectsVersionV_ViaRegistry exercises the full AffectsVersionV
// routing path (Advisory → registry → rubyGemsVersionInRangeV) to confirm
// end-to-end wiring.
func TestRubyGemsAffectsVersionV_ViaRegistry(t *testing.T) {
	t.Parallel()

	// Modelled on a real actionpack advisory: CVE-2024-26142
	// Introduced: 7.1.0, Fixed: 7.1.3.1
	adv := &Advisory{
		ID:        "GHSA-xxxx-rubygems-test",
		Ecosystem: EcosystemRubyGems,
		VersionRanges: []VersionRange{
			{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
	}

	assert.Equal(t, VersionAffected, adv.AffectsVersionV("7.1.2"),
		"7.1.2 inside [7.1.0, 7.1.3.1) must be Affected")
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("7.1.0"),
		"7.1.0 == introduced (inclusive) must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("7.1.3.1"),
		"7.1.3.1 == fixed (exclusive) must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("7.0.9"),
		"7.0.9 < introduced 7.1.0 must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("8.0.0"),
		"8.0.0 > fixed 7.1.3.1 must be NotAffected")

	// Pre-release below introduced must be NotAffected.
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("7.1.0.beta"),
		"7.1.0.beta < 7.1.0 (introduced) must be NotAffected")

	// OSV canonical "v" prefix on query version must be handled.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("v7.1.2"),
		"v7.1.2 (with v prefix) inside range must be Affected")

	// Parse error must propagate as Undecidable, never NotAffected.
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("not-a-version"),
		"unparseable query version must yield VersionUndecidable")
}

// TestRubyGemsAffectsVersionV_MultipleRanges verifies that an advisory with
// multiple disjoint ranges (as OSV can emit) returns Affected when the version
// falls in any one range.
func TestRubyGemsAffectsVersionV_MultipleRanges(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemRubyGems,
		VersionRanges: []VersionRange{
			{Introduced: "6.0.0", Fixed: "6.1.7.7"},
			{Introduced: "7.0.0", Fixed: "7.0.8.4"},
			{Introduced: "7.1.0", Fixed: "7.1.3.1"},
		},
	}

	// In the first range.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("6.1.7.0"))
	// Between first and second range (not affected).
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("6.1.7.7"))
	// In the third range.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("7.1.2"))
	// Above all ranges.
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("8.0.0"))
}
