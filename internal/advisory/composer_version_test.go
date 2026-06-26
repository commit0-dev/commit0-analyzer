package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// parseComposerVersion — parser correctness
// ---------------------------------------------------------------------------

func TestParseComposerVersion_ValidVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  composerVersion
	}{
		// 1-part → 1.0.0.0 stable
		{"1", composerVersion{1, 0, 0, 0, composerStabilityStable, 0}},
		// 2-part → 1.2.0.0 stable
		{"1.2", composerVersion{1, 2, 0, 0, composerStabilityStable, 0}},
		// 3-part → 1.2.3.0 stable
		{"1.2.3", composerVersion{1, 2, 3, 0, composerStabilityStable, 0}},
		// 4-part → 1.2.3.4 stable
		{"1.2.3.4", composerVersion{1, 2, 3, 4, composerStabilityStable, 0}},
		// Leading v prefix stripped
		{"v1.2.3", composerVersion{1, 2, 3, 0, composerStabilityStable, 0}},
		{"V2.0.0", composerVersion{2, 0, 0, 0, composerStabilityStable, 0}},

		// --- dev stability ---
		{"1.0.0-dev", composerVersion{1, 0, 0, 0, composerStabilityDev, 0}},
		{"2.0.0-dev", composerVersion{2, 0, 0, 0, composerStabilityDev, 0}},

		// --- alpha stability ---
		{"1.0.0-alpha", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 0}},
		{"1.0.0-alpha1", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 1}},
		{"1.0.0-alpha.1", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 1}},
		{"1.0.0-alpha.3", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 3}},
		// Short alias 'a'
		{"1.0.0-a", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 0}},
		{"1.0.0-a1", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 1}},
		{"1.0.0-a.2", composerVersion{1, 0, 0, 0, composerStabilityAlpha, 2}},

		// --- beta stability ---
		{"1.0.0-beta", composerVersion{1, 0, 0, 0, composerStabilityBeta, 0}},
		{"1.0.0-beta1", composerVersion{1, 0, 0, 0, composerStabilityBeta, 1}},
		{"1.0.0-beta.2", composerVersion{1, 0, 0, 0, composerStabilityBeta, 2}},
		{"3.0.0-beta.5", composerVersion{3, 0, 0, 0, composerStabilityBeta, 5}},
		// Short alias 'b'
		{"1.0.0-b", composerVersion{1, 0, 0, 0, composerStabilityBeta, 0}},
		{"1.0.0-b1", composerVersion{1, 0, 0, 0, composerStabilityBeta, 1}},

		// --- RC stability ---
		{"1.0.0-RC", composerVersion{1, 0, 0, 0, composerStabilityRC, 0}},
		{"1.0.0-RC1", composerVersion{1, 0, 0, 0, composerStabilityRC, 1}},
		{"1.0.0-RC.1", composerVersion{1, 0, 0, 0, composerStabilityRC, 1}},
		{"1.0.0-rc", composerVersion{1, 0, 0, 0, composerStabilityRC, 0}},
		{"2.0.0-RC2", composerVersion{2, 0, 0, 0, composerStabilityRC, 2}},

		// --- patch stability ---
		{"1.0.0-patch", composerVersion{1, 0, 0, 0, composerStabilityPatch, 0}},
		{"1.0.0-patch.1", composerVersion{1, 0, 0, 0, composerStabilityPatch, 1}},
		{"1.0.0-p", composerVersion{1, 0, 0, 0, composerStabilityPatch, 0}},
		{"1.0.0-p1", composerVersion{1, 0, 0, 0, composerStabilityPatch, 1}},

		// --- 4-part with stability ---
		{"1.2.3.4-alpha", composerVersion{1, 2, 3, 4, composerStabilityAlpha, 0}},
		{"1.2.3.4-RC1", composerVersion{1, 2, 3, 4, composerStabilityRC, 1}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, ok := parseComposerVersion(tc.input)
			assert.True(t, ok, "parseComposerVersion(%q) should succeed", tc.input)
			if ok {
				assert.Equal(t, tc.want, *got,
					"parseComposerVersion(%q) parsed fields mismatch", tc.input)
			}
		})
	}
}

func TestParseComposerVersion_InvalidAndUndecidable(t *testing.T) {
	t.Parallel()

	cases := []string{
		// empty / blank
		"",
		"   ",

		// branch aliases → undecidable
		"dev-main",
		"dev-master",
		"dev-feature/xyz",
		"1.x-dev",
		"2.2.x-dev",
		"1.0.x-dev",

		// 5-part numeric (too many segments)
		"1.2.3.4.5",

		// non-numeric core
		"1.a.3",
		"major.minor.patch",

		// negative not legal (strconv.Atoi on "-1" works but we reject n<0)
		// Note: "-1.2.3" would be parsed as stability sep before '1', so
		// the core would be "" → rejected.

		// unknown stability keyword
		"1.0.0-gamma",
		"1.0.0-snapshot",
		"1.0.0-milestone",

		// "dev" with a number is invalid
		"1.0.0-dev1",
		"1.0.0-dev.2",

		// empty stability after '-'
		"1.0.0-",
	}

	for _, input := range cases {
		input := input
		t.Run("reject_"+input, func(t *testing.T) {
			t.Parallel()
			_, ok := parseComposerVersion(input)
			assert.False(t, ok,
				"parseComposerVersion(%q) should return false (undecidable)", input)
		})
	}
}

// ---------------------------------------------------------------------------
// composerVersion.compare — ordering correctness
// ---------------------------------------------------------------------------

func TestComposerVersionCompare_Order(t *testing.T) {
	t.Parallel()

	// Each pair: left < right (compare(left, right) < 0).
	lessThans := []struct{ a, b string }{
		// Numeric tuple ordering
		{"1.0.0", "2.0.0"},
		{"1.0.0", "1.1.0"},
		{"1.0.0", "1.0.1"},
		{"1.0.0.0", "1.0.0.1"},

		// Stability tier ordering (same numeric base)
		{"1.0.0-dev", "1.0.0-alpha"},
		{"1.0.0-alpha", "1.0.0-beta"},
		{"1.0.0-beta", "1.0.0-RC"},
		{"1.0.0-RC", "1.0.0"},     // stable
		{"1.0.0", "1.0.0-patch"},  // patch > stable

		// Stability number ordering within tier
		{"1.0.0-alpha", "1.0.0-alpha1"},
		{"1.0.0-alpha1", "1.0.0-alpha2"},
		{"1.0.0-alpha.1", "1.0.0-alpha.3"},
		{"1.0.0-beta", "1.0.0-beta.1"},
		{"1.0.0-RC1", "1.0.0-RC2"},

		// Short aliases ordered same as long aliases
		{"1.0.0-a", "1.0.0-b"},
		{"1.0.0-b", "1.0.0-RC"},

		// Numeric base beats stability
		{"1.0.0-patch", "2.0.0-dev"},
	}

	for _, tc := range lessThans {
		tc := tc
		t.Run(tc.a+"<"+tc.b, func(t *testing.T) {
			t.Parallel()
			a, okA := parseComposerVersion(tc.a)
			b, okB := parseComposerVersion(tc.b)
			assert.True(t, okA, "parseComposerVersion(%q)", tc.a)
			assert.True(t, okB, "parseComposerVersion(%q)", tc.b)
			if okA && okB {
				assert.Negative(t, a.compare(b), "%q should be < %q", tc.a, tc.b)
				assert.Positive(t, b.compare(a), "%q should be > %q", tc.b, tc.a)
			}
		})
	}

	// Equality cases.
	equals := []struct{ a, b string }{
		{"1.0.0", "1.0.0.0"},      // missing fourth segment defaults to 0
		{"1.0", "1.0.0.0"},        // missing segments default to 0
		{"1.0.0-RC", "1.0.0-rc"}, // case-insensitive stability
		{"1.0.0-a", "1.0.0-alpha"}, // short alias
		{"1.0.0-b", "1.0.0-beta"},  // short alias
		{"1.0.0-p", "1.0.0-patch"}, // short alias
		{"v1.0.0", "1.0.0"},        // v prefix stripped
	}

	for _, tc := range equals {
		tc := tc
		t.Run(tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			a, okA := parseComposerVersion(tc.a)
			b, okB := parseComposerVersion(tc.b)
			assert.True(t, okA, "parseComposerVersion(%q)", tc.a)
			assert.True(t, okB, "parseComposerVersion(%q)", tc.b)
			if okA && okB {
				assert.Zero(t, a.compare(b), "%q should equal %q", tc.a, tc.b)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// composerVersionInRangeV — tri-state range comparator
// ---------------------------------------------------------------------------

func TestComposerVersionInRangeV_Affected(t *testing.T) {
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
			version: "1.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "below_fixed_exclusive",
			version: "1.9.9",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "prerelease_inside_range",
			version: "1.5.0-beta.2",
			r:       VersionRange{Introduced: "1.5.0-alpha", Fixed: "2.0.0"},
		},
		{
			name:    "at_last_affected_inclusive",
			version: "1.9.9",
			r:       VersionRange{Introduced: "1.0.0", LastAffected: "1.9.9"},
		},
		{
			name:    "no_upper_bound_unfixed",
			version: "9.9.9",
			r:       VersionRange{Introduced: "1.0.0"},
		},
		{
			name:    "dev_pre_below_alpha_fixed",
			version: "2.0.0-dev",
			r:       VersionRange{Introduced: "2.0.0-dev", Fixed: "2.0.0"},
		},
		{
			name:    "rc_below_stable_fixed",
			version: "1.0.0-RC1",
			r:       VersionRange{Introduced: "1.0.0-dev", Fixed: "1.0.0"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := composerVersionInRangeV(tc.version, tc.r)
			assert.Equal(t, VersionAffected, got,
				"version %q in range %+v should be Affected", tc.version, tc.r)
		})
	}
}

func TestComposerVersionInRangeV_NotAffected(t *testing.T) {
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
			version: "2.0.0",
			r:       VersionRange{Introduced: "1.0.0", LastAffected: "1.9.9"},
		},
		{
			name:    "patch_above_stable_fixed",
			version: "1.0.0-patch",
			r:       VersionRange{Introduced: "1.0.0-dev", Fixed: "1.0.0"},
		},
		{
			name:    "stable_at_and_above_fixed",
			version: "1.0.0",
			r:       VersionRange{Introduced: "0.9.0", Fixed: "1.0.0"},
		},
		{
			name:    "stable_above_last_affected_rc",
			version: "1.0.0",
			r:       VersionRange{Introduced: "1.0.0-dev", LastAffected: "1.0.0-RC"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := composerVersionInRangeV(tc.version, tc.r)
			assert.Equal(t, VersionNotAffected, got,
				"version %q in range %+v should be NotAffected", tc.version, tc.r)
		})
	}
}

func TestComposerVersionInRangeV_Undecidable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		r       VersionRange
	}{
		// Unparseable query version
		{
			name:    "bad_query_version",
			version: "not-a-version",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "empty_query_version",
			version: "",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		// Branch alias in query position
		{
			name:    "dev_main_alias_query",
			version: "dev-main",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		{
			name:    "x_dev_alias_query",
			version: "1.x-dev",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
		// Unparseable introduced bound
		{
			name:    "bad_introduced_bound",
			version: "1.5.0",
			r:       VersionRange{Introduced: "not-a-version", Fixed: "2.0.0"},
		},
		// Unparseable fixed bound
		{
			name:    "bad_fixed_bound",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "garbage"},
		},
		// Branch alias in bounds
		{
			name:    "dev_alias_introduced",
			version: "1.5.0",
			r:       VersionRange{Introduced: "dev-main"},
		},
		{
			name:    "dev_alias_fixed",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "dev-master"},
		},
		// Unknown stability keyword
		{
			name:    "unknown_stability_in_range",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0-snapshot", Fixed: "2.0.0"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := composerVersionInRangeV(tc.version, tc.r)
			assert.Equal(t, VersionUndecidable, got,
				"version %q in range %+v should be Undecidable (never NotAffected)",
				tc.version, tc.r)
		})
	}
}

// ---------------------------------------------------------------------------
// Registry integration — EcosystemPackagist is registered and routed correctly
// ---------------------------------------------------------------------------

func TestComparatorRegistry_PackagistRegistered(t *testing.T) {
	t.Parallel()
	assert.NotNil(t, lookupComparator(EcosystemPackagist),
		"EcosystemPackagist must have a registered comparator after init()")
}

func TestComparatorRegistry_PackagistRoute(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemPackagist,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("1.5.0"),
		"Packagist 1.5.0 inside [1.0.0, 2.0.0) should be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.0.0"),
		"Packagist 2.0.0 == fixed (exclusive upper bound) should be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("0.9.9"),
		"Packagist 0.9.9 < introduced 1.0.0 should be NotAffected")
}

func TestComparatorRegistry_PackagistUndecidableOnBranchAlias(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemPackagist,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("dev-main"),
		"branch alias dev-main must propagate as VersionUndecidable (never NotAffected)")
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("1.x-dev"),
		"branch alias 1.x-dev must propagate as VersionUndecidable (never NotAffected)")
}

// TestComposerStabilityOrdering_FullChain confirms the stability ordering is
// strictly: dev < alpha < beta < RC < stable < patch.
// Uses a zero-lower-bound advisory so any version in range returns Affected.
func TestComposerStabilityOrdering_FullChain(t *testing.T) {
	t.Parallel()

	// Build an advisory with no lower bound, fixed at stable "2.0.0".
	// Anything below 2.0.0 (stable) should be Affected.
	// 2.0.0-dev, 2.0.0-alpha, 2.0.0-beta, 2.0.0-RC are all < 2.0.0 stable.
	advBelowStable := &Advisory{
		Ecosystem:     EcosystemPackagist,
		VersionRanges: []VersionRange{{Introduced: "0.0.0", Fixed: "2.0.0"}},
	}
	for _, pre := range []string{"2.0.0-dev", "2.0.0-alpha", "2.0.0-alpha1", "2.0.0-beta", "2.0.0-RC"} {
		pre := pre
		t.Run("pre_affected_"+pre, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, VersionAffected, advBelowStable.AffectsVersionV(pre),
				"%q should be < 2.0.0 (stable) and thus Affected", pre)
		})
	}

	// 2.0.0 (stable) and above (including patch) should NOT be affected.
	for _, notPre := range []string{"2.0.0", "2.0.0-patch", "2.0.1", "3.0.0"} {
		notPre := notPre
		t.Run("stable_not_affected_"+notPre, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, VersionNotAffected, advBelowStable.AffectsVersionV(notPre),
				"%q should be >= 2.0.0 (stable) and thus NotAffected", notPre)
		})
	}
}

// TestComposerBranchAliasDetection verifies the branch alias detector directly.
func TestComposerBranchAliasDetection(t *testing.T) {
	t.Parallel()

	aliases := []string{
		"dev-main", "dev-master", "dev-feature/foo", "dev-1.x", "DEV-MAIN",
		"1.x-dev", "2.2.x-dev", "1.0.x-dev",
	}
	for _, a := range aliases {
		a := a
		t.Run("alias_"+a, func(t *testing.T) {
			t.Parallel()
			assert.True(t, isComposerBranchAlias(a), "%q should be detected as a branch alias", a)
		})
	}

	notAliases := []string{
		"1.0.0", "1.0.0-dev", "2.0.0-RC1", "v1.2.3", "1.0.0-alpha.1",
	}
	for _, a := range notAliases {
		a := a
		t.Run("not_alias_"+a, func(t *testing.T) {
			t.Parallel()
			assert.False(t, isComposerBranchAlias(a), "%q should NOT be detected as a branch alias", a)
		})
	}
}
