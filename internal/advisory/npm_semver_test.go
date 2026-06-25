package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNPMVersionInRange covers node-semver semantics for the OSV introduced/fixed
// event model. All cases use bare npm versions (no "v" prefix in either the
// query version or the range boundaries, matching OSV npm records).
//
// Boundary rule: [Introduced, Fixed) — introduced is inclusive, fixed is exclusive.
func TestNPMVersionInRange(t *testing.T) {
	cases := []struct {
		name       string
		version    string
		introduced string // empty = since beginning
		fixed      string // empty = unfixed
		want       bool
	}{
		// Basic boundary: fixed=14.2.0 means 14.2.0 itself is NOT affected.
		{name: "fixed_boundary_exact", version: "14.2.0", introduced: "", fixed: "14.2.0", want: false},
		{name: "just_below_fixed", version: "14.1.9", introduced: "", fixed: "14.2.0", want: true},
		{name: "just_below_fixed_patch", version: "14.1.999", introduced: "", fixed: "14.2.0", want: true},

		// With introduced bound.
		{name: "in_range_with_introduced", version: "14.1.1", introduced: "14.0.0", fixed: "14.2.0", want: true},
		{name: "at_introduced_inclusive", version: "14.0.0", introduced: "14.0.0", fixed: "14.2.0", want: true},
		{name: "before_introduced", version: "13.9.9", introduced: "14.0.0", fixed: "14.2.0", want: false},

		// Open upper bound (unfixed).
		{name: "unfixed_high_version", version: "99.0.0", introduced: "1.0.0", fixed: "", want: true},
		{name: "unfixed_at_introduced", version: "1.0.0", introduced: "1.0.0", fixed: "", want: true},
		{name: "unfixed_before_introduced", version: "0.9.9", introduced: "1.0.0", fixed: "", want: false},

		// Open lower bound (introduced = "").
		{name: "no_lower_bound_matches_zero", version: "0.0.1", introduced: "", fixed: "1.0.0", want: true},
		{name: "no_lower_bound_at_fixed", version: "1.0.0", introduced: "", fixed: "1.0.0", want: false},

		// Prerelease: node-semver prereleases only match within the same [major.minor.patch]
		// tuple unless explicitly included. A prerelease of the fixed version is still
		// affected (it's < fixed). A prerelease of a version ABOVE fixed is not affected.
		{name: "prerelease_below_fixed", version: "14.1.0-beta.1", introduced: "", fixed: "14.2.0", want: true},
		{name: "prerelease_of_fixed_not_matched", version: "14.2.0-alpha.1", introduced: "", fixed: "14.2.0", want: true},
		// 14.2.1-beta.0 > 14.2.0 (different [major,minor,patch]), so only matches if
		// there is no upper fixed or the fixed is higher. Since fixed=14.2.0 and
		// 14.2.1-beta.0 has different tuple than 14.2.0, it is > 14.2.0 → not affected.
		{name: "prerelease_above_fixed_not_matched", version: "14.2.1-beta.0", introduced: "", fixed: "14.2.0", want: false},

		// Patch version comparisons.
		{name: "patch_ordering", version: "1.0.10", introduced: "", fixed: "1.0.11", want: true},
		{name: "patch_ordering_at_fixed", version: "1.0.11", introduced: "", fixed: "1.0.11", want: false},

		// Major version comparisons.
		{name: "major_above_fixed", version: "2.0.0", introduced: "", fixed: "1.5.0", want: false},
		{name: "major_below_introduced", version: "0.9.0", introduced: "1.0.0", fixed: "1.5.0", want: false},

		// Both bounds empty (open range = everything affected).
		{name: "both_empty_all_affected", version: "1.2.3", introduced: "", fixed: "", want: true},
		{name: "both_empty_zero_version", version: "0.0.0", introduced: "", fixed: "", want: true},

		// 4-part npm versions (sometimes encountered in registry metadata).
		// node-semver ignores the 4th part for comparison purposes (it's not valid semver
		// but npm tolerates it by truncating). We coerce x.y.z.w → x.y.z.
		{name: "four_part_version_in_range", version: "1.2.3.4", introduced: "", fixed: "2.0.0", want: true},
		{name: "four_part_version_above_fixed", version: "2.0.0.1", introduced: "", fixed: "2.0.0", want: false},

		// The real regression case: debug advisory [0, 14.2.0). Version 14.1.1 is
		// affected; 14.2.0 is not.
		{name: "debug_in_range", version: "14.1.1", introduced: "", fixed: "14.2.0", want: true},
		{name: "debug_at_fixed", version: "14.2.0", introduced: "", fixed: "14.2.0", want: false},
		{name: "debug_above_fixed", version: "14.2.1", introduced: "", fixed: "14.2.0", want: false},

		// Go-semver false-positive regression: Go semver mishandles npm versions that
		// look like pseudo-versions or fail the strict vX.Y.Z form. A valid npm
		// version like "14.1.1" without "v" prefix should still match correctly.
		{name: "bare_npm_version_no_v_prefix", version: "14.1.1", introduced: "0", fixed: "14.2.0", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := VersionRange{Introduced: tc.introduced, Fixed: tc.fixed}
			got := npmVersionInRange(tc.version, r)
			assert.Equal(t, tc.want, got,
				"npmVersionInRange(%q, {Introduced:%q, Fixed:%q})", tc.version, tc.introduced, tc.fixed)
		})
	}
}

// TestNPMParseVersion validates the version parser handles valid and edge-case inputs.
func TestNPMParseVersion(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
		// Only checking a key field to prove parsing.
		major int
		minor int
		patch int
	}{
		{input: "1.2.3", major: 1, minor: 2, patch: 3},
		{input: "0.0.0", major: 0, minor: 0, patch: 0},
		{input: "14.2.0", major: 14, minor: 2, patch: 0},
		{input: "1.2.3-alpha.1", major: 1, minor: 2, patch: 3},
		{input: "1.2.3-beta.0+build", major: 1, minor: 2, patch: 3},
		{input: "1.2.3.4", major: 1, minor: 2, patch: 3},  // 4-part: truncate
		{input: "v1.2.3", major: 1, minor: 2, patch: 3},   // v-prefixed: strip
		{input: "", wantErr: true},
		{input: "not-a-version", wantErr: true},
		{input: "1.2", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			v, err := parseNPMVersion(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.major, v.major)
			assert.Equal(t, tc.minor, v.minor)
			assert.Equal(t, tc.patch, v.patch)
		})
	}
}

// TestNPMVersionCompare validates the node-semver comparison precedence rules:
// major → minor → patch → prerelease (empty > non-empty) → alpha sort.
func TestNPMVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int // -1, 0, 1
	}{
		// Basic ordering.
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		// Minor ordering.
		{"1.1.0", "1.2.0", -1},
		{"1.2.0", "1.1.0", 1},
		// Prerelease: 1.0.0-alpha < 1.0.0 (release beats prerelease).
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		// Prerelease alpha ordering.
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-alpha", 0},
		// Numeric prerelease identifiers sort numerically.
		{"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-2", "1.0.0-1", 1},
		{"1.0.0-10", "1.0.0-9", 1}, // numeric: 10 > 9
		// Mixed: numeric < alphabetic per SemVer spec.
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		// Build metadata is ignored.
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"1.0.0+a", "1.0.0", 0},
		// 14.2.0-alpha.1 < 14.2.0 (prerelease < release).
		{"14.2.0-alpha.1", "14.2.0", -1},
		{"14.2.0", "14.2.0-alpha.1", 1},
	}

	for _, tc := range cases {
		name := tc.a + "_vs_" + tc.b
		t.Run(name, func(t *testing.T) {
			va, err := parseNPMVersion(tc.a)
			assert.NoError(t, err)
			vb, err := parseNPMVersion(tc.b)
			assert.NoError(t, err)
			got := compareNPMVersions(va, vb)
			if tc.want < 0 {
				assert.Less(t, got, 0, "expected %s < %s", tc.a, tc.b)
			} else if tc.want > 0 {
				assert.Greater(t, got, 0, "expected %s > %s", tc.a, tc.b)
			} else {
				assert.Equal(t, 0, got, "expected %s == %s", tc.a, tc.b)
			}
		})
	}
}

// TestAffectsVersion_NPMEcosystem confirms that Advisory.AffectsVersion uses npm
// semantics when Ecosystem is "npm", and returns correct results for the boundary case.
func TestAffectsVersion_NPMEcosystem(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemNPM,
		VersionRanges: []VersionRange{
			{Introduced: "", Fixed: "14.2.0"},
		},
	}

	// Versions in range must be affected.
	assert.True(t, adv.AffectsVersion("14.1.1"), "14.1.1 must be affected")
	assert.True(t, adv.AffectsVersion("0.0.1"), "0.0.1 must be affected")
	assert.True(t, adv.AffectsVersion("14.1.999"), "14.1.999 must be affected")

	// The fixed version itself must NOT be affected.
	assert.False(t, adv.AffectsVersion("14.2.0"), "14.2.0 is fixed — must not be affected")

	// Versions above the fix must NOT be affected.
	assert.False(t, adv.AffectsVersion("14.2.1"), "14.2.1 must not be affected")
	assert.False(t, adv.AffectsVersion("15.0.0"), "15.0.0 must not be affected")
}

// TestAffectsVersion_GoEcosystemUnchanged confirms that Go ecosystem advisory
// version matching continues to use the existing Go semver logic unchanged.
// This is the non-regression guard.
func TestAffectsVersion_GoEcosystemUnchanged(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemGo,
		VersionRanges: []VersionRange{
			{Introduced: "", Fixed: "1.2.3"},
		},
	}

	// Go versions use "v" prefix.
	assert.True(t, adv.AffectsVersion("v1.0.0"), "v1.0.0 must be affected in Go advisory")
	assert.True(t, adv.AffectsVersion("v1.2.2"), "v1.2.2 must be affected in Go advisory")
	assert.False(t, adv.AffectsVersion("v1.2.3"), "v1.2.3 is fixed — must not be affected")
	assert.False(t, adv.AffectsVersion("v2.0.0"), "v2.0.0 must not be affected")
}

// TestAffectsVersion_MultiPair_NPM verifies multi-pair OSV range handling for the
// npm ecosystem:
//   - 1.1.0 in [0, 1.2.0)        → affected
//   - 1.5.0 between the ranges   → NOT affected
//   - 2.0.5 in [2.0.0, 2.1.0)   → affected
//   - 2.5.0 past upper range     → NOT affected
func TestAffectsVersion_MultiPair_NPM(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemNPM,
		VersionRanges: []VersionRange{
			{Introduced: "", Fixed: "1.2.0"},
			{Introduced: "2.0.0", Fixed: "2.1.0"},
		},
	}

	assert.True(t, adv.AffectsVersion("1.1.0"), "1.1.0 in [0,1.2.0) must be affected")
	assert.False(t, adv.AffectsVersion("1.5.0"), "1.5.0 between ranges must NOT be affected")
	assert.True(t, adv.AffectsVersion("2.0.5"), "2.0.5 in [2.0.0,2.1.0) must be affected")
	assert.False(t, adv.AffectsVersion("2.5.0"), "2.5.0 past upper range must NOT be affected")
}

// TestNPMVersionInRange_LastAffectedInclusive verifies that a last_affected bound is
// treated as inclusive for npm: the exact last_affected version IS affected, one above NOT.
func TestNPMVersionInRange_LastAffectedInclusive(t *testing.T) {
	cases := []struct {
		name    string
		version string
		r       VersionRange
		want    bool
	}{
		{
			name:    "at_last_affected_inclusive",
			version: "1.2.0",
			r:       VersionRange{Introduced: "", LastAffected: "1.2.0"},
			want:    true,
		},
		{
			name:    "above_last_affected_not_matched",
			version: "1.2.1",
			r:       VersionRange{Introduced: "", LastAffected: "1.2.0"},
			want:    false,
		},
		{
			name:    "below_last_affected_matched",
			version: "1.0.0",
			r:       VersionRange{Introduced: "", LastAffected: "1.2.0"},
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := npmVersionInRange(tc.version, tc.r)
			assert.Equal(t, tc.want, got,
				"npmVersionInRange(%q, {LastAffected:%q})", tc.version, tc.r.LastAffected)
		})
	}
}

// TestAffectsVersion_LastAffected_NPM verifies inclusive last_affected semantics
// via Advisory.AffectsVersion for the npm ecosystem.
func TestAffectsVersion_LastAffected_NPM(t *testing.T) {
	adv := &Advisory{
		Ecosystem: EcosystemNPM,
		VersionRanges: []VersionRange{
			{Introduced: "", LastAffected: "1.2.0"},
		},
	}

	assert.True(t, adv.AffectsVersion("1.2.0"), "1.2.0 (last_affected) must be affected (inclusive)")
	assert.False(t, adv.AffectsVersion("1.2.1"), "1.2.1 above last_affected must NOT be affected")
	assert.True(t, adv.AffectsVersion("1.0.0"), "1.0.0 below last_affected must be affected")
}

// TestAffectsVersion_MultiPair_NPM_ParsedFromOSV verifies end-to-end parsing of a
// multi-pair OSV JSON record for the npm ecosystem.
func TestAffectsVersion_MultiPair_NPM_ParsedFromOSV(t *testing.T) {
	rawJSON := []byte(`{
		"id": "GHSA-npm-multi-0001",
		"affected": [{
			"package": {"ecosystem": "npm", "name": "example-pkg"},
			"ranges": [{
				"type": "SEMVER",
				"events": [
					{"introduced": "0"},
					{"fixed": "1.2.0"},
					{"introduced": "2.0.0"},
					{"fixed": "2.1.0"}
				]
			}]
		}]
	}`)

	adv, err := parseOSVRecord(rawJSON, EcosystemNPM)
	require.NoError(t, err)
	adv.Ecosystem = EcosystemNPM
	require.Len(t, adv.VersionRanges, 2, "two disjoint ranges must be parsed for npm")

	assert.True(t, adv.AffectsVersion("1.1.0"), "1.1.0 in [0,1.2.0) must be affected")
	assert.False(t, adv.AffectsVersion("1.5.0"), "1.5.0 between ranges must NOT be affected")
	assert.True(t, adv.AffectsVersion("2.0.5"), "2.0.5 in [2.0.0,2.1.0) must be affected")
	assert.False(t, adv.AffectsVersion("2.5.0"), "2.5.0 past upper range must NOT be affected")
}

// TestNPMVersionInRange_GoSemverFalsePositiveGone demonstrates that the prior
// Go-semver over-inclusion is fixed. Go semver would return true for any npm
// version that happened to parse as a valid "vX.Y.Z" but fail on versions that
// don't follow strict Go semver forms, causing both false positives and missed
// matches. With npm-native matching we always handle bare npm versions correctly.
func TestNPMVersionInRange_GoSemverFalsePositiveGone(t *testing.T) {
	// debug advisory range: [0, 14.2.0)
	r := VersionRange{Introduced: "", Fixed: "14.2.0"}

	// 14.2.0 should NOT be affected — Go semver with "v14.2.0" >= "v14.2.0" correctly
	// returns false, but only if canonical() is applied. With bare npm versions (no "v")
	// that Go semver can't parse, it returns false conservatively — which wrongly
	// excludes versions that ARE affected. Npm-native matching handles both directions.
	assert.False(t, npmVersionInRange("14.2.0", r),
		"14.2.0 (fixed) must not be affected with npm matcher")

	// These would have been incorrectly handled by Go semver when version had no "v" prefix.
	assert.True(t, npmVersionInRange("14.1.1", r),
		"14.1.1 must be affected with npm matcher")
	assert.True(t, npmVersionInRange("1.0.0", r),
		"1.0.0 must be affected with npm matcher")
}
