package advisory

import (
	"fmt"
	"strconv"
	"strings"
)

// npmVersion is a parsed npm/node-semver version following SemVer 2.0.0 semantics
// with npm extensions (v-prefix stripping, 4-part version coercion).
//
// Prerelease identifiers are stored as []string so numeric and alphanumeric
// identifiers are distinguished at comparison time per SemVer spec §11.
type npmVersion struct {
	major      int
	minor      int
	patch      int
	prerelease []string // empty = release version (beats all prereleases)
}

// parseNPMVersion parses an npm version string into an npmVersion.
//
// Accepts:
//   - Canonical SemVer: "1.2.3", "1.2.3-alpha.1", "1.2.3-beta.0+build"
//   - v-prefixed: "v1.2.3" (strips the prefix)
//   - 4-part: "1.2.3.4" (truncates to 3 parts, per npm registry behaviour)
//
// Returns an error for versions that cannot be parsed (e.g. "", "1.2", "not-a-ver").
// Build metadata (the "+..." suffix) is stripped and ignored per SemVer §10.
func parseNPMVersion(s string) (npmVersion, error) {
	if s == "" {
		return npmVersion{}, fmt.Errorf("npm semver: empty version string")
	}

	// Strip "v" or "V" prefix (OSV and lockfiles sometimes include it).
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	// Strip build metadata: everything after the first "+".
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}

	// Split pre-release from core: "1.2.3-alpha.1" → core="1.2.3", pre="alpha.1".
	var preStr string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		preStr = s[idx+1:]
		s = s[:idx]
	}

	// Parse core version parts. Allow 3 or 4 parts; 4-part is coerced to 3.
	parts := strings.Split(s, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return npmVersion{}, fmt.Errorf("npm semver: expected 3 or 4 parts in %q", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return npmVersion{}, fmt.Errorf("npm semver: bad major in %q: %w", s, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return npmVersion{}, fmt.Errorf("npm semver: bad minor in %q: %w", s, err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return npmVersion{}, fmt.Errorf("npm semver: bad patch in %q: %w", s, err)
	}

	v := npmVersion{major: major, minor: minor, patch: patch}

	if preStr != "" {
		v.prerelease = strings.Split(preStr, ".")
	}

	return v, nil
}

// compareNPMVersions compares two npmVersions using SemVer 2.0.0 precedence rules
// (SemVer spec §11):
//
//  1. Major, minor, patch compared numerically.
//  2. Prerelease: a version without prerelease beats one with prerelease
//     (1.0.0 > 1.0.0-alpha).
//  3. Prerelease identifiers compared left-to-right:
//     - Both numeric: numeric comparison.
//     - Both alphanumeric: lexicographic comparison.
//     - Numeric < alphanumeric (spec §11.4.1).
//  4. Longer prerelease list beats shorter if all preceding identifiers are equal.
//  5. Build metadata is ignored (callers strip it during parse).
//
// Returns -1, 0, or 1 following the usual cmp convention.
func compareNPMVersions(a, b npmVersion) int {
	if n := cmpInt(a.major, b.major); n != 0 {
		return n
	}
	if n := cmpInt(a.minor, b.minor); n != 0 {
		return n
	}
	if n := cmpInt(a.patch, b.patch); n != 0 {
		return n
	}

	// Release (no prerelease) beats prerelease.
	aIsRelease := len(a.prerelease) == 0
	bIsRelease := len(b.prerelease) == 0
	switch {
	case aIsRelease && bIsRelease:
		return 0
	case aIsRelease && !bIsRelease:
		return 1
	case !aIsRelease && bIsRelease:
		return -1
	}

	// Both have prerelease identifiers — compare left-to-right.
	minLen := len(a.prerelease)
	if len(b.prerelease) < minLen {
		minLen = len(b.prerelease)
	}
	for i := 0; i < minLen; i++ {
		ai, aErr := strconv.Atoi(a.prerelease[i])
		bi, bErr := strconv.Atoi(b.prerelease[i])

		bothNumeric := aErr == nil && bErr == nil
		bothAlpha := aErr != nil && bErr != nil

		switch {
		case bothNumeric:
			if n := cmpInt(ai, bi); n != 0 {
				return n
			}
		case bothAlpha:
			if a.prerelease[i] < b.prerelease[i] {
				return -1
			}
			if a.prerelease[i] > b.prerelease[i] {
				return 1
			}
		case aErr == nil: // a is numeric, b is alpha → numeric < alpha
			return -1
		default: // a is alpha, b is numeric → alpha > numeric
			return 1
		}
	}

	// All shared identifiers are equal; longer list wins.
	return cmpInt(len(a.prerelease), len(b.prerelease))
}

// cmpInt returns -1, 0, or 1 for integer comparison.
func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// npmVersionInRangeV is the tri-state variant of npmVersionInRange.
//
// Returns:
//   - VersionAffected when version falls within the range.
//   - VersionNotAffected when version is provably outside the range.
//   - VersionUndecidable when the version or a bound cannot be parsed — the
//     caller must treat this as "possibly affected" and flag incomplete=true.
func npmVersionInRangeV(version string, r VersionRange) VersionVerdict {
	qv, err := parseNPMVersion(version)
	if err != nil {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" && r.Introduced != "0" {
		iv, err := parseNPMVersion(r.Introduced)
		if err != nil {
			return VersionUndecidable
		}
		if compareNPMVersions(qv, iv) < 0 {
			return VersionNotAffected // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive, LastAffected is inclusive.
	if r.Fixed != "" {
		fv, err := parseNPMVersion(r.Fixed)
		if err != nil {
			return VersionUndecidable
		}
		if compareNPMVersions(qv, fv) >= 0 {
			return VersionNotAffected // version >= fixed
		}
	} else if r.LastAffected != "" {
		lv, err := parseNPMVersion(r.LastAffected)
		if err != nil {
			return VersionUndecidable
		}
		if compareNPMVersions(qv, lv) > 0 {
			return VersionNotAffected // version > last_affected
		}
	}

	return VersionAffected
}

// npmVersionInRange reports whether the given npm version string falls within the
// OSV SEMVER range r, using node-semver comparison semantics.
//
// Range semantics: [Introduced, Fixed) — introduced inclusive, fixed exclusive.
//   - Empty Introduced: no lower bound (all versions from 0.0.0 are included).
//     OSV uses "0" as the sentinel for "since the beginning"; extractVersionRange
//     normalises "0" to "" already, but we also handle "0" here defensively.
//   - Empty Fixed: no upper bound (all versions from Introduced onward are included).
//
// If either the query version or a bound cannot be parsed, the function returns
// false conservatively (unknown → not matched → no false positive).
//
// Deprecated: prefer npmVersionInRangeV, which returns a tri-state verdict so
// that parse errors are never silently treated as not-affected.
func npmVersionInRange(version string, r VersionRange) bool {
	qv, err := parseNPMVersion(version)
	if err != nil {
		return false
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" && r.Introduced != "0" {
		iv, err := parseNPMVersion(r.Introduced)
		if err != nil {
			return false
		}
		if compareNPMVersions(qv, iv) < 0 {
			return false // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive, LastAffected is inclusive.
	if r.Fixed != "" {
		fv, err := parseNPMVersion(r.Fixed)
		if err != nil {
			return false
		}
		if compareNPMVersions(qv, fv) >= 0 {
			return false // version >= fixed
		}
	} else if r.LastAffected != "" {
		lv, err := parseNPMVersion(r.LastAffected)
		if err != nil {
			return false
		}
		if compareNPMVersions(qv, lv) > 0 {
			return false // version > last_affected
		}
	}

	return true
}
