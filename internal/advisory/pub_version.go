package advisory

import (
	"strconv"
	"strings"
)

// pubVersionInRangeV is the tri-state comparator for Pub (Dart/Flutter) package
// versions registered under EcosystemPub.
//
// Dart/Flutter packages on pub.dev follow pub_semver semantics.  pub_semver
// extends SemVer 2.0 with one critical difference: build metadata (+N) is
// SIGNIFICANT and ORDERED.  A version without build metadata sorts BEFORE the
// same version with build metadata (1.2.3 < 1.2.3+1), and build identifier
// lists are compared the same way as pre-release identifier lists — numeric
// identifiers compared numerically, alphanumeric compared lexically (ASCII),
// numeric < alphanumeric, longer list wins when all prior identifiers are equal.
// This differs from SemVer 2.0 / Cargo / Hex, which discard build metadata.
//
// Versions in pubspec.lock are bare (e.g. "1.2.3+1", never "v1.2.3+1").  This
// function strips any leading "v" that canonical() may have added upstream.
//
// Returns:
//   - VersionAffected    — version falls within the advisory range.
//   - VersionNotAffected — version is provably outside the range.
//   - VersionUndecidable — the query version or a range bound is not valid
//     Pub SemVer.  Parse errors are NEVER silently treated as NotAffected;
//     callers MUST emit a synthetic UNKNOWN finding with incomplete=true.
//
// Range semantics (OSV schema):
//   - Introduced is an inclusive lower bound; empty means "since the beginning".
//   - Fixed is an exclusive upper bound; empty means "no fix yet".
//   - LastAffected is an inclusive upper bound; at most one of Fixed/LastAffected
//     is set per range.
//
// Prerelease ordering: a prerelease of a given major.minor.patch sorts BEFORE
// the release (1.0.0-rc.1 < 1.0.0).
func pubVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// Pub registry versions never carry a "v" prefix.  Strip it in case the
	// upstream pipeline ran canonical() (which adds "v") before calling here.
	version = strings.TrimPrefix(version, "v")

	qv, ok := parsePubVersion(version)
	if !ok {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		iv, ok := parsePubVersion(strings.TrimPrefix(r.Introduced, "v"))
		if !ok {
			return VersionUndecidable
		}
		if comparePubVersions(qv, iv) < 0 {
			return VersionNotAffected // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive, LastAffected is inclusive.
	if r.Fixed != "" {
		fv, ok := parsePubVersion(strings.TrimPrefix(r.Fixed, "v"))
		if !ok {
			return VersionUndecidable
		}
		if comparePubVersions(qv, fv) >= 0 {
			return VersionNotAffected // version >= fixed
		}
	} else if r.LastAffected != "" {
		lv, ok := parsePubVersion(strings.TrimPrefix(r.LastAffected, "v"))
		if !ok {
			return VersionUndecidable
		}
		if comparePubVersions(qv, lv) > 0 {
			return VersionNotAffected // version > last_affected
		}
	}

	return VersionAffected
}

// pubVersion is a parsed Pub (pub_semver) version.
type pubVersion struct {
	major, minor, patch int
	pre                 []string // pre-release identifiers; empty if none
	build               []string // build metadata identifiers; empty if none
}

// parsePubVersion parses a Pub version string (leading "v" must be stripped
// before calling).  Returns (pubVersion{}, false) on any parse failure.
//
// Valid form:  MAJOR.MINOR.PATCH[-PRE[.PRE...]][+BUILD[.BUILD...]]
// where MAJOR, MINOR, PATCH are non-negative integers and PRE/BUILD are
// dot-separated identifiers (alphanumeric or numeric).
func parsePubVersion(v string) (pubVersion, bool) {
	if v == "" {
		return pubVersion{}, false
	}

	// Split off build metadata first (everything after the first '+').
	var buildStr string
	if idx := strings.IndexByte(v, '+'); idx >= 0 {
		buildStr = v[idx+1:]
		v = v[:idx]
	}

	// Split off pre-release (everything after the first '-').
	var preStr string
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		preStr = v[idx+1:]
		v = v[:idx]
	}

	// Parse core: exactly MAJOR.MINOR.PATCH.
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return pubVersion{}, false
	}
	major, err := parseNonNegInt(parts[0])
	if err != nil {
		return pubVersion{}, false
	}
	minor, err := parseNonNegInt(parts[1])
	if err != nil {
		return pubVersion{}, false
	}
	patch, err := parseNonNegInt(parts[2])
	if err != nil {
		return pubVersion{}, false
	}

	var pre []string
	if preStr != "" {
		pre = strings.Split(preStr, ".")
	}

	var build []string
	if buildStr != "" {
		build = strings.Split(buildStr, ".")
	}

	return pubVersion{
		major: major,
		minor: minor,
		patch: patch,
		pre:   pre,
		build: build,
	}, true
}

// parseNonNegInt parses a string as a non-negative integer.
// Returns an error if the string is empty, non-numeric, or negative.
func parseNonNegInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, strconv.ErrRange
	}
	return n, nil
}

// comparePubVersions returns -1, 0, or +1 per pub_semver Version.compareTo.
//
//  1. Compare major, minor, patch numerically.
//  2. Pre-release: WITH pre sorts BEFORE the same version WITHOUT pre
//     (1.0.0-dev < 1.0.0); two pre-releases are compared by identifier list
//     per SemVer §11.
//  3. Build metadata: WITHOUT build sorts BEFORE WITH build
//     (1.2.3 < 1.2.3+1); two build strings are compared by identifier list
//     the same way as pre-release (numeric numerically, else lexically,
//     numeric < alphanumeric, longer wins when all equal).
func comparePubVersions(a, b pubVersion) int {
	// 1. Core numeric comparison.
	if c := pubCmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := pubCmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := pubCmpInt(a.patch, b.patch); c != 0 {
		return c
	}

	// 2. Pre-release ordering.
	switch {
	case len(a.pre) > 0 && len(b.pre) == 0:
		return -1 // pre-release < release
	case len(a.pre) == 0 && len(b.pre) > 0:
		return 1 // release > pre-release
	case len(a.pre) > 0 && len(b.pre) > 0:
		if c := comparePubIdentifierList(a.pre, b.pre); c != 0 {
			return c
		}
	}

	// 3. Build metadata ordering (the fix: unlike SemVer 2.0, Pub orders it).
	switch {
	case len(a.build) == 0 && len(b.build) > 0:
		return -1 // no-build < with-build
	case len(a.build) > 0 && len(b.build) == 0:
		return 1 // with-build > no-build
	case len(a.build) > 0 && len(b.build) > 0:
		return comparePubIdentifierList(a.build, b.build)
	}

	return 0
}

// comparePubIdentifierList compares two dot-separated identifier lists.
// Rules: compare element by element; numeric identifiers numerically; others
// lexically (ASCII); numeric < alphanumeric; longer list wins when all
// prior identifiers are equal.
func comparePubIdentifierList(a, b []string) int {
	lim := len(a)
	if len(b) < lim {
		lim = len(b)
	}
	for i := 0; i < lim; i++ {
		if c := comparePubIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	return pubCmpInt(len(a), len(b))
}

// comparePubIdentifier compares two individual version identifiers.
// If both parse as integers, compare numerically.
// If only one is numeric, numeric < alphanumeric.
// If neither is numeric, compare lexically (ASCII byte order).
func comparePubIdentifier(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return pubCmpInt(an, bn)
	case aerr == nil:
		return -1 // numeric < alphanumeric
	case berr == nil:
		return 1 // alphanumeric > numeric
	default:
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
}

// pubCmpInt returns -1, 0, or +1 for a compared to b.
func pubCmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// init registers the Pub ecosystem comparator into the shared registry.
// pubVersionInRangeV implements the full pub_semver Version.compareTo ordering,
// including significant and ordered build metadata (unlike Cargo / SemVer 2.0).
func init() {
	RegisterComparator(EcosystemPub, pubVersionInRangeV)
}
