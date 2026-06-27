package advisory

import (
	"strconv"
	"strings"
	"unicode"
)

// nugetPrePart is a single dot-separated identifier in a NuGet pre-release label.
// Per SemVer 2.0: identifiers are either all-digit (compared numerically) or
// alphanumeric (compared lexicographically). Numeric identifiers always have
// lower precedence than alphanumeric identifiers.
type nugetPrePart struct {
	isNum bool
	num   int
	str   string // lower-cased for case-insensitive comparison
}

// nugetVersion is the parsed form of a NuGet package version.
//
// NuGet versioning is SemVer 2.0 with an optional fourth numeric component
// (Revision). Comparison follows SemVer 2.0 rules once the Revision is included
// as a fourth numeric component (0 if absent). Build metadata (after "+") is
// stripped per SemVer 11.
//
// Floating versions ("1.*", "1.2.*") are detected and rejected at parse time —
// they are inherently undecidable as an exact pin.
type nugetVersion struct {
	major, minor, patch, revision int
	// pre is the parsed pre-release identifiers; nil means release version.
	// An empty slice would indicate a trailing "-" (invalid), but parseNugetVersion
	// returns false in that case, so nil unambiguously means release.
	pre []nugetPrePart
}

// isNugetFloating reports whether v contains a NuGet floating wildcard ("*").
// A floating version in a lockfile or range bound is inherently undecidable —
// it cannot be matched against an exact pinned version.
func isNugetFloating(v string) bool {
	return strings.ContainsRune(v, '*')
}

// parseNugetVersion parses a NuGet version string into a nugetVersion.
//
// Accepted forms (case-insensitive pre-release labels):
//
//	MAJOR[.MINOR[.PATCH[.REVISION]]][-prerelease.ident.ident][+buildmeta]
//
// Rules:
//   - Leading "v"/"V" prefix is stripped (OSV bounds may carry it).
//   - Build metadata (after "+") is silently dropped (SemVer 11).
//   - Floating wildcards ("*") → returns (nil, false) → VersionUndecidable.
//   - Empty pre-release after "-" is invalid → (nil, false).
//   - Negative or non-numeric core components → (nil, false).
//   - Missing components default to 0 (e.g. "1.0" → major=1, minor=0, patch=0, revision=0).
//
// Returns (nil, false) for any parse failure; callers must treat false as
// VersionUndecidable, never as VersionNotAffected.
func parseNugetVersion(v string) (*nugetVersion, bool) {
	v = strings.TrimSpace(v)
	// Strip leading "v"/"V" prefix (OSV range bounds may carry it; NuGet never does).
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	if v == "" {
		return nil, false
	}

	// Floating versions are undecidable — reject immediately.
	if isNugetFloating(v) {
		return nil, false
	}

	// Drop build metadata (after "+"); SemVer §11 says build metadata MUST be
	// ignored when determining version precedence.
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}

	// Split at the first "-" to separate the numeric core from the pre-release.
	core := v
	preStr := ""
	hasPre := false
	if idx := strings.Index(v, "-"); idx >= 0 {
		core = v[:idx]
		preStr = v[idx+1:]
		hasPre = true
	}

	// An empty core (e.g. v = "-alpha") is invalid.
	if core == "" {
		return nil, false
	}

	// A trailing "-" with no pre-release label is invalid.
	if hasPre && preStr == "" {
		return nil, false
	}

	// Parse core: MAJOR[.MINOR[.PATCH[.REVISION]]], 1–4 dot-separated integers.
	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil, false
	}
	nums := make([]int, 4) // defaults to 0
	for i, p := range parts {
		if p == "" {
			return nil, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		nums[i] = n
	}

	nv := &nugetVersion{
		major:    nums[0],
		minor:    nums[1],
		patch:    nums[2],
		revision: nums[3],
	}

	// Parse pre-release identifiers: dot-separated per SemVer 2.0 §9.
	if hasPre {
		idents := strings.Split(preStr, ".")
		for _, id := range idents {
			if id == "" {
				// Empty identifier (e.g. "1.0.0-alpha..1") is invalid.
				return nil, false
			}
			pp, ok := parseNugetPrePart(id)
			if !ok {
				return nil, false
			}
			nv.pre = append(nv.pre, pp)
		}
	}
	// nv.pre == nil means release version (no pre-release section).
	return nv, true
}

// parseNugetPrePart classifies a single pre-release identifier as numeric or
// alphanumeric (SemVer 2.0 §9). Numeric identifiers must not have a leading
// zero per SemVer (e.g. "01" is invalid; "0" is valid).
//
// NuGet pre-release labels are case-insensitive in practice; this function
// lower-cases alphanumeric identifiers for comparison consistency.
func parseNugetPrePart(id string) (nugetPrePart, bool) {
	if id == "" {
		return nugetPrePart{}, false
	}
	allDigit := true
	for _, ch := range id {
		if !unicode.IsDigit(ch) {
			allDigit = false
			break
		}
	}
	if allDigit {
		// Numeric: leading zeros are invalid per SemVer (except "0" itself).
		if len(id) > 1 && id[0] == '0' {
			return nugetPrePart{}, false
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			// Overflow — treat as undecidable.
			return nugetPrePart{}, false
		}
		return nugetPrePart{isNum: true, num: n}, true
	}
	// Alphanumeric: store lower-cased for case-insensitive comparison.
	return nugetPrePart{isNum: false, str: strings.ToLower(id)}, true
}

// compare returns a negative integer when nv < other, zero when equal, and a
// positive integer when nv > other, following NuGet / SemVer 2.0 precedence.
//
// Comparison order:
//  1. Major (numeric ascending).
//  2. Minor (numeric ascending).
//  3. Patch (numeric ascending).
//  4. Revision (numeric ascending; 0 = absent, so "1.0.0" == "1.0.0.0").
//  5. Pre-release vs release: release > pre-release (SemVer §11.3).
//  6. Pre-release identifier list: left-to-right, per SemVer §11.4.
//     Numeric < alphanumeric; tie on longer list wins.
func (nv *nugetVersion) compare(other *nugetVersion) int {
	if d := nugetCmpInt(nv.major, other.major); d != 0 {
		return d
	}
	if d := nugetCmpInt(nv.minor, other.minor); d != 0 {
		return d
	}
	if d := nugetCmpInt(nv.patch, other.patch); d != 0 {
		return d
	}
	if d := nugetCmpInt(nv.revision, other.revision); d != 0 {
		return d
	}

	// Pre-release precedence.
	hasPreA := nv.pre != nil
	hasPreB := other.pre != nil

	switch {
	case !hasPreA && !hasPreB:
		return 0 // both release
	case hasPreA && !hasPreB:
		return -1 // pre-release < release
	case !hasPreA && hasPreB:
		return 1 // release > pre-release
	}

	// Both have pre-release: compare identifiers left-to-right (SemVer §11.4).
	minLen := len(nv.pre)
	if len(other.pre) < minLen {
		minLen = len(other.pre)
	}
	for i := 0; i < minLen; i++ {
		a, b := nv.pre[i], other.pre[i]
		var d int
		switch {
		case a.isNum && b.isNum:
			d = nugetCmpInt(a.num, b.num)
		case !a.isNum && !b.isNum:
			// Both alphanumeric: lexicographic (case-insensitive via lower-cased storage).
			if a.str < b.str {
				d = -1
			} else if a.str > b.str {
				d = 1
			}
		case a.isNum && !b.isNum:
			// Numeric always has lower precedence than alphanumeric (SemVer §11.4.3).
			d = -1
		default:
			// Alphanumeric > numeric.
			d = 1
		}
		if d != 0 {
			return d
		}
	}
	// All shared identifiers are equal; larger set has higher precedence (SemVer §11.4.4).
	return nugetCmpInt(len(nv.pre), len(other.pre))
}

// nugetCmpInt returns -1, 0, or 1 for integer comparison without overflow.
func nugetCmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// nugetVersionInRangeV is the tri-state NuGet version comparator.
//
// Floating versions in either the query version or any range bound produce
// VersionUndecidable. A parse failure for any component also produces
// VersionUndecidable — never VersionNotAffected, so that no advisory is
// silently dropped due to an unparseable string.
//
// Range semantics (OSV):
//   - Introduced: inclusive lower bound; empty = since the beginning.
//   - Fixed: exclusive upper bound; empty = no fix yet.
//   - LastAffected: inclusive upper bound; at most one of Fixed/LastAffected.
func nugetVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// A floating query version is inherently undecidable as a pin.
	if isNugetFloating(version) {
		return VersionUndecidable
	}

	qv, ok := parseNugetVersion(version)
	if !ok {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		if isNugetFloating(r.Introduced) {
			return VersionUndecidable
		}
		iv, ok := parseNugetVersion(r.Introduced)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(iv) < 0 {
			return VersionNotAffected // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive; LastAffected is inclusive.
	if r.Fixed != "" {
		if isNugetFloating(r.Fixed) {
			return VersionUndecidable
		}
		fv, ok := parseNugetVersion(r.Fixed)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(fv) >= 0 {
			return VersionNotAffected // version >= fixed
		}
	} else if r.LastAffected != "" {
		if isNugetFloating(r.LastAffected) {
			return VersionUndecidable
		}
		lv, ok := parseNugetVersion(r.LastAffected)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(lv) > 0 {
			return VersionNotAffected // version > last_affected
		}
	}

	return VersionAffected
}

func init() {
	RegisterComparator(EcosystemNuGet, nugetVersionInRangeV)
}
