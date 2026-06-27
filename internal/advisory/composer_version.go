package advisory

import (
	"strconv"
	"strings"
	"unicode"
)

// composerStability is the pre/post-release stability level of a Composer version.
//
// Ordering (ascending precedence, per Composer/Packagist specification):
//
//	dev (0) < alpha (1) < beta (2) < RC (3) < stable (4) < patch (5)
type composerStability int

const (
	composerStabilityDev    composerStability = 0
	composerStabilityAlpha  composerStability = 1
	composerStabilityBeta   composerStability = 2
	composerStabilityRC     composerStability = 3
	composerStabilityStable composerStability = 4 // no suffix
	composerStabilityPatch  composerStability = 5
)

// composerVersion is the parsed, normalized form of a Composer package version.
//
// Normalization follows Composer's own VersionParser logic:
//   - 1–4 numeric segments; missing segments default to 0 (e.g. "1.2" → 1.2.0.0).
//   - A stability suffix (after the first '-' that follows a digit) names the
//     pre/post-release tier; an optional integer suffix ranks within that tier.
//   - No suffix → composerStabilityStable with stabNum=0.
type composerVersion struct {
	major, minor, patch, build int
	stability                  composerStability
	stabNum                    int // optional integer after the stability keyword (e.g. "alpha.1" → 1)
}

// isComposerBranchAlias reports whether v is a VCS-branch alias rather than an
// exact version pin. Branch aliases are inherently undecidable — they resolve to
// whatever HEAD of a branch is at install time, so they cannot be compared against
// a fixed advisory range.
//
// Alias forms (Composer specification):
//   - "dev-<branchname>"  e.g. "dev-main", "dev-master", "dev-feature/foo"
//   - "<version>.x-dev"   e.g. "1.x-dev", "2.2.x-dev"
func isComposerBranchAlias(v string) bool {
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "dev-") {
		return true
	}
	if strings.HasSuffix(lower, ".x-dev") {
		return true
	}
	return false
}

// parseComposerVersion parses a Composer version string into a composerVersion.
//
// Accepted forms (all case-insensitive for the stability keyword):
//
//	[v]MAJOR[.MINOR[.PATCH[.BUILD]]][-STABILITY[.NUM|NUM]]
//
// where STABILITY is one of: dev, alpha, a, beta, b, RC, rc, patch, p.
//
// Branch aliases ("dev-main", "1.x-dev") return (nil, false) — they are
// undecidable, not an error in the strictest sense, but must propagate as
// VersionUndecidable to avoid silent false negatives.
//
// Any parse failure returns (nil, false). Callers MUST treat false as
// VersionUndecidable, never as VersionNotAffected.
func parseComposerVersion(v string) (*composerVersion, bool) {
	v = strings.TrimSpace(v)

	// Branch aliases are inherently undecidable.
	if isComposerBranchAlias(v) {
		return nil, false
	}

	// Strip optional leading 'v'/'V' prefix.
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	if v == "" {
		return nil, false
	}

	// Split the numeric core from the stability suffix at the first '-' that
	// immediately follows a digit. Example: "1.2.3-alpha1" → core="1.2.3", suf="alpha1".
	core := v
	stabRaw := ""
	hadSep := false
	if idx := findStabilitySep(v); idx >= 0 {
		core = v[:idx]
		stabRaw = v[idx+1:] // strip the '-'
		hadSep = true
	}

	if core == "" {
		return nil, false
	}

	// A trailing '-' with nothing after it (e.g. "1.0.0-") is invalid.
	if hadSep && stabRaw == "" {
		return nil, false
	}

	// Parse the numeric core: 1–4 dot-separated non-negative integers.
	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil, false
	}
	nums := make([]int, 4) // default to 0 for absent segments
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

	cv := &composerVersion{
		major: nums[0],
		minor: nums[1],
		patch: nums[2],
		build: nums[3],
	}

	// No separator → stable with no stability number.
	if !hadSep {
		cv.stability = composerStabilityStable
		return cv, true
	}

	// Parse stability keyword + optional numeric suffix.
	stab, num, ok := parseComposerStability(stabRaw)
	if !ok {
		return nil, false
	}
	cv.stability = stab
	cv.stabNum = num
	return cv, true
}

// findStabilitySep returns the index of the '-' that separates the numeric core
// from the stability suffix in a Composer version string, or -1 when none exists.
//
// The separator must follow at least one digit so that a leading '-' (invalid) or
// a bare stability keyword is not mistakenly split.
func findStabilitySep(v string) int {
	for i, ch := range v {
		if ch == '-' && i > 0 && unicode.IsDigit(rune(v[i-1])) {
			return i
		}
	}
	return -1
}

// parseComposerStability parses the stability portion of a Composer version string
// (the part after the first '-' separator).
//
// Accepted keyword + optional number combinations:
//
//	"dev"        → (composerStabilityDev,    0, true)
//	"alpha"/"a"  → (composerStabilityAlpha,  N, true)
//	"beta"/"b"   → (composerStabilityBeta,   N, true)
//	"RC"/"rc"    → (composerStabilityRC,     N, true)
//	"patch"/"p"  → (composerStabilityPatch,  N, true)
//
// The optional number N may be appended directly ("alpha1", "RC2") or after a
// dot ("alpha.1", "beta.3"). An absent number is treated as N=0.
//
// Returns (_, _, false) for unrecognised or malformed suffixes.
func parseComposerStability(s string) (composerStability, int, bool) {
	if s == "" {
		return 0, 0, false
	}
	lower := strings.ToLower(s)

	// Possible forms: "dev", "alpha", "alpha1", "alpha.1", "a", "a1", "a.1", etc.
	// We detect the keyword as a leading alphabetic run, then the optional number.

	// Split keyword from number suffix.
	keyEnd := 0
	for keyEnd < len(lower) && unicode.IsLetter(rune(lower[keyEnd])) {
		keyEnd++
	}
	keyword := lower[:keyEnd]
	rest := s[keyEnd:] // everything after the letters

	// Optional separator between keyword and number: a single '.'.
	rest = strings.TrimPrefix(rest, ".")

	// rest must now be purely digits (or empty).
	num := 0
	if rest != "" {
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		num = n
	}

	switch keyword {
	case "dev":
		if num != 0 {
			// "dev1" is not a valid Composer stability; treat as undecidable.
			return 0, 0, false
		}
		return composerStabilityDev, 0, true
	case "alpha", "a":
		return composerStabilityAlpha, num, true
	case "beta", "b":
		return composerStabilityBeta, num, true
	case "rc":
		return composerStabilityRC, num, true
	case "patch", "p":
		return composerStabilityPatch, num, true
	default:
		return 0, 0, false
	}
}

// compare returns a negative integer when cv < other, zero when equal, and a
// positive integer when cv > other, following Composer version precedence rules.
//
// Comparison order:
//  1. Numeric 4-tuple (major, minor, patch, build) — ascending.
//  2. Stability tier — ascending (dev < alpha < beta < RC < stable < patch).
//  3. Stability number — ascending within a tier (e.g. alpha.1 < alpha.2).
func (cv *composerVersion) compare(other *composerVersion) int {
	if d := composerCmpInt(cv.major, other.major); d != 0 {
		return d
	}
	if d := composerCmpInt(cv.minor, other.minor); d != 0 {
		return d
	}
	if d := composerCmpInt(cv.patch, other.patch); d != 0 {
		return d
	}
	if d := composerCmpInt(cv.build, other.build); d != 0 {
		return d
	}
	if d := composerCmpInt(int(cv.stability), int(other.stability)); d != 0 {
		return d
	}
	return composerCmpInt(cv.stabNum, other.stabNum)
}

// composerCmpInt returns -1, 0, or 1 for signed integer comparison.
func composerCmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// composerVersionInRangeV is the tri-state Packagist/Composer version comparator.
//
// Returns VersionUndecidable (never VersionNotAffected) on any parse failure so
// that no advisory is silently dropped due to an unparseable version string.
//
// Range semantics (OSV):
//   - Introduced: inclusive lower bound; empty = since the beginning.
//   - Fixed: exclusive upper bound; empty = no fix yet (still vulnerable).
//   - LastAffected: inclusive upper bound; at most one of Fixed/LastAffected is set.
func composerVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// A branch alias in the query position is undecidable.
	if isComposerBranchAlias(version) {
		return VersionUndecidable
	}

	qv, ok := parseComposerVersion(version)
	if !ok {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		if isComposerBranchAlias(r.Introduced) {
			return VersionUndecidable
		}
		iv, ok := parseComposerVersion(r.Introduced)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(iv) < 0 {
			return VersionNotAffected // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive; LastAffected is inclusive.
	if r.Fixed != "" {
		if isComposerBranchAlias(r.Fixed) {
			return VersionUndecidable
		}
		fv, ok := parseComposerVersion(r.Fixed)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(fv) >= 0 {
			return VersionNotAffected // version >= fixed
		}
	} else if r.LastAffected != "" {
		if isComposerBranchAlias(r.LastAffected) {
			return VersionUndecidable
		}
		lv, ok := parseComposerVersion(r.LastAffected)
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
	RegisterComparator(EcosystemPackagist, composerVersionInRangeV)
}
