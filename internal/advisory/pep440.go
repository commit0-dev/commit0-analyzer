package advisory

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pep440PreRelease represents a PEP 440 pre-release segment.
// Kind is the canonical form: "a" (alpha), "b" (beta), "rc" (release candidate).
// N is the pre-release number (e.g. "a1" → Kind="a", N=1).
type pep440PreRelease struct {
	Kind string // "a", "b", or "rc"
	N    int
}

// pep440Version is a fully-parsed PEP 440 version according to
// https://peps.python.org/pep-0440/#public-version-identifiers.
//
// Ordering (lowest to highest):
//
//	dev release < pre-release (a < b < rc) < release < post-release
//
// Epoch dominates all other comparisons.
// Local version segments sort after the corresponding public version.
type pep440Version struct {
	Epoch   int
	Release []int // e.g. [1, 2, 3] for "1.2.3"; may have any number of parts
	Pre     *pep440PreRelease
	Post    int // -1 = not set
	Dev     int // -1 = not set
	Local   string
}

// pep440FullRegex is the single authoritative PEP 440 regex, following
// the normalised grammar from https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings.
//
// It is applied AFTER the input has been:
//   - lower-cased
//   - implicit-post expanded ("1.0-1" → "1.0.post1")
//   - local segment stripped (saved separately)
//   - dash/underscore separators replaced with "."
//
// After normalisation, pre-release tokens like "a1", "b2", "rc1", "alpha1",
// "beta2", "preview1", "c1" appear directly adjacent to the last release
// digit (possibly with a preceding ".").  The regex handles both forms.
//
// Capture groups:
//
//	1: epoch          (digits before "!", omitted when 0)
//	2: release        (dot-separated digits, e.g. "1.2.3")
//	3: pre-kind       ("a","alpha","b","beta","c","preview","rc") — optional
//	4: pre-number     (digits) — optional
//	5: post-number    (digits) — optional
//	6: dev-number     (digits) — optional
var pep440FullRegex = regexp.MustCompile(
	`^(?:(\d+)!)?` +
		`(\d+(?:\.\d+)*)` +
		`(?:\.?(a|alpha|b|beta|c|preview|rc)\.?(\d+))?` +
		`(?:\.post(\d+))?` +
		`(?:\.dev(\d+))?` +
		`$`,
)

// implicitPostRegex matches the bare-dash implicit post-release form, e.g. "1.0-1".
// This must be tested BEFORE separator normalisation.
var implicitPostRegex = regexp.MustCompile(`^(\d+(?:\.\d+)*)-(\d+)$`)

// parsePEP440 parses a PEP 440 version string into a pep440Version.
// Returns an error when the string cannot be parsed.
//
// Normalisation steps (per PEP 440 §6.1 / Appendix B):
//  0. Strip surrounding whitespace and a single leading "v" or "V"
//     (PEP 440 Appendix B explicitly permits both).
//  1. Lower-case.
//  2. Handle implicit post-release "N.N-N" → "N.N.post.N" before separator normalisation.
//  3. Separate local version (after "+").
//  4. Replace "-" / "_" separators with "." in the main segment.
//  5. Apply full regex to the normalised main segment.
//
// Note: canonical() in osv.go prepends "v" to every non-"v" version string so
// that Go semver parsing works. parsePEP440 must therefore accept the resulting
// "v2.28.0" as equivalent to "2.28.0".
func parsePEP440(v string) (*pep440Version, error) {
	if v == "" {
		return nil, fmt.Errorf("pep440: empty version string")
	}

	// Step 0: strip surrounding whitespace and an optional leading v/V.
	v = strings.TrimSpace(v)
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}

	if v == "" {
		return nil, fmt.Errorf("pep440: empty version string after normalization")
	}

	orig := v
	v = strings.ToLower(v)

	// Step 3: separate local version segment (everything after the first "+").
	var localPart string
	if idx := strings.IndexByte(v, '+'); idx >= 0 {
		localPart = v[idx+1:]
		v = v[:idx]
	}

	// Step 2: implicit post-release (must happen before separator normalisation).
	if m := implicitPostRegex.FindStringSubmatch(v); m != nil {
		v = m[1] + ".post" + m[2]
	}

	// Step 4: normalise separators in the main segment.
	v = strings.ReplaceAll(v, "-", ".")
	v = strings.ReplaceAll(v, "_", ".")

	// Step 5: match full regex.
	m := pep440FullRegex.FindStringSubmatch(v)
	if m == nil {
		return nil, fmt.Errorf("pep440: cannot parse %q (normalised: %q)", orig, v)
	}

	pv := &pep440Version{
		Post:  -1,
		Dev:   -1,
		Local: localPart,
	}

	// Epoch.
	if m[1] != "" {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("pep440: bad epoch in %q: %w", orig, err)
		}
		pv.Epoch = n
	}

	// Release segments.
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("pep440: bad release segment %q in %q: %w", part, orig, err)
		}
		pv.Release = append(pv.Release, n)
	}

	// Pre-release.
	if m[3] != "" {
		kind := canonicalisePEP440PreKind(m[3])
		n := 0
		if m[4] != "" {
			var err error
			n, err = strconv.Atoi(m[4])
			if err != nil {
				return nil, fmt.Errorf("pep440: bad pre-release number in %q: %w", orig, err)
			}
		}
		pv.Pre = &pep440PreRelease{Kind: kind, N: n}
	}

	// Post-release.
	if m[5] != "" {
		n, err := strconv.Atoi(m[5])
		if err != nil {
			return nil, fmt.Errorf("pep440: bad post number in %q: %w", orig, err)
		}
		pv.Post = n
	}

	// Dev release.
	if m[6] != "" {
		n, err := strconv.Atoi(m[6])
		if err != nil {
			return nil, fmt.Errorf("pep440: bad dev number in %q: %w", orig, err)
		}
		pv.Dev = n
	}

	return pv, nil
}

// canonicalisePEP440PreKind maps PEP 440 pre-release aliases to their canonical form.
func canonicalisePEP440PreKind(s string) string {
	switch s {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "c", "preview":
		return "rc"
	default:
		return s // already "a", "b", or "rc"
	}
}

// compare returns a negative int, zero, or positive int when v is less than,
// equal to, or greater than other per PEP 440 ordering rules.
//
// Ordering:
//  1. Epoch (higher epoch wins regardless of release).
//  2. Release (numerically, shorter slices padded with implicit zeros).
//  3. Pre/dev/post/final slot:
//     .devN < aN < bN < rcN < final < .postN
//  4. Local version: public (no local) < any local; two local versions compared
//     lexicographically (conservative — the spec says they are incomparable across
//     different distributions, but for range-checking we need a total order).
func (v *pep440Version) compare(other *pep440Version) int {
	// 1. Epoch.
	if d := v.Epoch - other.Epoch; d != 0 {
		return d
	}

	// 2. Release (zero-pad to equal length).
	maxLen := len(v.Release)
	if len(other.Release) > maxLen {
		maxLen = len(other.Release)
	}
	for i := 0; i < maxLen; i++ {
		vi, oi := 0, 0
		if i < len(v.Release) {
			vi = v.Release[i]
		}
		if i < len(other.Release) {
			oi = other.Release[i]
		}
		if d := vi - oi; d != 0 {
			return d
		}
	}

	// 3. Pre/dev/post/final ordering via slot encoding.
	vs, vn := pep440Slot(v)
	os, on := pep440Slot(other)
	if vs != os {
		return vs - os
	}
	if d := vn - on; d != 0 {
		return d
	}

	// 4. Local version: public < local.
	if v.Local == "" && other.Local != "" {
		return -1
	}
	if v.Local != "" && other.Local == "" {
		return 1
	}
	return strings.Compare(v.Local, other.Local)
}

// pep440Slot encodes the release phase as (slotOrdinal, number) for compare.
//
// Ordinals (must be consistent and totally ordered):
//
//	dev-of-dev   = -4000 (e.g. 1.0.dev0 with no pre)
//	dev-of-alpha = preKindOrdinal("a") - 1000
//	dev-of-beta  = preKindOrdinal("b") - 1000
//	dev-of-rc    = preKindOrdinal("rc") - 1000
//	alpha        = -3
//	beta         = -2
//	rc           = -1
//	final        = 0
//	post         = 1
func pep440Slot(v *pep440Version) (slot, n int) {
	if v.Dev >= 0 {
		if v.Pre != nil {
			// dev of a pre-release: e.g. 1.0a1.dev0 < 1.0a1
			return preKindOrdinal(v.Pre.Kind) - 1000, v.Dev
		}
		// pure dev release: 1.0.dev0
		return -4000, v.Dev
	}
	if v.Pre != nil {
		return preKindOrdinal(v.Pre.Kind), v.Pre.N
	}
	if v.Post >= 0 {
		return 1, v.Post
	}
	return 0, 0 // final release
}

// preKindOrdinal returns a small negative integer for each pre-release kind.
// a < b < rc.
func preKindOrdinal(kind string) int {
	switch kind {
	case "a":
		return -3
	case "b":
		return -2
	case "rc":
		return -1
	default:
		return -3 // treat unknown as alpha (conservative)
	}
}

// pep440VersionInRangeV is the tri-state PEP 440 comparator that feeds
// AffectsVersionV for EcosystemPyPI advisories.
//
// OSV PyPI ranges are ECOSYSTEM type (not SEMVER); this function applies
// PEP 440 semantics, not node-semver or Go semver.
//
// Returns:
//   - VersionAffected    — version is within [Introduced, Fixed) or ≤ LastAffected.
//   - VersionNotAffected — version is provably outside every bound.
//   - VersionUndecidable — the version or any range bound fails to parse.
//     A parse error is NEVER silently treated as NotAffected; the caller must
//     emit a synthetic UNKNOWN finding and set incomplete=true.
func pep440VersionInRangeV(version string, r VersionRange) VersionVerdict {
	qv, err := parsePEP440(version)
	if err != nil {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		iv, err := parsePEP440(r.Introduced)
		if err != nil {
			return VersionUndecidable
		}
		if qv.compare(iv) < 0 {
			return VersionNotAffected
		}
	}

	// Upper bound: Fixed is exclusive; LastAffected is inclusive.
	if r.Fixed != "" {
		fv, err := parsePEP440(r.Fixed)
		if err != nil {
			return VersionUndecidable
		}
		if qv.compare(fv) >= 0 {
			return VersionNotAffected
		}
	} else if r.LastAffected != "" {
		lv, err := parsePEP440(r.LastAffected)
		if err != nil {
			return VersionUndecidable
		}
		if qv.compare(lv) > 0 {
			return VersionNotAffected
		}
	}

	return VersionAffected
}
