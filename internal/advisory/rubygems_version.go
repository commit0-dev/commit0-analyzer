package advisory

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// gemSegment is one parsed segment of a Gem::Version.
//
// RubyGems version strings are scanned as alternating runs of digits and
// letters (mimicking Ruby's String#scan(/[0-9]+|[a-z]+/i)).  Dot separators
// and mixed letter/digit adjacency (e.g. "rc1") are handled implicitly by the
// scan — each contiguous run becomes one segment.
//
// Ordering contract (Gem::Version#<=> semantics):
//
//	string segment < integer segment (pre-release sorts BEFORE the release)
//
// So `1.0.0.beta < 1.0.0`, `1.0.0.rc1 < 1.0.0`, `1.0.0.alpha < 1.0.0.beta`.
// Two string segments compare lexicographically; two integer segments compare
// numerically.  A missing (padding) segment is treated as integer 0.
type gemSegment struct {
	isStr bool
	str   string // set when isStr == true
	num   int64  // set when isStr == false
}

// gemSegmentRe matches one contiguous run of digits or letters, matching
// Ruby's Gem::Version._segments scan pattern.
var gemSegmentRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

// parseGemVersion parses a Gem::Version-compatible version string.
//
// The leading "v"/"V" prefix is accepted and stripped so that the OSV
// canonical() representation ("v1.2.3") round-trips cleanly.
//
// Returns an error on empty input or any character that is not a digit,
// ASCII letter, or dot — invalid characters must not silently return a
// default; parse errors propagate as VersionUndecidable upstream.
func parseGemVersion(v string) ([]gemSegment, error) {
	v = strings.TrimSpace(v)
	// Strip OSV canonical "v" prefix.
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}

	// Special case: "0" and "" both represent the zero version.
	if v == "" || v == "0" {
		return []gemSegment{{isStr: false, num: 0}}, nil
	}

	// A valid Gem::Version starts with a digit (VERSION_PATTERN begins with
	// [0-9]+). Requiring a leading digit rejects all-letter garbage such as
	// "not-a-version" — whose hyphens would otherwise scan into string segments —
	// while still accepting hyphenated pre-releases like "3.0.0-rc.1".
	if v[0] < '0' || v[0] > '9' {
		return nil, fmt.Errorf("rubygems: version %q must start with a digit", v)
	}

	// Reject characters outside the allowed set (digits, ASCII letters, dots,
	// and hyphens). A hyphen is just a separator in Gem::Version: its segment
	// scan is /[0-9]+|[a-z]+/i, so "3.0.0-rc.1" and "3.0.0.rc.1" both segment to
	// [3,0,0,"rc",1] — a pre-release of 3.0.0. OSV RubyGems range bounds use the
	// hyphen form (e.g. introduced "3.0.0-rc.1"); rejecting "-" here turned a
	// decidable bound into Undecidable and surfaced a false UNKNOWN finding
	// (e.g. jquery-rails 4.6.1 flagged for an advisory affecting only 3.0.0-rc.1).
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-'
		if !ok {
			return nil, fmt.Errorf("rubygems: invalid character %q in version %q", string(c), v)
		}
	}

	tokens := gemSegmentRe.FindAllString(v, -1)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("rubygems: cannot parse version %q", v)
	}

	segs := make([]gemSegment, 0, len(tokens))
	for _, tok := range tokens {
		if tok[0] >= '0' && tok[0] <= '9' {
			n, err := strconv.ParseInt(tok, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("rubygems: numeric overflow in segment %q of version %q: %w", tok, v, err)
			}
			segs = append(segs, gemSegment{isStr: false, num: n})
		} else {
			// Normalise to lower-case for stable comparison (Gem::Version is
			// case-insensitive on string segments in practice).
			segs = append(segs, gemSegment{isStr: true, str: strings.ToLower(tok)})
		}
	}

	return segs, nil
}

// canonicalGemSegments implements Ruby's Gem::Version#canonical_segments.
//
// The algorithm mirrors Gem::Version#_split_segments combined with trailing-zero
// stripping applied to each part independently:
//
//  1. Split at the first string segment into:
//     numPfx   — the leading all-integer prefix
//     alphaTail — everything from the first string segment onward
//
//  2. Strip trailing integer-zero segments from each part.
//
//  3. Concatenate numPfx + alphaTail.
//
// Examples:
//
//	[1,0,0,"beta",1]  → numPfx=[1]; alphaTail=["beta",1] → [1,"beta",1]
//	[1,0,"beta",1]    → numPfx=[1]; alphaTail=["beta",1] → [1,"beta",1]  (same!)
//	[1,0,0]           → numPfx=[1]; alphaTail=[]          → [1]
//	[1,0,0,1]         → numPfx=[1,0,0,1]; alphaTail=[]   → [1,0,0,1]
func canonicalGemSegments(segs []gemSegment) []gemSegment {
	// Locate the first string segment (split point).
	split := len(segs)
	for i, s := range segs {
		if s.isStr {
			split = i
			break
		}
	}

	numPfx := segs[:split]
	alphaTail := segs[split:]

	// Strip trailing integer-zero segments from the numeric prefix.
	n := len(numPfx)
	for n > 0 && !numPfx[n-1].isStr && numPfx[n-1].num == 0 {
		n--
	}
	numPfx = numPfx[:n]

	// Strip trailing integer-zero segments from the alpha tail.
	// (Mirrors Ruby's map! { |s| s.reverse.drop_while(&:zero?).reverse }.)
	m := len(alphaTail)
	for m > 0 && !alphaTail[m-1].isStr && alphaTail[m-1].num == 0 {
		m--
	}
	alphaTail = alphaTail[:m]

	if len(alphaTail) == 0 {
		return numPfx
	}
	if len(numPfx) == 0 {
		return alphaTail
	}
	result := make([]gemSegment, 0, len(numPfx)+len(alphaTail))
	result = append(result, numPfx...)
	result = append(result, alphaTail...)
	return result
}

// compareGemVersions returns the ordering of two parsed Gem::Version segment
// slices: negative when a < b, 0 when equal, positive when a > b.
//
// Both inputs are first reduced to their canonical form via
// canonicalGemSegments (Ruby's Gem::Version#canonical_segments), which strips
// trailing integer zeros from the numeric prefix so that 1.0.0 and 1.0 and 1
// all compare equal, and 1.0.0.beta1 and 1.0.beta1 compare equal.
//
// After canonicalization the canonical lists are compared element-wise. Missing
// elements on the shorter list are treated as integer 0 (same Gem::Version
// zero-padding semantics, but now applied after the canonical reduction).
//
// Mixed-type rules (the pre-release invariant):
//
//	string < integer → `1.0.0.beta < 1.0.0`
//	integer > string → `1.0.0 > 1.0.0.beta`
func compareGemVersions(a, b []gemSegment) int {
	ca := canonicalGemSegments(a)
	cb := canonicalGemSegments(b)

	n := len(ca)
	if len(cb) > n {
		n = len(cb)
	}

	for i := 0; i < n; i++ {
		var lhs, rhs gemSegment
		if i < len(ca) {
			lhs = ca[i]
		} // else: lhs is zero-value gemSegment{isStr:false, num:0}
		if i < len(cb) {
			rhs = cb[i]
		} // else: rhs is zero-value gemSegment{isStr:false, num:0}

		// Both integers — numeric compare.
		if !lhs.isStr && !rhs.isStr {
			if lhs.num < rhs.num {
				return -1
			}
			if lhs.num > rhs.num {
				return 1
			}
			continue
		}

		// Both strings — lexicographic compare.
		if lhs.isStr && rhs.isStr {
			if lhs.str < rhs.str {
				return -1
			}
			if lhs.str > rhs.str {
				return 1
			}
			continue
		}

		// Mixed types: string segment sorts BEFORE integer segment.
		if lhs.isStr {
			return -1 // string (pre-release) < integer (release)
		}
		return 1 // integer (release) > string (pre-release)
	}

	return 0
}

// rubyGemsVersionInRangeV is the tri-state Gem::Version range comparator
// registered for EcosystemRubyGems advisories.
//
// OSV RubyGems ranges carry ECOSYSTEM-type event pairs (introduced/fixed/
// last_affected); they do NOT embed pessimistic `~>` operators — those are
// resolved by bundler at lockfile generation time.  This function therefore
// handles only plain introduced/fixed/last_affected bounds.
//
// Returns:
//   - VersionAffected    — version is within the range.
//   - VersionNotAffected — version is provably outside the range.
//   - VersionUndecidable — version or a bound fails to parse.  NEVER treated
//     as NotAffected; callers must emit UNKNOWN + incomplete=true.
func rubyGemsVersionInRangeV(version string, r VersionRange) VersionVerdict {
	qsegs, err := parseGemVersion(version)
	if err != nil {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive (version >= introduced required).
	if r.Introduced != "" {
		isegs, err := parseGemVersion(r.Introduced)
		if err != nil {
			return VersionUndecidable
		}
		if compareGemVersions(qsegs, isegs) < 0 {
			return VersionNotAffected
		}
	}

	// Upper bound: Fixed is exclusive (version < fixed required).
	if r.Fixed != "" {
		fsegs, err := parseGemVersion(r.Fixed)
		if err != nil {
			return VersionUndecidable
		}
		if compareGemVersions(qsegs, fsegs) >= 0 {
			return VersionNotAffected
		}
		return VersionAffected
	}

	// Upper bound: LastAffected is inclusive (version <= last_affected required).
	if r.LastAffected != "" {
		lsegs, err := parseGemVersion(r.LastAffected)
		if err != nil {
			return VersionUndecidable
		}
		if compareGemVersions(qsegs, lsegs) > 0 {
			return VersionNotAffected
		}
	}

	return VersionAffected
}

// init registers the RubyGems comparator into the shared comparator registry.
// The "v" prefix added by canonical() is stripped inside parseGemVersion, so
// no wrapper is needed here (unlike crates.io which needs an explicit strip).
func init() {
	RegisterComparator(EcosystemRubyGems, rubyGemsVersionInRangeV)
}
