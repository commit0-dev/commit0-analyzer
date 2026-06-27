package advisory

import (
	"strconv"
	"strings"
	"unicode"
)

// mavenCanonicalQualifier normalises known Maven qualifier aliases to a single
// canonical spelling so that ordinal and lexicographic comparison produce a
// consistent total order.
//
// Rules from org.apache.maven.artifact.versioning.ComparableVersion (StringItem ctor):
//
//  1. When followedByDigit=true AND the token is exactly one character:
//     "a" → "alpha", "b" → "beta", "m" → "milestone".
//     These expansions apply ONLY when the single letter is immediately followed
//     by a digit (no separator). A bare "-a", "-b", "-m" is an UNKNOWN qualifier
//     that sorts ABOVE release (ordinal 2), not below it.
//
//  2. Unconditional aliases (ALIASES map in Maven source):
//     "ga" → "", "final" → "", "release" → "" (all synonyms for the release sentinel)
//     "cr" → "rc"
func mavenCanonicalQualifier(q string, followedByDigit bool) string {
	// Step 1: single-letter expansion (only when immediately followed by a digit).
	if followedByDigit && len(q) == 1 {
		switch q {
		case "a":
			q = "alpha"
		case "b":
			q = "beta"
		case "m":
			q = "milestone"
		}
	}
	// Step 2: unconditional aliases.
	switch q {
	case "ga", "final", "release":
		return ""
	case "cr":
		return "rc"
	default:
		return q
	}
}

// mavenQualifierOrdinal returns the ordering value for a Maven qualifier string.
//
// Maven qualifier ordering (ascending precedence), from Apache Maven source
// (org.apache.maven.artifact.versioning.ComparableVersion):
//
//	alpha (-5) < beta (-4) < milestone (-3) < rc (-2) < snapshot (-1) < "" (0, release) < sp (1) < unknown (2)
//
// Note: alpha/beta/milestone/rc are all below the release sentinel.
// "release", "final", and "ga" are canonicalized to "" before this function is
// called, so only "" appears as the release sentinel here.
// Unknown qualifiers (e.g. "jre", "android", "foo") sort ABOVE "sp" (ordinal 2); ties
// are broken lexicographically in mavenStrItem.compareTo.
// The input must already be lower-cased and canonicalized via mavenCanonicalQualifier.
func mavenQualifierOrdinal(q string) int {
	switch q {
	case "alpha":
		return -5
	case "beta":
		return -4
	case "milestone":
		return -3
	case "rc":
		return -2
	case "snapshot":
		return -1
	case "":
		return 0
	case "sp":
		return 1
	default:
		// Unknown qualifiers (e.g. "jre", "android", "foo") sort ABOVE the
		// known qualifier list, including above "sp" (ordinal 1). This matches
		// Apache Maven ComparableVersion, where an unknown qualifier gets index
		// len(QUALIFIERS)+"-"+qualifier, placing it after "sp" in the ordering.
		// Lexicographic tiebreak among unknowns is handled in mavenStrItem.compareTo.
		// IMPORTANT: returning 2 (not 0) means parseMavenVersion will NOT strip
		// unknown qualifiers as "trailing zeros", so "31.1-jre" != "31.1-android"
		// and "32.0.0" (release) < "32.0.0-jre" (unknown) as Maven requires.
		return 2
	}
}

// ── Hierarchical item model (Apache Maven ComparableVersion) ──────────────────
//
// Maven versions are parsed into a HIERARCHICAL tree, not a flat list.
// Three item kinds mirror the Java implementation exactly:
//
//   - mavenIntItem    — a non-negative integer (BigInteger in Java; int64 here).
//   - mavenStrItem    — a qualifier string (lower-cased, canonicalized).
//   - mavenListItem   — an ordered list of items that can itself be nested.
//
// The root of every parsed version is a mavenListItem.
//
// The separator rules determine when nesting occurs:
//   - "." appends the pending token to the CURRENT list (no nesting).
//   - "-" appends the pending token and then starts a NEW nested sub-list.
//   - A digit/letter transition (without a separator) also starts a new sub-list.
//
// After parsing, each mavenListItem is normalized bottom-up using Maven's exact
// algorithm: scan from right-to-left; remove null items; skip (continue past)
// non-null sub-lists; stop at the first non-null Integer or String.
// "Null" = IntItem(0), StringItem with release ordinal (ordinal 0), or empty ListItem.
// This makes 1 == 1.0 == 1.0.0 == 1.0-ga == 1.0-final and also
// 1.0-rc1 == 1.0.0-rc1 (trailing zeros before a sub-list are removed).

// mavenItem is implemented by mavenIntItem, mavenStrItem, and mavenListItem.
type mavenItem interface {
	// compareTo returns a negative, zero, or positive int when this item is
	// less than, equal to, or greater than other.  other==nil means "absent"
	// (the null/zero sentinel used when one list is exhausted during comparison).
	compareTo(other mavenItem) int
	// isNull returns true when this item is semantically equal to the absent value
	// and therefore eligible for stripping during normalization.
	isNull() bool
}

// ── mavenIntItem ──────────────────────────────────────────────────────────────

type mavenIntItem struct{ value int64 }

func (a *mavenIntItem) isNull() bool { return a.value == 0 }

func (a *mavenIntItem) compareTo(other mavenItem) int {
	switch b := other.(type) {
	case nil:
		// absent == zero; any positive integer is greater than absent.
		if a.value == 0 {
			return 0
		}
		return 1
	case *mavenIntItem:
		switch {
		case a.value < b.value:
			return -1
		case a.value > b.value:
			return 1
		default:
			return 0
		}
	case *mavenStrItem:
		return 1 // integer > any qualifier
	case *mavenListItem:
		return 1 // integer > list
	}
	return 0
}

// ── mavenStrItem ──────────────────────────────────────────────────────────────

type mavenStrItem struct{ qualifier string }

func (a *mavenStrItem) isNull() bool { return mavenQualifierOrdinal(a.qualifier) == 0 }

func (a *mavenStrItem) compareTo(other mavenItem) int {
	switch b := other.(type) {
	case nil:
		// Compare this qualifier's ordinal against the release ordinal (0).
		ord := mavenQualifierOrdinal(a.qualifier)
		switch {
		case ord < 0:
			return -1
		case ord > 0:
			return 1
		default:
			return 0
		}
	case *mavenIntItem:
		return -1 // qualifier < integer
	case *mavenStrItem:
		ao := mavenQualifierOrdinal(a.qualifier)
		bo := mavenQualifierOrdinal(b.qualifier)
		if ao != bo {
			if ao < bo {
				return -1
			}
			return 1
		}
		// Same ordinal (both unknown or both the same canonical qualifier):
		// use lexicographic ordering as the tiebreak.
		return strings.Compare(a.qualifier, b.qualifier)
	case *mavenListItem:
		return -1 // qualifier < list
	}
	return 0
}

// ── mavenListItem ─────────────────────────────────────────────────────────────

type mavenListItem struct{ items []mavenItem }

func (a *mavenListItem) isNull() bool { return len(a.items) == 0 }

func (a *mavenListItem) compareTo(other mavenItem) int {
	switch b := other.(type) {
	case nil:
		// Compare this list against "absent" by comparing each element against nil.
		// The first non-zero result decides.
		for _, item := range a.items {
			c := item.compareTo(nil)
			if c != 0 {
				return c
			}
		}
		return 0
	case *mavenIntItem:
		return -1 // list < integer
	case *mavenStrItem:
		return 1 // list > qualifier
	case *mavenListItem:
		// Element-wise comparison; when one list is exhausted, remaining elements
		// of the longer list are compared against nil (absent).
		maxLen := len(a.items)
		if len(b.items) > maxLen {
			maxLen = len(b.items)
		}
		for i := 0; i < maxLen; i++ {
			var ai, bi mavenItem
			if i < len(a.items) {
				ai = a.items[i]
			}
			if i < len(b.items) {
				bi = b.items[i]
			}
			var c int
			if ai == nil {
				// null vs bi: negate bi.compareTo(nil) to get null.compareTo(bi).
				c = -bi.compareTo(nil)
			} else {
				c = ai.compareTo(bi) // bi may be nil (absent); that's handled above
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}
	return 0
}

// ── normalizeListItem ─────────────────────────────────────────────────────────

// normalizeListItem recursively normalizes a mavenListItem tree in post-order
// (children first, then parent), using Apache Maven's exact ListItem.normalize()
// algorithm:
//
//   - Scan items from right to left (index = size-1 down to 0).
//   - If the item isNull(): remove it.
//   - Else if the item is a (non-null) ListItem: keep it AND continue scanning left.
//   - Else (non-null Integer or String): stop.
//
// The "continue past non-null sub-lists" rule is the critical difference from a
// simple "strip trailing nulls" loop.  It ensures that trailing zero components
// before a qualifier sub-list are also removed, e.g.:
//
//	"1.0.0-rc1" → [1, 0, 0, ["rc",[1]]] → [1, ["rc",[1]]]  (same as "1.0-rc1")
//	"31.1.0-jre" → [31, 1, 0, ["jre"]] → [31, 1, ["jre"]] (same as "31.1-jre")
func normalizeListItem(l *mavenListItem) {
	// Normalize nested sub-lists first (post-order / bottom-up).
	for _, item := range l.items {
		if sub, ok := item.(*mavenListItem); ok {
			normalizeListItem(sub)
		}
	}
	// Scan right-to-left per Maven's ListItem.normalize() algorithm.
	for i := len(l.items) - 1; i >= 0; i-- {
		item := l.items[i]
		if item.isNull() {
			// Null item: remove it and keep scanning left.
			l.items = append(l.items[:i], l.items[i+1:]...)
		} else if _, isList := item.(*mavenListItem); isList {
			// Non-null sub-list: keep it, but continue scanning left for more
			// nulls (this is the key difference from a simple trailing-null strip).
			continue
		} else {
			// Non-null Integer or String: stop.
			break
		}
	}
}

// ── parseMavenVersion ─────────────────────────────────────────────────────────

// mavenVersion is the parsed, normalized form of a Maven ComparableVersion.
type mavenVersion struct {
	root *mavenListItem
}

// parseMavenVersion tokenises a Maven version string per ComparableVersion rules
// and returns the hierarchical item tree.
//
// Tokenisation rules (from org.apache.maven.artifact.versioning.ComparableVersion):
//   - Input is lower-cased first (case-insensitive).
//   - "." appends the pending token to the current list; does NOT nest.
//   - "-" appends the pending token then creates and pushes a new nested sub-list.
//   - A digit/letter transition (no separator) also creates a new nested sub-list.
//   - An empty token at a separator position → IntegerItem(0).
//   - After all tokens are consumed, every ListItem is normalized bottom-up.
//
// Returns (nil, false) for an empty input or an integer token that overflows int64.
func parseMavenVersion(v string) (*mavenVersion, bool) {
	v = strings.TrimSpace(v)
	// Strip a leading "v" that canonical() may have prepended.
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	v = strings.ToLower(v)
	n := len(v)

	root := &mavenListItem{}
	stack := []*mavenListItem{}
	current := root

	parseOK := true

	// finalizeToken appends the token tok to current.
	// wasDigit=true → IntegerItem; false → StringItem.
	// followedByDigit is forwarded to mavenCanonicalQualifier: the a/b/m→alpha/beta/
	// milestone expansion applies only when the single-letter token is immediately
	// followed by a digit (letter→digit transition in the main loop).
	// An empty token always appends IntegerItem(0).
	finalizeToken := func(tok string, wasDigit bool, followedByDigit bool) {
		if tok == "" {
			current.items = append(current.items, &mavenIntItem{value: 0})
			return
		}
		if wasDigit {
			num, err := strconv.ParseInt(tok, 10, 64)
			if err != nil {
				// Overflow: treat the entire version as unparseable.
				parseOK = false
				return
			}
			current.items = append(current.items, &mavenIntItem{value: num})
		} else {
			q := mavenCanonicalQualifier(tok, followedByDigit)
			current.items = append(current.items, &mavenStrItem{qualifier: q})
		}
	}

	// pushSubList creates a new nested ListItem, appends it to current, and
	// makes it the new current.
	pushSubList := func() {
		sub := &mavenListItem{}
		current.items = append(current.items, sub)
		stack = append(stack, current)
		current = sub
	}

	// startIdx is the beginning of the current token run.
	// isDigit tracks whether the current run is a digit run (true) or letter run (false).
	// Both variables follow Apache Maven ComparableVersion's local variables.
	startIdx := 0
	isDigit := false

	for i := 0; i < n; i++ {
		ch := rune(v[i])

		switch {
		case ch == '.':
			// Dot separator: finalize token into current list (no nesting).
			// followedByDigit=false (a letter run ending at '.' is bare, not digit-adjacent).
			finalizeToken(v[startIdx:i], isDigit, false)
			startIdx = i + 1
			// isDigit is intentionally NOT reset here; it will be set when the
			// next non-separator character is encountered (matching Maven source).

		case ch == '-':
			// Dash separator: finalize token, then start a new nested sub-list.
			// followedByDigit=false (same reasoning as for '.').
			finalizeToken(v[startIdx:i], isDigit, false)
			startIdx = i + 1
			pushSubList()

		case unicode.IsDigit(ch):
			// Letter-to-digit transition (only when there is an accumulated token).
			// followedByDigit=true: the letter token was immediately followed by a digit.
			if !isDigit && i > startIdx {
				finalizeToken(v[startIdx:i], false, true) // letter→digit: followedByDigit=true
				startIdx = i
				pushSubList()
			}
			isDigit = true

		default: // letter
			// Digit-to-letter transition (only when there is an accumulated token).
			if isDigit && i > startIdx {
				finalizeToken(v[startIdx:i], true, false)
				startIdx = i
				pushSubList()
			}
			isDigit = false
		}

		if !parseOK {
			return nil, false
		}
	}

	// Finalize the last token (if any characters remain since the last separator).
	// followedByDigit=false: end-of-string means no digit follows.
	if startIdx < n {
		finalizeToken(v[startIdx:], isDigit, false)
	}

	if !parseOK {
		return nil, false
	}

	// Normalize the tree bottom-up: strip trailing null items from every ListItem,
	// continuing past non-null sub-lists per Maven's ListItem.normalize() algorithm.
	normalizeListItem(root)

	return &mavenVersion{root: root}, true
}

// compare returns a negative int, zero, or positive int when mv is less than,
// equal to, or greater than other per Maven ComparableVersion ordering rules.
func (mv *mavenVersion) compare(other *mavenVersion) int {
	return mv.root.compareTo(other.root)
}

// mavenVersionInRangeV is the tri-state Maven version comparator registered for
// EcosystemMaven. It implements Maven ComparableVersion ordering as specified by
// Apache Maven (org.apache.maven.artifact.versioning.ComparableVersion).
//
// OSV Maven ranges are ECOSYSTEM type; this function does NOT use semver.
//
// Returns:
//   - VersionAffected    — version is within [Introduced, Fixed) or ≤ LastAffected.
//   - VersionNotAffected — version is provably outside every bound.
//   - VersionUndecidable — the version or any range bound fails to parse.
//     A parse error is NEVER silently treated as NotAffected; the caller must
//     emit a synthetic UNKNOWN finding and set incomplete=true.
func mavenVersionInRangeV(version string, r VersionRange) VersionVerdict {
	qv, ok := parseMavenVersion(version)
	if !ok {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		iv, ok := parseMavenVersion(r.Introduced)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(iv) < 0 {
			return VersionNotAffected
		}
	}

	// Upper bound: Fixed is exclusive; LastAffected is inclusive.
	if r.Fixed != "" {
		fv, ok := parseMavenVersion(r.Fixed)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(fv) >= 0 {
			return VersionNotAffected
		}
	} else if r.LastAffected != "" {
		lv, ok := parseMavenVersion(r.LastAffected)
		if !ok {
			return VersionUndecidable
		}
		if qv.compare(lv) > 0 {
			return VersionNotAffected
		}
	}

	return VersionAffected
}

func init() {
	RegisterComparator(EcosystemMaven, mavenVersionInRangeV)
}
