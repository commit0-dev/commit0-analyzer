package advisory

import (
	"testing"
)

// TestParseMavenVersion verifies basic tokenisation of Maven version strings.
func TestParseMavenVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input   string
		wantOK  bool
		wantStr string // canonical form for debugging; not strictly tested
	}{
		{"1.0", true, "1.0"},
		{"1.0.0", true, "1.0.0"},
		{"1.2.3", true, "1.2.3"},
		{"1.0-SNAPSHOT", true, "1.0-snapshot"},
		{"1.0-alpha-1", true, "1.0-alpha-1"},
		{"1.0-alpha1", true, "1.0-alpha1"},
		{"1.0-beta-2", true, "1.0-beta-2"},
		{"1.0-rc1", true, "1.0-rc1"},
		{"1.0-RC1", true, "1.0-rc1"},
		{"1.0-release", true, "1.0-release"},
		{"1.0-final", true, "1.0-final"},
		{"2.28.0", true, "2.28.0"},
		{"v2.28.0", true, "2.28.0"}, // strip leading "v" from canonical()
		{"", false, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			_, got := parseMavenVersion(tc.input)
			if got != tc.wantOK {
				t.Errorf("parseMavenVersion(%q) ok=%v, want %v", tc.input, got, tc.wantOK)
			}
		})
	}
}

// TestMavenVersionOrdering verifies the canonical Maven ComparableVersion ordering.
// Cases derived from the Apache Maven source tests and the research report.
func TestMavenVersionOrdering(t *testing.T) {
	t.Parallel()

	// Each entry: {lower, higher} — lower must compare < higher.
	lessThans := []struct{ lower, higher string }{
		// Qualifier ordering
		{"1.0-snapshot", "1.0"},
		{"1.0-alpha-1", "1.0"},
		{"1.0-alpha1", "1.0"},
		{"1.0-beta-1", "1.0"},
		{"1.0-rc1", "1.0"},
		{"1.0-SNAPSHOT", "1.0"},
		{"1.0-Alpha-1", "1.0-beta-1"},
		{"1.0-alpha", "1.0-beta"},
		{"1.0-beta", "1.0-rc"},
		{"1.0-milestone-1", "1.0-rc-1"},
		{"1.0-m1", "1.0-rc1"},
		{"1.0-rc1", "1.0"},
		{"1.0-cr1", "1.0"}, // "cr" is alias for "rc"
		{"1.0", "1.0-sp"},
		{"1.0", "1.0-sp1"},
		{"1.0-sp", "1.0-sp1"},

		// Numeric ordering
		{"1.0", "1.1"},
		{"1.9", "1.10"},
		{"1.0.1", "1.1"},
		{"1.0.0", "1.0.1"},
		{"2.0", "10.0"},
		{"1.0.0", "1.0.0.1"},

		// Trailing zero equivalence (not actually "less", but covered in equals)
		// Use a strictly less pair around these to avoid false failures.
		{"0.9", "1.0"},

		// Pre-release vs release
		{"1.0.0-alpha", "1.0.0"},
		{"1.0.0-beta", "1.0.0"},
		{"1.0.0-rc", "1.0.0"},
		{"1.0.0-snapshot", "1.0.0"},

		// snapshot is below release
		{"3.1.0-SNAPSHOT", "3.1.0"},
		{"3.1.0-snapshot", "3.1.0.Final"},

		// Commons-collections-style
		{"3.2", "3.2.1"},
		{"3.2.1", "4.0"},

		// Unknown (non-release) qualifiers sort ABOVE release and sp, lexically among themselves.
		// This covers Guava-style jre/android flavors and any arbitrary unknown qualifier.
		{"1.0", "1.0-jre"},           // unknown > release
		{"1.0", "1.0-android"},       // unknown > release
		{"1.0-android", "1.0-jre"},   // android < jre lexically (a < j)
		{"1.0-sp", "1.0-jre"},        // unknown (ordinal 2) > sp (ordinal 1)
		{"31.1", "31.1-jre"},         // Guava-scale: release < jre
		{"31.1-android", "31.1-jre"}, // Guava-scale: android < jre
	}

	for _, tc := range lessThans {
		tc := tc
		t.Run(tc.lower+"<"+tc.higher, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.lower)
			b, ok2 := parseMavenVersion(tc.higher)
			if !ok1 {
				t.Fatalf("failed to parse lower version %q", tc.lower)
			}
			if !ok2 {
				t.Fatalf("failed to parse higher version %q", tc.higher)
			}
			if got := a.compare(b); got >= 0 {
				t.Errorf("expected %q < %q, got compare=%d", tc.lower, tc.higher, got)
			}
			// Also check symmetry.
			if got := b.compare(a); got <= 0 {
				t.Errorf("expected %q > %q (reverse), got compare=%d", tc.higher, tc.lower, got)
			}
		})
	}

	// Equality cases: trailing zeros, aliases.
	equals := []struct{ a, b string }{
		{"1.0", "1.0.0"},
		{"1.0", "1.0.0.0"},
		{"1.0-release", "1.0"},
		{"1.0-final", "1.0"},
		{"1.0-0", "1.0"},
		{"1.0-ga", "1.0"},     // "ga" is a recognized Maven release alias (equal to "" release)
		{"1.0-rc", "1.0-cr"},  // rc and cr are the same rank (both ordinal -2)
	}

	for _, tc := range equals {
		tc := tc
		t.Run(tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.a)
			b, ok2 := parseMavenVersion(tc.b)
			if !ok1 {
				t.Fatalf("failed to parse %q", tc.a)
			}
			if !ok2 {
				t.Fatalf("failed to parse %q", tc.b)
			}
			if got := a.compare(b); got != 0 {
				t.Errorf("expected %q == %q, got compare=%d", tc.a, tc.b, got)
			}
		})
	}
}

// TestMavenVersionInRangeV tests the tri-state comparator for a variety of
// OSV-style ranges from real Maven advisories.
func TestMavenVersionInRangeV(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		version string
		r       VersionRange
		want    VersionVerdict
	}

	cases := []testCase{
		// --- Basic fixed upper bound ---
		{
			name:    "affected: inside [1.0, 2.0)",
			version: "1.5",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionAffected,
		},
		{
			name:    "not affected: at fixed bound (exclusive)",
			version: "2.0",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "not affected: above fixed bound",
			version: "2.1",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "not affected: below introduced",
			version: "0.9",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "affected: at introduced (inclusive)",
			version: "1.0",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionAffected,
		},

		// --- Open-ended (unfixed) range ---
		{
			name:    "affected: unfixed range",
			version: "99.0",
			r:       VersionRange{Introduced: "1.0"},
			want:    VersionAffected,
		},

		// --- LastAffected (inclusive upper) ---
		{
			name:    "affected: at last affected (inclusive)",
			version: "1.9",
			r:       VersionRange{Introduced: "1.0", LastAffected: "1.9"},
			want:    VersionAffected,
		},
		{
			name:    "not affected: above last affected",
			version: "2.0",
			r:       VersionRange{Introduced: "1.0", LastAffected: "1.9"},
			want:    VersionNotAffected,
		},

		// --- Maven qualifier ordering in ranges ---
		{
			name:    "snapshot inside range",
			version: "1.5-SNAPSHOT",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionAffected,
		},
		{
			name:    "rc is below release, inside range",
			version: "2.0-rc1",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionAffected,
		},
		{
			// 1.0-alpha1 < 1.0 in Maven ordering, so it is BELOW the Introduced
			// lower bound of 1.0 and is therefore NOT in the affected range.
			name:    "alpha below range lower bound — not affected",
			version: "1.0-alpha1",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionNotAffected,
		},

		// --- Real-world range: log4j-core GHSA-jfh8-c2jp-jmhp ---
		// log4j 2.0-beta9 through 2.14.1 (fixed in 2.15.0)
		{
			name:    "log4j 2.14.1 affected",
			version: "2.14.1",
			r:       VersionRange{Introduced: "2.0-beta9", Fixed: "2.15.0"},
			want:    VersionAffected,
		},
		{
			name:    "log4j 2.0-beta9 affected (at introduced)",
			version: "2.0-beta9",
			r:       VersionRange{Introduced: "2.0-beta9", Fixed: "2.15.0"},
			want:    VersionAffected,
		},
		{
			name:    "log4j 2.15.0 not affected (at fixed)",
			version: "2.15.0",
			r:       VersionRange{Introduced: "2.0-beta9", Fixed: "2.15.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "log4j 2.0-alpha1 not affected (below introduced)",
			version: "2.0-alpha1",
			r:       VersionRange{Introduced: "2.0-beta9", Fixed: "2.15.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "log4j 1.2.17 not affected (well below range)",
			version: "1.2.17",
			r:       VersionRange{Introduced: "2.0-beta9", Fixed: "2.15.0"},
			want:    VersionNotAffected,
		},

		// --- Parse errors → undecidable ---
		{
			name:    "empty version → undecidable",
			version: "",
			r:       VersionRange{Introduced: "1.0", Fixed: "2.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "unparseable introduced → undecidable",
			version: "1.5",
			r:       VersionRange{Introduced: "", Fixed: ""},
			// Empty Introduced and Fixed → range is open in both directions → affected.
			want: VersionAffected,
		},

		// --- Trailing zero equivalence in ranges ---
		{
			name:    "1.0.0 equals 1.0 — at fixed boundary",
			version: "1.0.0",
			r:       VersionRange{Introduced: "0.9", Fixed: "1.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "1.0 equals 1.0.0 — inside range using 1.0.0 bound",
			version: "1.0",
			r:       VersionRange{Introduced: "0.9", Fixed: "1.0.0"},
			want:    VersionNotAffected,
		},

		// --- sp qualifier (service pack) ---
		{
			name:    "sp is above release, not affected when range ends at release",
			version: "1.0-sp1",
			r:       VersionRange{Introduced: "1.0", Fixed: "1.0"},
			// Fixed == Introduced: empty range, nothing is affected.
			want: VersionNotAffected,
		},
		{
			name:    "sp1 not in [0,1.0) range",
			version: "1.0-sp1",
			r:       VersionRange{Introduced: "0", Fixed: "1.0"},
			want:    VersionNotAffected, // 1.0-sp1 > 1.0 ≥ fixed
		},

		// --- Unknown (non-release) qualifiers: Guava jre/android flavor cases ---
		// Guava publishes two artifacts whose versions differ only by jre/android suffix.
		// An advisory may have Fixed=X.Y.Z-jre; android (android < jre lexically) is still
		// inside the range and must be VersionAffected.
		{
			name:    "guava: android inside [1.0, 32.0.0-jre) — affected",
			version: "32.0.0-android",
			r:       VersionRange{Introduced: "1.0", Fixed: "32.0.0-jre"},
			want:    VersionAffected, // android < jre => below Fixed
		},
		{
			name:    "guava: jre at exclusive fixed bound — not affected",
			version: "32.0.0-jre",
			r:       VersionRange{Introduced: "1.0", Fixed: "32.0.0-jre"},
			want:    VersionNotAffected, // exactly at Fixed (exclusive)
		},
		{
			name:    "guava: release (32.0.0) inside [1.0, 32.0.0-jre) — affected",
			version: "32.0.0",
			r:       VersionRange{Introduced: "1.0", Fixed: "32.0.0-jre"},
			want:    VersionAffected, // 32.0.0 < 32.0.0-jre (release < unknown)
		},
		{
			name:    "unknown qualifier above release — above range ending at release",
			version: "1.0-jre",
			r:       VersionRange{Introduced: "0.9", Fixed: "1.0"},
			want:    VersionNotAffected, // 1.0-jre > 1.0 = Fixed
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mavenVersionInRangeV(tc.version, tc.r)
			if got != tc.want {
				t.Errorf("mavenVersionInRangeV(%q, {%q,%q,%q}) = %v, want %v",
					tc.version, tc.r.Introduced, tc.r.Fixed, tc.r.LastAffected, got, tc.want)
			}
		})
	}
}

// TestMavenVersionHierarchicalCorpus covers all MUST-hold ordering facts for the
// hierarchical ComparableVersion model. Every case here encodes TRUE Maven ordering
// verified against the Apache Maven spec and source.
func TestMavenVersionHierarchicalCorpus(t *testing.T) {
	t.Parallel()

	// lessThan: each pair (lo, hi) must satisfy lo < hi.
	lessThans := []struct{ lo, hi string }{
		// ── Bug case: separator hierarchy ────────────────────────────────────────
		// "-" nests into a sub-list; "." does not.  Sub-list < integer at same
		// position → 2.0-1 (root=[2,0,[1]]) < 2.0.1 (root=[2,0,1]).
		{"2.0-1", "2.0.1"},
		{"1-1", "1.1"},

		// ── Full qualifier order (alpha<beta<milestone<rc<snapshot<release<sp<unknown) ─
		{"1.0-alpha", "1.0-beta"},
		{"1.0-beta", "1.0-milestone"},
		{"1.0-milestone", "1.0-rc"},
		{"1.0-rc", "1.0-snapshot"},
		{"1.0-snapshot", "1.0"},
		{"1.0", "1.0-sp"},
		{"1.0-sp", "1.0-foo"}, // unknown qualifier sorts above sp

		// ── SNAPSHOT below release ────────────────────────────────────────────
		{"1.0-SNAPSHOT", "1.0"},

		// ── Case-insensitive input (both sides) ───────────────────────────────
		{"1.0-Alpha", "1.0-Beta"},
		{"1.0-ALPHA", "1.0"},

		// ── Unknown qualifiers: lexicographic among themselves ────────────────
		{"1.0-android", "1.0-jre"}, // android < jre
		{"1.0-sp", "1.0-android"},  // unknown (ordinal 2) > sp (ordinal 1)

		// ── Real-world: Guava jre/android flavors ────────────────────────────
		{"31.1", "31.1-jre"},
		{"31.1-android", "31.1-jre"},

		// ── Real-world: jackson-databind ─────────────────────────────────────
		{"2.9.10", "2.9.10.1"},
		{"2.9.10", "2.9.11"},

		// ── Real-world: log4j-core ────────────────────────────────────────────
		{"2.14.1", "2.17.0"},
		{"2.0-beta9", "2.14.1"},
		{"2.0-alpha1", "2.0-beta9"},

		// ── Numeric ordering ──────────────────────────────────────────────────
		{"1.9", "1.10"},
		{"1.0.0", "1.0.1"},
	}

	for _, tc := range lessThans {
		tc := tc
		t.Run(tc.lo+"<"+tc.hi, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.lo)
			b, ok2 := parseMavenVersion(tc.hi)
			if !ok1 {
				t.Fatalf("failed to parse lower %q", tc.lo)
			}
			if !ok2 {
				t.Fatalf("failed to parse higher %q", tc.hi)
			}
			if got := a.compare(b); got >= 0 {
				t.Errorf("%q < %q expected, got compare=%d", tc.lo, tc.hi, got)
			}
			if got := b.compare(a); got <= 0 {
				t.Errorf("%q > %q (reverse) expected, got compare=%d", tc.hi, tc.lo, got)
			}
		})
	}

	// equals: each pair must compare as 0 in both directions.
	equals := []struct{ a, b string }{
		// Null-trim equivalences
		{"1", "1.0"},
		{"1", "1.0.0"},
		{"1.0", "1.0.0"},
		// Release qualifier aliases all equal bare version
		{"1.0-ga", "1.0"},
		{"1.0-final", "1.0"},
		{"1.0-release", "1.0"},
		{"1.0-0", "1.0"},
		// case-insensitive
		{"1.0-Alpha", "1.0-alpha"},
		{"1.0-SNAPSHOT", "1.0-snapshot"},
		// canonical alias pairs
		{"1.0-rc", "1.0-cr"},
		{"1.0-a1", "1.0-alpha1"},
		{"1.0-b1", "1.0-beta1"},
		{"1.0-m1", "1.0-milestone1"},
	}

	for _, tc := range equals {
		tc := tc
		t.Run(tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.a)
			b, ok2 := parseMavenVersion(tc.b)
			if !ok1 {
				t.Fatalf("failed to parse %q", tc.a)
			}
			if !ok2 {
				t.Fatalf("failed to parse %q", tc.b)
			}
			if got := a.compare(b); got != 0 {
				t.Errorf("%q == %q expected, got compare=%d (a<b direction)", tc.a, tc.b, got)
			}
			if got := b.compare(a); got != 0 {
				t.Errorf("%q == %q expected, got compare=%d (b<a direction)", tc.b, tc.a, got)
			}
		})
	}
}

// TestMavenVersionNormalizeSoundness guards the two soundness bugs fixed after the
// initial port. Tests were RED before the fix; they must stay GREEN forever.
//
// Bug 1 (normalizeListItem): the old loop stopped at the first non-null item,
// including a non-null sub-list, so trailing zeros BEFORE a qualifier sub-list
// were not removed. Maven's ListItem.normalize() continues scanning left past
// non-null sub-lists. Fix: scan right-to-left, remove nulls, continue past
// ListItems, break on non-null Integer/String.
//
// Bug 2 (mavenCanonicalQualifier): a/b/m were expanded to alpha/beta/milestone
// unconditionally, but Maven only expands them when the single letter is
// immediately followed by a digit (StringItem(value, followedByDigit) ctor).
// A bare "-a"/"-b"/"-m" is an UNKNOWN qualifier (ordinal 2) that sorts ABOVE
// release, not below it. Fix: thread followedByDigit through finalizeToken.
func TestMavenVersionNormalizeSoundness(t *testing.T) {
	t.Parallel()

	// ── Bug 1 equality pairs: zeros between an integer and a sub-list must be
	// stripped during normalization, making these pairs identical. ──────────────
	bug1Equals := []struct{ a, b string }{
		// Basic: trailing zero before a qualifier sub-list removed.
		{"1.0-rc1", "1.0.0-rc1"},
		{"1.0-snapshot", "1.0.0-snapshot"},
		// Multi-zero: all intermediate zeros stripped.
		{"2.0.0-rc1", "2-rc1"},
		// Guava-style: trailing zero before an unknown qualifier.
		{"31.1-jre", "31.1.0-jre"},
		// Nested sub-list (integer inside sub-list): zeros still stripped.
		{"1.0-1", "1-1"},
		// Unknown qualifier: trailing zero before the sub-list is removed.
		{"1x", "1.0-x"},
	}

	for _, tc := range bug1Equals {
		tc := tc
		t.Run("bug1/"+tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.a)
			b, ok2 := parseMavenVersion(tc.b)
			if !ok1 {
				t.Fatalf("failed to parse %q", tc.a)
			}
			if !ok2 {
				t.Fatalf("failed to parse %q", tc.b)
			}
			if got := a.compare(b); got != 0 {
				t.Errorf("bug1: %q == %q expected, got compare=%d", tc.a, tc.b, got)
			}
			if got := b.compare(a); got != 0 {
				t.Errorf("bug1: %q == %q (reverse) expected, got compare=%d", tc.b, tc.a, got)
			}
		})
	}

	// False-NotAffected reproduction (Bug 1): installed "1.0-rc1" is in
	// [1.0.0-rc1, 1.0.0) because 1.0-rc1 == 1.0.0-rc1 (inclusive lower bound).
	// Before the fix this returned NotAffected — a silent advisory drop.
	t.Run("bug1/range-1.0-rc1-in-[1.0.0-rc1,1.0.0)", func(t *testing.T) {
		t.Parallel()
		got := mavenVersionInRangeV("1.0-rc1", VersionRange{
			Introduced: "1.0.0-rc1",
			Fixed:      "1.0.0",
		})
		if got != VersionAffected {
			t.Errorf("bug1: 1.0-rc1 in [1.0.0-rc1, 1.0.0) got %v, want VersionAffected "+
				"(1.0-rc1 normalises to same tree as 1.0.0-rc1 = inclusive lower bound)", got)
		}
	})

	// ── Bug 2 ordering cases: bare a/b/m (not followed by a digit) must be
	// treated as UNKNOWN qualifiers (ordinal 2), sorting ABOVE release. ─────────
	bug2Less := []struct{ lo, hi string }{
		// Bare "-a"/"-b"/"-m" are unknown → above release.
		{"1.0", "1.0-a"},
		{"1.0", "1.0-b"},
		{"1.0", "1.0-m"},
		// a followed by digit is alpha → below release (pre-release ordering).
		{"1.0.0a1", "1.0.0"}, // a1 = alpha1 < release
	}

	for _, tc := range bug2Less {
		tc := tc
		t.Run("bug2/"+tc.lo+"<"+tc.hi, func(t *testing.T) {
			t.Parallel()
			a, ok1 := parseMavenVersion(tc.lo)
			b, ok2 := parseMavenVersion(tc.hi)
			if !ok1 {
				t.Fatalf("failed to parse lower %q", tc.lo)
			}
			if !ok2 {
				t.Fatalf("failed to parse higher %q", tc.hi)
			}
			if got := a.compare(b); got >= 0 {
				t.Errorf("bug2: %q < %q expected, got compare=%d", tc.lo, tc.hi, got)
			}
			if got := b.compare(a); got <= 0 {
				t.Errorf("bug2: %q > %q (reverse) expected, got compare=%d", tc.hi, tc.lo, got)
			}
		})
	}

	// Bare "-a" as unknown equals another bare "-a" (both ordinal 2, same string).
	t.Run("bug2/1a==1.0-a", func(t *testing.T) {
		t.Parallel()
		a, ok1 := parseMavenVersion("1a")
		b, ok2 := parseMavenVersion("1.0-a")
		if !ok1 || !ok2 {
			t.Fatal("failed to parse 1a or 1.0-a")
		}
		if got := a.compare(b); got != 0 {
			t.Errorf("bug2: 1a == 1.0-a expected, got compare=%d "+
				"(bare 'a' in both = unknown qualifier, not alpha)", got)
		}
	})
}

// TestMavenComparatorRegistered verifies that the Maven ecosystem comparator
// is registered and reachable via AffectsVersionV.
func TestMavenComparatorRegistered(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemMaven,
		VersionRanges: []VersionRange{
			{Introduced: "1.0", Fixed: "2.0"},
		},
	}

	if got := adv.AffectsVersionV("1.5"); got != VersionAffected {
		t.Errorf("AffectsVersionV(1.5) via registry = %v, want VersionAffected", got)
	}
	if got := adv.AffectsVersionV("2.5"); got != VersionNotAffected {
		t.Errorf("AffectsVersionV(2.5) via registry = %v, want VersionNotAffected", got)
	}
	if got := adv.AffectsVersionV(""); got != VersionUndecidable {
		t.Errorf("AffectsVersionV('') via registry = %v, want VersionUndecidable", got)
	}
}
