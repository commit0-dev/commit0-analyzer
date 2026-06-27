package advisory

import (
	"testing"
)

// TestParseNugetVersion verifies the parser accepts valid NuGet version strings
// and rejects malformed/floating inputs.
func TestParseNugetVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input  string
		wantOK bool
	}{
		// --- Valid 3-part (canonical SemVer) ---
		{"1.0.0", true},
		{"1.2.3", true},
		{"0.0.1", true},
		{"10.20.30", true},

		// --- Valid 4-part (NuGet revision) ---
		{"1.0.0.0", true},
		{"1.2.3.4", true},
		{"1.0.0.1", true},

		// --- Valid 1-part and 2-part (partial core) ---
		{"1", true},
		{"1.0", true},

		// --- Leading v prefix stripped ---
		{"v1.0.0", true},
		{"V2.3.4", true},

		// --- Pre-release labels ---
		{"1.0.0-alpha", true},
		{"1.0.0-alpha.1", true},
		{"1.0.0-beta.2", true},
		{"1.0.0-rc.1", true},
		{"1.0.0-0.3.7", true},
		{"1.0.0-x.7.z.92", true},
		{"2.0.0-preview.3", true},

		// --- Build metadata stripped (valid) ---
		{"1.0.0+build.1", true},
		{"1.0.0-alpha+001", true},

		// --- 4-part with pre-release ---
		{"1.2.3.4-beta.1", true},

		// --- Floating versions → rejected (undecidable) ---
		{"1.*", false},
		{"1.2.*", false},
		{"*", false},
		{"1.0.*-alpha", false},

		// --- Invalid: empty ---
		{"", false},

		// --- Invalid: trailing hyphen ---
		{"1.0.0-", false},

		// --- Invalid: too many parts ---
		{"1.2.3.4.5", false},

		// --- Invalid: non-numeric core component ---
		{"1.a.0", false},
		{"1.0.x", false},

		// --- Invalid: negative component (represented as non-numeric) ---
		{"1.-1.0", false},

		// --- Invalid: empty core component ---
		{"1..0", false},
		{".1.0", false},

		// --- Invalid: empty pre-release identifier ---
		{"1.0.0-alpha..1", false},

		// --- Invalid: leading zeros in numeric pre-release identifier ---
		{"1.0.0-01", false},
		{"1.0.0-00", false},

		// --- Valid: "0" alone as numeric pre-release identifier is allowed ---
		{"1.0.0-0", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			_, got := parseNugetVersion(tc.input)
			if got != tc.wantOK {
				t.Errorf("parseNugetVersion(%q) ok=%v, want %v", tc.input, got, tc.wantOK)
			}
		})
	}
}

// TestNugetVersionOrdering verifies the NuGet version comparison produces the
// correct total order for the pairs documented in the research report and the
// NuGet / SemVer 2.0 specifications.
func TestNugetVersionOrdering(t *testing.T) {
	t.Parallel()

	// Each entry: lower must compare strictly less than higher.
	lessThans := []struct{ lower, higher string }{
		// --- Core numeric ordering ---
		{"1.0.0", "2.0.0"},
		{"1.0.0", "1.1.0"},
		{"1.0.0", "1.0.1"},
		{"1.9.0", "1.10.0"},   // numeric, not lexicographic
		{"1.0.9", "1.0.10"},   // numeric, not lexicographic
		{"0.0.1", "0.0.2"},
		{"0.9.9", "1.0.0"},

		// --- 4-part revision ordering ---
		{"1.0.0.0", "1.0.0.1"},
		{"1.2.3.0", "1.2.3.1"},
		{"1.2.3.4", "1.2.3.5"},
		{"1.0.0", "1.0.0.1"}, // no revision < revision 1

		// --- Pre-release < release (SemVer §11.3) ---
		{"1.0.0-alpha", "1.0.0"},
		{"1.0.0-beta", "1.0.0"},
		{"1.0.0-rc.1", "1.0.0"},
		{"1.0.0-0.3.7", "1.0.0"},
		{"2.0.0-preview.1", "2.0.0"},

		// --- Pre-release ordering (SemVer §11.4) ---
		{"1.0.0-alpha", "1.0.0-alpha.1"},     // longer set wins when prefix matches
		{"1.0.0-alpha.1", "1.0.0-alpha.2"},   // numeric comparison
		{"1.0.0-alpha", "1.0.0-beta"},         // lexicographic string comparison
		{"1.0.0-beta", "1.0.0-rc"},            // lexicographic: beta < rc
		{"1.0.0-rc", "1.0.0-rc.1"},            // longer wins when prefix equal
		{"1.0.0-1", "1.0.0-alpha"},            // numeric < alphanumeric (SemVer §11.4.3)
		{"1.0.0-1", "1.0.0-2"},               // numeric comparison within pre
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"}, // numeric < alphanumeric in second ident

		// --- Real NuGet advisory ranges ---
		// Newtonsoft.Json — commonly versioned
		{"12.0.3", "13.0.1"},
		// Microsoft.AspNetCore packages
		{"6.0.0", "6.0.1"},
		{"6.0.0-rc.1", "6.0.0"},
		// System.Text.Json
		{"7.0.0-preview.1", "7.0.0"},
		{"7.0.0-preview.1", "7.0.0-preview.2"},
	}

	for _, tc := range lessThans {
		tc := tc
		t.Run(tc.lower+"<"+tc.higher, func(t *testing.T) {
			t.Parallel()
			a, okA := parseNugetVersion(tc.lower)
			b, okB := parseNugetVersion(tc.higher)
			if !okA {
				t.Fatalf("failed to parse lower %q", tc.lower)
			}
			if !okB {
				t.Fatalf("failed to parse higher %q", tc.higher)
			}
			if got := a.compare(b); got >= 0 {
				t.Errorf("expected %q < %q, got compare=%d", tc.lower, tc.higher, got)
			}
			// Verify symmetry.
			if got := b.compare(a); got <= 0 {
				t.Errorf("expected %q > %q (reverse), got compare=%d", tc.higher, tc.lower, got)
			}
		})
	}

	// Equality cases: semantically equivalent versions must compare as equal.
	equals := []struct{ a, b string }{
		// 4-part revision 0 == 3-part
		{"1.0.0", "1.0.0.0"},
		{"1.2.3", "1.2.3.0"},
		// Partial core pads with zeros
		{"1.0", "1.0.0"},
		{"1", "1.0.0"},
		{"1.0", "1.0.0.0"},
		// Build metadata is ignored
		{"1.0.0", "1.0.0+build.1"},
		{"1.0.0-alpha", "1.0.0-alpha+001"},
		// Leading v prefix stripped
		{"v1.0.0", "1.0.0"},
		{"V1.2.3", "1.2.3"},
		// Case-insensitive pre-release (NuGet convention)
		{"1.0.0-Alpha", "1.0.0-alpha"},
		{"1.0.0-BETA", "1.0.0-beta"},
		{"1.0.0-RC.1", "1.0.0-rc.1"},
	}

	for _, tc := range equals {
		tc := tc
		t.Run(tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			a, okA := parseNugetVersion(tc.a)
			b, okB := parseNugetVersion(tc.b)
			if !okA {
				t.Fatalf("failed to parse %q", tc.a)
			}
			if !okB {
				t.Fatalf("failed to parse %q", tc.b)
			}
			if got := a.compare(b); got != 0 {
				t.Errorf("expected %q == %q, got compare=%d", tc.a, tc.b, got)
			}
		})
	}
}

// TestNugetVersionInRangeV tests the tri-state comparator for a variety of
// OSV-style ranges derived from real NuGet advisories.
func TestNugetVersionInRangeV(t *testing.T) {
	t.Parallel()

	type tc struct {
		name    string
		version string
		r       VersionRange
		want    VersionVerdict
	}

	cases := []tc{
		// --- Basic fixed-upper-bound range ---
		{
			name:    "affected: inside [1.0.0, 2.0.0)",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},
		{
			name:    "not affected: at fixed bound (exclusive)",
			version: "2.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "not affected: above fixed bound",
			version: "2.1.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "not affected: below introduced",
			version: "0.9.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionNotAffected,
		},
		{
			name:    "affected: at introduced (inclusive)",
			version: "1.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},

		// --- Open-ended (unfixed) range ---
		{
			name:    "affected: unfixed range, any version above introduced",
			version: "99.0.0",
			r:       VersionRange{Introduced: "1.0.0"},
			want:    VersionAffected,
		},
		{
			name:    "affected: unfixed range, at introduced",
			version: "1.0.0",
			r:       VersionRange{Introduced: "1.0.0"},
			want:    VersionAffected,
		},

		// --- LastAffected (inclusive upper bound) ---
		{
			name:    "affected: at last affected (inclusive)",
			version: "1.9.0",
			r:       VersionRange{Introduced: "1.0.0", LastAffected: "1.9.0"},
			want:    VersionAffected,
		},
		{
			name:    "not affected: above last affected",
			version: "2.0.0",
			r:       VersionRange{Introduced: "1.0.0", LastAffected: "1.9.0"},
			want:    VersionNotAffected,
		},

		// --- Pre-release ordering in ranges ---
		{
			name:    "pre-release is inside range when below release fixed bound",
			version: "1.5.0-beta.1",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},
		{
			name:    "pre-release at patch boundary — rc is below release",
			version: "2.0.0-rc.1",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected, // 2.0.0-rc.1 < 2.0.0 = Fixed
		},
		{
			name:    "alpha below introduced (pre-release < release introduced)",
			version: "1.0.0-alpha",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionNotAffected, // 1.0.0-alpha < 1.0.0 = Introduced
		},

		// --- 4-part revision semantics ---
		{
			name:    "4-part version: revision 0 equals 3-part — inside range",
			version: "1.5.0.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},
		{
			name:    "4-part version: revision non-zero — inside range",
			version: "1.5.0.1",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},
		{
			name:    "4-part fixed bound: pinned revision inside range",
			version: "1.0.0.1",
			r:       VersionRange{Introduced: "1.0.0.0", Fixed: "1.0.0.5"},
			want:    VersionAffected,
		},
		{
			name:    "4-part fixed bound: at exclusive upper — not affected",
			version: "1.0.0.5",
			r:       VersionRange{Introduced: "1.0.0.0", Fixed: "1.0.0.5"},
			want:    VersionNotAffected,
		},

		// --- Build metadata ignored ---
		{
			name:    "build metadata stripped — still affected",
			version: "1.5.0+build.123",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionAffected,
		},

		// --- Floating versions → undecidable ---
		{
			name:    "floating query version → undecidable",
			version: "1.*",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "floating in Introduced bound → undecidable",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.*", Fixed: "2.0.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "floating in Fixed bound → undecidable",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.*"},
			want:    VersionUndecidable,
		},

		// --- Parse errors → undecidable (never not-affected) ---
		{
			name:    "empty version → undecidable",
			version: "",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "non-version string → undecidable",
			version: "notaversion",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "unparseable introduced → undecidable",
			version: "1.5.0",
			r:       VersionRange{Introduced: "bad", Fixed: "2.0.0"},
			want:    VersionUndecidable,
		},
		{
			name:    "unparseable fixed → undecidable",
			version: "1.5.0",
			r:       VersionRange{Introduced: "1.0.0", Fixed: "bad"},
			want:    VersionUndecidable,
		},

		// --- Empty range (no bounds) → affected by convention ---
		{
			name:    "empty range → affected (open from beginning, no fixed)",
			version: "1.5.0",
			r:       VersionRange{},
			want:    VersionAffected,
		},

		// --- Real NuGet advisory patterns (derived from GHSA records) ---
		// CVE-2025-30399 — .NET 8 & 9 RCE; fixed in 8.0.15 / 9.0.4
		{
			name:    "dotnet rce: inside [8.0.0, 8.0.15)",
			version: "8.0.14",
			r:       VersionRange{Introduced: "8.0.0", Fixed: "8.0.15"},
			want:    VersionAffected,
		},
		{
			name:    "dotnet rce: at fixed 8.0.15 — not affected",
			version: "8.0.15",
			r:       VersionRange{Introduced: "8.0.0", Fixed: "8.0.15"},
			want:    VersionNotAffected,
		},
		{
			name:    "dotnet rce: 9.0.3 inside [9.0.0, 9.0.4)",
			version: "9.0.3",
			r:       VersionRange{Introduced: "9.0.0", Fixed: "9.0.4"},
			want:    VersionAffected,
		},
		{
			name:    "dotnet rce: 9.0.4 at fixed — not affected",
			version: "9.0.4",
			r:       VersionRange{Introduced: "9.0.0", Fixed: "9.0.4"},
			want:    VersionNotAffected,
		},
		// Newtonsoft.Json — historical example (many vulnerabilities fixed in 13.0.1)
		{
			name:    "newtonsoft: 12.0.3 inside [0, 13.0.1)",
			version: "12.0.3",
			r:       VersionRange{Fixed: "13.0.1"},
			want:    VersionAffected,
		},
		{
			name:    "newtonsoft: 13.0.1 at fixed — not affected",
			version: "13.0.1",
			r:       VersionRange{Fixed: "13.0.1"},
			want:    VersionNotAffected,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := nugetVersionInRangeV(tc.version, tc.r)
			if got != tc.want {
				t.Errorf("nugetVersionInRangeV(%q, {Introduced:%q Fixed:%q LastAffected:%q}) = %v, want %v",
					tc.version, tc.r.Introduced, tc.r.Fixed, tc.r.LastAffected, got, tc.want)
			}
		})
	}
}

// TestNugetComparatorRegistered verifies that the NuGet ecosystem comparator
// is registered and reachable via the AffectsVersionV dispatch path.
func TestNugetComparatorRegistered(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem: EcosystemNuGet,
		VersionRanges: []VersionRange{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		},
	}

	if got := adv.AffectsVersionV("1.5.0"); got != VersionAffected {
		t.Errorf("AffectsVersionV(1.5.0) via registry = %v, want VersionAffected", got)
	}
	if got := adv.AffectsVersionV("2.5.0"); got != VersionNotAffected {
		t.Errorf("AffectsVersionV(2.5.0) via registry = %v, want VersionNotAffected", got)
	}
	if got := adv.AffectsVersionV(""); got != VersionUndecidable {
		t.Errorf("AffectsVersionV('') via registry = %v, want VersionUndecidable", got)
	}
	if got := adv.AffectsVersionV("1.*"); got != VersionUndecidable {
		t.Errorf("AffectsVersionV('1.*') via registry = %v, want VersionUndecidable", got)
	}
}

// TestNugetFloatingDetection verifies isNugetFloating correctly identifies
// wildcard versions.
func TestNugetFloatingDetection(t *testing.T) {
	t.Parallel()

	floatingCases := []string{"1.*", "1.2.*", "*", "1.0.*-alpha"}
	for _, v := range floatingCases {
		v := v
		t.Run("floating:"+v, func(t *testing.T) {
			t.Parallel()
			if !isNugetFloating(v) {
				t.Errorf("isNugetFloating(%q) = false, want true", v)
			}
		})
	}

	pinnedCases := []string{"1.0.0", "1.2.3", "1.0.0-alpha", "1.0.0+build"}
	for _, v := range pinnedCases {
		v := v
		t.Run("pinned:"+v, func(t *testing.T) {
			t.Parallel()
			if isNugetFloating(v) {
				t.Errorf("isNugetFloating(%q) = true, want false", v)
			}
		})
	}
}
