package advisory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEcosystemConstants_Values verifies that each ecosystem constant carries
// exactly the string value that osv.dev uses as the "ecosystem" key in its OSV
// JSON records and as the path component in the bundle URL:
//
//	https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip
//
// These values are cross-checked against the OSV schema reference at
// https://ossf.github.io/osv-schema/#affectedpackageecosystem-field and the
// research report in plans/reports/*-additional-language-ecosystems-*.
// A wrong constant would construct a bad URL at Refresh time and return 404.
func TestEcosystemConstants_Values(t *testing.T) {
	cases := []struct {
		name  string
		got   string
		want  string
	}{
		// Existing ecosystems — regression guard: renaming them is a breaking change.
		{"EcosystemGo", EcosystemGo, "Go"},
		{"EcosystemNPM", EcosystemNPM, "npm"},
		{"EcosystemCratesIO", EcosystemCratesIO, "crates.io"},
		{"EcosystemPyPI", EcosystemPyPI, "PyPI"},
		{"EcosystemMaven", EcosystemMaven, "Maven"},
		// New ecosystems (Wave 1 and Wave 2).
		{"EcosystemNuGet", EcosystemNuGet, "NuGet"},
		{"EcosystemPackagist", EcosystemPackagist, "Packagist"},
		{"EcosystemRubyGems", EcosystemRubyGems, "RubyGems"},
		{"EcosystemHex", EcosystemHex, "Hex"},
		{"EcosystemPub", EcosystemPub, "Pub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got,
				"ecosystem constant %s must match the osv.dev ecosystem key exactly", tc.name)
		})
	}
}

// TestOSVBundleEcosystems_ContainsAllRegistered verifies that OSVBundleEcosystems
// lists every ecosystem constant — existing and newly added — so callers that
// iterate the list to fetch bundles will not silently miss a language.
func TestOSVBundleEcosystems_ContainsAllRegistered(t *testing.T) {
	want := []string{
		EcosystemGo,
		EcosystemNPM,
		EcosystemCratesIO,
		EcosystemPyPI,
		EcosystemMaven,
		EcosystemNuGet,
		EcosystemPackagist,
		EcosystemRubyGems,
		EcosystemHex,
		EcosystemPub,
	}

	got := make(map[string]bool, len(OSVBundleEcosystems))
	for _, eco := range OSVBundleEcosystems {
		got[eco] = true
	}

	for _, eco := range want {
		assert.True(t, got[eco], "OSVBundleEcosystems must include %q", eco)
	}

	// No duplicates.
	assert.Equal(t, len(OSVBundleEcosystems), len(got),
		"OSVBundleEcosystems must not contain duplicate entries")
}

// TestOSVBundleSource_QueryUnrefreshedNewEcosystems verifies that Query returns
// (nil, nil) — not an error — for new ecosystems whose bundle has not yet been
// fetched via Refresh. This upholds the Source interface contract: "no advisory
// found" is distinct from "query failed". The caller must treat a non-nil error
// as unknown, not safe; (nil, nil) means "no data yet, refresh first".
func TestOSVBundleSource_QueryUnrefreshedNewEcosystems(t *testing.T) {
	src := NewOSVBundleSource(t.TempDir())
	ctx := context.Background()

	for _, eco := range []string{
		EcosystemNuGet,
		EcosystemPackagist,
		EcosystemRubyGems,
		EcosystemHex,
		EcosystemPub,
	} {
		eco := eco
		t.Run(eco, func(t *testing.T) {
			advs, err := src.Query(ctx, Package{Ecosystem: eco, Name: "somepkg"}, "1.0.0")
			require.NoError(t, err, "Query must not error for unrefreshed ecosystem %s", eco)
			assert.Nil(t, advs, "Query must return nil advisories for unrefreshed ecosystem %s", eco)
		})
	}
}

// TestOSVBundleEcosystems_ConstantsAreURLSafe verifies that none of the
// ecosystem names contain characters that would produce an invalid bundle URL.
// OSV ecosystem names are used verbatim as URL path segments; a slash, space,
// or control character would silently corrupt the download URL.
func TestOSVBundleEcosystems_ConstantsAreURLSafe(t *testing.T) {
	for _, eco := range OSVBundleEcosystems {
		eco := eco
		t.Run(eco, func(t *testing.T) {
			assert.NotEmpty(t, eco, "ecosystem must not be empty")
			for _, ch := range eco {
				assert.False(t, ch == '/' || ch == ' ' || ch < 0x20,
					"ecosystem %q contains URL-unsafe character %q", eco, ch)
			}
		})
	}
}
