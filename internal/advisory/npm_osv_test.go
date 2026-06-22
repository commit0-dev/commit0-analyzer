package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── npm OSV bundle query tests ───────────────────────────────────────────────
//
// These tests verify that OSVBundleSource correctly handles the npm ecosystem:
//   - Refresh(ctx, "npm") downloads + extracts the npm bundle
//   - Query for a known-vulnerable npm package@version returns the advisory
//   - Scoped packages (@scope/name) are matched by name without modification
//   - Case normalisation: npm names are lowercased to match OSV records
//   - go-vuln-db source (goVulnDBClient) returns (nil,nil) for npm ecosystem

// TestOSVBundleSource_NPM_RefreshAndQuery is the primary npm happy-path test:
//  1. httptest serves a crafted npm/all.zip with one npm advisory.
//  2. Refresh(ctx, EcosystemNPM) downloads + extracts into the cache dir.
//  3. Query returns the matching advisory with Sources=["osv.dev"] and Ecosystem="npm".
func TestOSVBundleSource_NPM_RefreshAndQuery(t *testing.T) {
	npmAdv := buildOSVRecord(t,
		"GHSA-npm-test-0001",
		"npm",
		"example-npm-pkg",
		"2.0.0",
		nil, // npm OSV records don't carry symbol data
	)
	zipBytes := buildZip(t, map[string][]byte{"GHSA-npm-test-0001.json": npmAdv})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("ETag", `"npm-etag-v1"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipBytes)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	ctx := context.Background()
	require.NoError(t, src.Refresh(ctx, EcosystemNPM))

	pkg := Package{Ecosystem: EcosystemNPM, Name: "example-npm-pkg"}
	advs, err := src.Query(ctx, pkg, "1.5.0")
	require.NoError(t, err)
	require.Len(t, advs, 1, "one advisory expected for example-npm-pkg@1.5.0")

	adv := advs[0]
	assert.Equal(t, "GHSA-npm-test-0001", adv.ID)
	assert.Equal(t, EcosystemNPM, adv.Ecosystem, "Ecosystem must be 'npm'")
	assert.Equal(t, []string{SourceOSV}, adv.Sources, "Sources must be [osv.dev]")
	assert.Equal(t, "example-npm-pkg", adv.Module)
}

// TestOSVBundleSource_NPM_FixedVersionNotMatched confirms the fixed version
// does not match the advisory range.
func TestOSVBundleSource_NPM_FixedVersionNotMatched(t *testing.T) {
	npmAdv := buildOSVRecord(t, "GHSA-npm-test-0001", "npm", "example-npm-pkg", "2.0.0", nil)
	zipBytes := buildZip(t, map[string][]byte{"GHSA-npm-test-0001.json": npmAdv})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))
	require.NoError(t, src.Refresh(context.Background(), EcosystemNPM))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemNPM, Name: "example-npm-pkg"}, "2.0.0")
	require.NoError(t, err)
	assert.Empty(t, advs, "fixed version 2.0.0 must not match the advisory range [0, 2.0.0)")
}

// TestOSVBundleSource_NPM_ScopedPackage verifies that scoped npm packages
// (@scope/name) are matched exactly by name, preserving the full scoped form.
func TestOSVBundleSource_NPM_ScopedPackage(t *testing.T) {
	scopedAdv := buildOSVRecord(t,
		"GHSA-npm-scoped-0001",
		"npm",
		"@scope/example-pkg",
		"3.0.0",
		nil,
	)
	zipBytes := buildZip(t, map[string][]byte{"GHSA-npm-scoped-0001.json": scopedAdv})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))
	require.NoError(t, src.Refresh(context.Background(), EcosystemNPM))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemNPM, Name: "@scope/example-pkg"}, "1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1, "scoped package @scope/example-pkg must be matched exactly")
	assert.Equal(t, "@scope/example-pkg", advs[0].Module)
}

// TestGoVulnDBClient_NPM_NoOp confirms that the goVulnDBClient (go-vuln-db source)
// returns (nil, nil) for npm packages — it covers only Go and must not error.
func TestGoVulnDBClient_NPM_NoOp(t *testing.T) {
	goAdv := buildOSVRecord(t, "GO-2024-9999", "Go", "github.com/example/gopkg", "1.0.0", nil)
	dbDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "GO-2024-9999.json"), goAdv, 0o644))

	client := &goVulnDBClient{dbDir: dbDir}
	ctx := context.Background()

	advs, err := client.Query(ctx, Package{Ecosystem: EcosystemNPM, Name: "some-npm-pkg"}, "1.0.0")
	require.NoError(t, err, "goVulnDBClient must not error on npm ecosystem query")
	assert.Nil(t, advs, "goVulnDBClient must return nil advisories for npm")
}

// TestNormalizeNPMPackageName verifies the npm package name normalisation rules:
// scoped packages (@scope/name) are preserved lowercased; unscoped names are lowercased.
func TestNormalizeNPMPackageName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"lodash", "lodash"},
		{"Lodash", "lodash"},
		{"LODASH", "lodash"},
		{"@scope/example", "@scope/example"},
		{"@Scope/Example", "@scope/example"},
		{"@SCOPE/EXAMPLE-PKG", "@scope/example-pkg"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeNPMPackageName(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
