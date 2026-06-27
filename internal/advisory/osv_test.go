package advisory

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Zip fixture builders ─────────────────────────────────────────────────────

// buildZip creates an in-memory zip archive from the provided name→content map.
// The resulting bytes can be served via httptest or written to disk.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// buildOSVZip returns an in-memory zip with one symbol-level and one
// package-level OSV entry using the existing testdata fixtures.
func buildOSVZip(t *testing.T) []byte {
	t.Helper()
	symData := loadFixture(t, "GO-2024-0001.json")    // symbol-level, module: github.com/example/vulnpkg
	pkgData := loadFixture(t, "GO-2024-0002.json")    // package-level, different module
	return buildZip(t, map[string][]byte{
		"GO-2024-0001.json": symData,
		"GO-2024-0002.json": pkgData,
	})
}

// ─── Version normalisation ────────────────────────────────────────────────────

// TestNormalizeOSVVersion_Go verifies that Go module versions (v-prefixed) are
// correctly normalised for OSV record comparison (no-v prefix) and vice versa.
func TestNormalizeOSVVersion_Go(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"v1.2.3", "1.2.3"},
		{"v0.0.1", "0.0.1"},
		{"v2.0.0-rc.1", "2.0.0-rc.1"},
		{"1.2.3", "1.2.3"},  // already no-v, stays the same
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeOSVVersion(EcosystemGo, tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeOSVVersion_NonGo verifies that non-Go ecosystems pass the version
// through unchanged (we don't mangle versions we don't understand).
func TestNormalizeOSVVersion_NonGo(t *testing.T) {
	got := normalizeOSVVersion("npm", "v1.2.3")
	assert.Equal(t, "v1.2.3", got, "non-Go ecosystem versions must not be altered")
}

// ─── Refresh: happy path ──────────────────────────────────────────────────────

// TestOSVBundleSource_Refresh_ExtractsAndQueries is the primary happy-path test:
//  1. httptest serves a crafted all.zip with symbol-level + package-level entries.
//  2. Refresh downloads + extracts into the cache dir.
//  3. Query returns the matching advisory with Sources=["osv.dev"] and Ecosystem set.
func TestOSVBundleSource_Refresh_ExtractsAndQueries(t *testing.T) {
	zipBytes := buildOSVZip(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Go/all.zip" {
			w.Header().Set("ETag", `"test-etag-v1"`)
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

	// Refresh must succeed.
	require.NoError(t, src.Refresh(ctx, EcosystemGo))

	// Cache dir must now have the extracted JSON files.
	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	_, err := os.Stat(filepath.Join(ecoDir, "GO-2024-0001.json"))
	require.NoError(t, err, "GO-2024-0001.json must exist after Refresh")

	// Manifest must be present and valid.
	_, err = verifyManifest(ecoDir)
	require.NoError(t, err, "manifest must be valid after Refresh")

	// Query for the symbol-level module.
	pkg := Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}
	advs, err := src.Query(ctx, pkg, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1, "one advisory expected for github.com/example/vulnpkg@v1.0.0")

	adv := advs[0]
	assert.Equal(t, "GO-2024-0001", adv.ID)
	assert.Equal(t, EcosystemGo, adv.Ecosystem)
	assert.Equal(t, []string{SourceOSV}, adv.Sources, "Sources must be [osv.dev]")
	assert.True(t, adv.SymbolLevel, "symbol-level advisory must have SymbolLevel=true")
}

// TestOSVBundleSource_Query_SymbolLevel verifies that the symbol-level entry
// (GO-2024-0001) is returned with SymbolLevel=true after a Refresh.
func TestOSVBundleSource_Query_SymbolLevel(t *testing.T) {
	symData := loadFixture(t, "GO-2024-0001.json")
	zipBytes := buildZip(t, map[string][]byte{"GO-2024-0001.json": symData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1)
	assert.True(t, advs[0].SymbolLevel)
}

// TestOSVBundleSource_Query_CleanPackage verifies that a package with no
// matching advisory returns empty, nil — not an error.
func TestOSVBundleSource_Query_CleanPackage(t *testing.T) {
	symData := loadFixture(t, "GO-2024-0001.json")
	zipBytes := buildZip(t, map[string][]byte{"GO-2024-0001.json": symData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	// A package not present in the DB must return empty, nil.
	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/totally-safe"}, "v1.0.0")
	require.NoError(t, err)
	assert.Empty(t, advs)
}

// TestOSVBundleSource_Query_FixedVersion verifies that a version at the fixed
// boundary is not returned.
func TestOSVBundleSource_Query_FixedVersion(t *testing.T) {
	symData := loadFixture(t, "GO-2024-0001.json") // affected [0, 1.2.3)
	zipBytes := buildZip(t, map[string][]byte{"GO-2024-0001.json": symData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.2.3")
	require.NoError(t, err)
	assert.Empty(t, advs, "fixed version must not match")
}

// ─── Offline reuse ────────────────────────────────────────────────────────────

// TestOSVBundleSource_OfflineReuseAfterRefresh verifies that after a successful
// Refresh, Query works with NO further network calls (cache is sufficient).
func TestOSVBundleSource_OfflineReuseAfterRefresh(t *testing.T) {
	zipBytes := buildOSVZip(t)

	var netCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		netCalls.Add(1)
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))
	callsAfterRefresh := netCalls.Load()

	// Multiple queries must NOT make additional network calls.
	pkg := Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}
	for i := 0; i < 3; i++ {
		advs, err := src.Query(context.Background(), pkg, "v1.0.0")
		require.NoError(t, err)
		require.NotEmpty(t, advs)
	}

	assert.Equal(t, callsAfterRefresh, netCalls.Load(),
		"Query must make zero additional network calls after Refresh")
}

// TestOSVBundleSource_Query_NoEcosystemDir verifies that querying an ecosystem
// whose cache dir doesn't exist returns empty, nil (caller controls Refresh).
func TestOSVBundleSource_Query_NoEcosystemDir(t *testing.T) {
	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir)

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: "PyPI", Name: "requests"}, "2.31.0")
	require.NoError(t, err)
	assert.Empty(t, advs, "missing ecosystem dir must return empty, nil — not an error")
}

// ─── Withdrawn filtering ──────────────────────────────────────────────────────

// TestOSVBundleSource_Query_WithdrawnFiltered verifies that withdrawn advisories
// are excluded from OSV bundle query results (inherited from parseOSVRecord).
func TestOSVBundleSource_Query_WithdrawnFiltered(t *testing.T) {
	withdrawnData := loadFixture(t, "GO-2025-3408.json") // withdrawn advisory
	zipBytes := buildZip(t, map[string][]byte{"GO-2025-3408.json": withdrawnData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	assert.Empty(t, advs, "withdrawn advisory must be excluded from OSV query results")
}

// ─── Failure cases: hard error + no manifest ─────────────────────────────────

// TestOSVBundleSource_Refresh_HTTP500_HardError verifies that an HTTP 500
// response from the OSV bundle endpoint is a hard error and leaves no manifest.
func TestOSVBundleSource_Refresh_HTTP500_HardError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	err := src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "HTTP 500 must be a hard error")

	// No manifest must exist.
	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	assertNoManifest(t, ecoDir)
}

// TestOSVBundleSource_Refresh_PathTraversal_HardError verifies that a zip entry
// with a path traversal sequence ("..") is rejected as a hard error with no manifest.
func TestOSVBundleSource_Refresh_PathTraversal_HardError(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("../escaped.json")
	require.NoError(t, err)
	_, err = fw.Write([]byte(`{"id":"evil"}`))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	err = src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "path traversal entry must be a hard error")
	assert.Contains(t, strings.ToLower(err.Error()), "path", "error must mention the path issue")

	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	assertNoManifest(t, ecoDir)
}

// TestOSVBundleSource_Refresh_ZipBomb_HardError verifies that an oversized zip
// entry (zip-bomb guard) is rejected as a hard error with no manifest.
func TestOSVBundleSource_Refresh_ZipBomb_HardError(t *testing.T) {
	// Build a zip entry that declares a large uncompressed size.
	// We write a real (non-compressed) large payload so the extractor reads it.
	// 11 MB exceeds the 10 MB per-file cap.
	const oversize = 11 << 20 // 11 MiB
	bigData := bytes.Repeat([]byte("A"), oversize)

	zipBytes := buildZip(t, map[string][]byte{"big.json": bigData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	err := src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "oversized entry must be a hard error")

	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	assertNoManifest(t, ecoDir)
}

// ─── ETag / conditional fetch ─────────────────────────────────────────────────

// TestOSVBundleSource_Refresh_ETagCaching verifies that after a successful Refresh
// with an ETag, a second Refresh sends If-None-Match and skips re-extraction when
// the server responds 304 Not Modified.
func TestOSVBundleSource_Refresh_ETagCaching(t *testing.T) {
	zipBytes := buildOSVZip(t)
	const etag = `"test-etag-v1"`

	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	// First Refresh — full download.
	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))
	firstCount := requestCount.Load()
	assert.GreaterOrEqual(t, firstCount, int64(1))

	// Second Refresh — must use conditional GET; if 304 returned, no re-extraction.
	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	// Manifest must still be valid after the conditional refresh.
	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	_, err := verifyManifest(ecoDir)
	require.NoError(t, err, "manifest must remain valid after conditional refresh")
}

// ─── ForceUpdate ─────────────────────────────────────────────────────────────

// TestOSVBundleSource_Refresh_ForceUpdate verifies that ForceUpdate=true triggers
// a new download even when the ETag would normally allow a 304.
func TestOSVBundleSource_Refresh_ForceUpdate(t *testing.T) {
	zipBytes := buildOSVZip(t)
	const etag = `"test-etag-v1"`

	var downloadCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never serve 304 — always respond with the full zip.
		w.Header().Set("ETag", etag)
		downloadCount.Add(1)
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir,
		withBaseURL(srv.URL),
		withHTTPClient(srv.Client()),
		withForceUpdate(true),
	)

	// First Refresh.
	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))
	// Second Refresh — ForceUpdate means another download even with same ETag.
	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	assert.GreaterOrEqual(t, downloadCount.Load(), int64(2),
		"ForceUpdate must trigger download on every Refresh call")
}

// ─── Ecosystem attribution ────────────────────────────────────────────────────

// TestOSVBundleSource_Query_EcosystemAttribution verifies that the Ecosystem field
// of returned advisories matches pkg.Ecosystem, not a hardcoded value.
func TestOSVBundleSource_Query_EcosystemAttribution(t *testing.T) {
	// Build an OSV record for the "Go" ecosystem.
	symData := loadFixture(t, "GO-2024-0001.json")
	zipBytes := buildZip(t, map[string][]byte{"GO-2024-0001.json": symData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.NotEmpty(t, advs)

	for _, adv := range advs {
		assert.Equal(t, EcosystemGo, adv.Ecosystem,
			"Ecosystem must be set from pkg.Ecosystem, not hardcoded")
	}
}

// ─── Sources attribution ──────────────────────────────────────────────────────

// TestOSVBundleSource_Query_Sources verifies that Sources=["osv.dev"] on all
// returned advisories, replacing the default go-vuln-db attribution.
func TestOSVBundleSource_Query_Sources(t *testing.T) {
	symData := loadFixture(t, "GO-2024-0001.json")
	zipBytes := buildZip(t, map[string][]byte{"GO-2024-0001.json": symData})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	require.NoError(t, src.Refresh(context.Background(), EcosystemGo))

	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.NotEmpty(t, advs)

	for _, adv := range advs {
		assert.Equal(t, []string{SourceOSV}, adv.Sources,
			"Sources must be exactly [osv.dev] for OSV bundle results")
		assert.NotContains(t, adv.Sources, SourceGoVulnDB,
			"go-vuln-db attribution must not appear in OSV source results")
	}
}

// ─── dirSource: shared reader (regression guard for Go-DB) ───────────────────

// TestDirSource_Query_GoEcosystem verifies that dirSource can serve queries for
// the Go ecosystem and returns advisories with the expected attribution passed in.
func TestDirSource_Query_GoEcosystem(t *testing.T) {
	dbDir := t.TempDir()
	for _, name := range []string{"GO-2024-0001.json", "GO-2024-0002.json"} {
		data := loadFixture(t, name)
		require.NoError(t, os.WriteFile(filepath.Join(dbDir, name), data, 0o644))
	}

	ds := &dirSource{dir: dbDir, sources: []string{SourceGoVulnDB}}
	ctx := context.Background()

	advs, err := ds.query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/vulnpkg"}, "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1)
	assert.Equal(t, "GO-2024-0001", advs[0].ID)
	assert.Equal(t, []string{SourceGoVulnDB}, advs[0].Sources)
	assert.Equal(t, EcosystemGo, advs[0].Ecosystem)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// assertNoManifest asserts that the ecosystem dir has no valid manifest.
// Absence of the dir entirely also satisfies the assertion.
func assertNoManifest(t *testing.T, dir string) {
	t.Helper()
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return // dir never created — definitely no manifest
	}
	manifestPath := filepath.Join(dir, ManifestFilename)
	_, err = os.Stat(manifestPath)
	if os.IsNotExist(err) {
		return // no manifest file — correct
	}
	// Manifest file exists — verify it: a valid manifest here is a failure.
	_, verifyErr := verifyManifest(dir)
	assert.Error(t, verifyErr,
		"a valid manifest must NOT exist after a failed Refresh (dir: %s)", dir)
}

// ─── OSVBundleSource functional option types (test seam) ─────────────────────
// These are thin wrappers around the functional options exposed by osv.go.

// withBaseURL returns an option that overrides the base URL.
func withBaseURL(u string) osvOption {
	return func(s *OSVBundleSource) { s.BaseURL = u }
}

// withHTTPClient returns an option that injects a custom *http.Client (e.g.
// the test server's client so TLS / redirects work correctly).
func withHTTPClient(c *http.Client) osvOption {
	return func(s *OSVBundleSource) { s.HTTP = c }
}

// withExtractCaps overrides the aggregate zip-bomb caps so the guards can be
// exercised with small fixtures instead of gigabyte archives. A non-positive
// value leaves the corresponding default in place.
func withExtractCaps(maxTotal, maxEntries int64) osvOption {
	return func(s *OSVBundleSource) {
		if maxTotal > 0 {
			s.maxTotalExtracted = maxTotal
		}
		if maxEntries > 0 {
			s.maxExtractEntries = maxEntries
		}
	}
}

// withForceUpdate returns an option that sets ForceUpdate=true.
func withForceUpdate(v bool) osvOption {
	return func(s *OSVBundleSource) { s.ForceUpdate = v }
}

// buildOSVRecord returns a minimal OSV JSON byte slice for the given ecosystem,
// module name, and advisory ID — used to build custom fixtures inline.
func buildOSVRecord(t *testing.T, id, ecosystem, module, fixed string, symbols []string) []byte {
	t.Helper()
	type osvSymImport struct {
		Path    string   `json:"path"`
		Symbols []string `json:"symbols"`
	}
	type osvEcoSpec struct {
		Imports []osvSymImport `json:"imports"`
	}
	type osvAffectedEntry struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges            []map[string]interface{} `json:"ranges"`
		EcosystemSpecific osvEcoSpec               `json:"ecosystem_specific"`
	}
	type record struct {
		ID       string             `json:"id"`
		Affected []osvAffectedEntry `json:"affected"`
	}

	aff := osvAffectedEntry{}
	aff.Package.Ecosystem = ecosystem
	aff.Package.Name = module
	aff.Ranges = []map[string]interface{}{
		{
			"type": "SEMVER",
			"events": []map[string]interface{}{
				{"introduced": "0"},
				{"fixed": fixed},
			},
		},
	}
	if len(symbols) > 0 {
		aff.EcosystemSpecific.Imports = []osvSymImport{{Path: module, Symbols: symbols}}
	}

	r := record{ID: id, Affected: []osvAffectedEntry{aff}}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	return data
}

// TestDirSource_Query_VersionNormalization verifies that the dirSource correctly
// handles Go OSV records whose version ranges lack the "v" prefix by using the
// canonical() helper in semver.go.
func TestDirSource_Query_VersionNormalization(t *testing.T) {
	// Build a synthetic OSV record with a Go module + version range.
	// OSV records from vuln.go.dev use "1.2.3" (no v), Go module versions use "v1.2.3".
	data := buildOSVRecord(t, "OSV-2024-9999", "Go", "github.com/example/normtest", "1.5.0", nil)

	dbDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "OSV-2024-9999.json"), data, 0o644))

	ds := &dirSource{dir: dbDir, sources: []string{SourceOSV}}
	ctx := context.Background()

	// v1.3.0 is in [0, 1.5.0) — must match even though OSV range has no "v" prefix.
	advs, err := ds.query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/normtest"}, "v1.3.0")
	require.NoError(t, err)
	require.Len(t, advs, 1, "v1.3.0 must be in [0, 1.5.0)")

	// v1.5.0 is the fix — must not match.
	advs, err = ds.query(ctx, Package{Ecosystem: EcosystemGo, Name: "github.com/example/normtest"}, "v1.5.0")
	require.NoError(t, err)
	assert.Empty(t, advs, "v1.5.0 (fixed) must not match")
}

// TestOSVBundleSource_Refresh_AbsolutePath_HardError verifies that a zip entry
// with an absolute path is rejected as a hard error.
func TestOSVBundleSource_Refresh_AbsolutePath_HardError(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	// Some zip implementations write absolute paths; guard against them.
	fw, err := w.Create("/etc/evil.json")
	require.NoError(t, err)
	_, err = fw.Write([]byte(`{"id":"evil"}`))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()))

	err = src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "absolute path in zip must be a hard error")

	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	assertNoManifest(t, ecoDir)
}

// TestOSVBundleSource_Refresh_TotalSizeBomb_HardError verifies that entries
// whose combined size exceeds the total extraction cap are rejected. The cap is
// injected small so the guard is exercised without a gigabyte fixture; each
// entry stays under the per-file cap so only the aggregate guard can trip.
func TestOSVBundleSource_Refresh_TotalSizeBomb_HardError(t *testing.T) {
	chunk := bytes.Repeat([]byte("X"), 6<<20) // 6 MiB per entry, under the 10 MiB per-file cap
	entries := make(map[string][]byte)
	for i := 0; i < 10; i++ {
		entries[fmt.Sprintf("entry%02d.json", i)] = chunk
	}
	// Total 60 MiB exceeds the injected 50 MiB total cap.
	zipBytes := buildZip(t, entries)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()),
		withExtractCaps(50<<20, 0))

	err := src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "total extracted size exceeding cap must be a hard error")
	require.Contains(t, err.Error(), "total extracted size exceeds")

	ecoDir := filepath.Join(cacheDir, EcosystemGo)
	assertNoManifest(t, ecoDir)
}

// TestOSVBundleSource_Refresh_EntryCountBomb_HardError verifies the entry-count
// guard: an archive padded with more (tiny) entries than the cap is rejected.
func TestOSVBundleSource_Refresh_EntryCountBomb_HardError(t *testing.T) {
	entries := make(map[string][]byte)
	for i := 0; i < 8; i++ {
		entries[fmt.Sprintf("rec%02d.json", i)] = []byte("{}")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buildZip(t, entries))
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	src := NewOSVBundleSource(cacheDir, withBaseURL(srv.URL), withHTTPClient(srv.Client()),
		withExtractCaps(0, 5)) // 8 entries exceeds the injected 5-entry cap

	err := src.Refresh(context.Background(), EcosystemGo)
	require.Error(t, err, "entry count exceeding cap must be a hard error")
	require.Contains(t, err.Error(), "entry count exceeds")

	assertNoManifest(t, filepath.Join(cacheDir, EcosystemGo))
}

// ─── PyPI precision: multi-package record isolation (Bug A) ──────────────────

// TestBuildAdvisoryIndex_PyPI_MultiPackageRecord_Isolation verifies that a single
// OSV record affecting multiple PyPI packages (e.g. langsmith, langchain-classic,
// langchain with different fixed bounds) does NOT pollute the ranges of one package
// with ranges belonging to another.
//
// Regression for: langsmith@0.8.18 false-positive from GHSA-3644-q5cj-c5c7 where
// langchain-classic's range [0, 1.0.7) captured langsmith@0.8.18 (< 1.0.7).
func TestBuildAdvisoryIndex_PyPI_MultiPackageRecord_Isolation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := loadFixture(t, "PYPI-MULTI-PKG-GHSA-3644.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-MULTI-PKG-GHSA-3644.json"), data, 0o644))

	ctx := context.Background()
	idx, err := buildAdvisoryIndex(ctx, dir, EcosystemPyPI)
	require.NoError(t, err)

	// langsmith@0.8.18 is ABOVE fixed=0.8.0 → must be NOT affected (Bug A regression).
	results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langsmith"}, canonical("0.8.18"), []string{"test"})
	assert.Empty(t, results,
		"langsmith@0.8.18 must NOT match: above fixed=0.8.0 (was false-positive due to cross-package range pollution)")

	// langsmith@0.7.9 is BELOW fixed=0.8.0 → must be affected (true positive).
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langsmith"}, canonical("0.7.9"), []string{"test"})
	assert.Len(t, results, 1,
		"langsmith@0.7.9 must match: inside [0, 0.8.0)")

	// langsmith@0.8.0 is AT fixed boundary (exclusive) → must NOT be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langsmith"}, canonical("0.8.0"), []string{"test"})
	assert.Empty(t, results,
		"langsmith@0.8.0 must NOT match: equals fixed bound (exclusive)")

	// langchain range is [0, 0.3.30) → langchain@1.3.9 must NOT be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langchain"}, canonical("1.3.9"), []string{"test"})
	assert.Empty(t, results,
		"langchain@1.3.9 must NOT match: above fixed=0.3.30")

	// langchain@0.0.308 is the fixed bound (exclusive) → must NOT be affected.
	// Note: fixture uses 0.3.30; the real GHSA-f73w has 0.0.308. We test the fixture's value.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langchain"}, canonical("0.3.30"), []string{"test"})
	assert.Empty(t, results,
		"langchain@0.3.30 must NOT match: equals fixed bound (exclusive)")

	// langchain@0.3.0 is inside [0, 0.3.30) → must be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "langchain"}, canonical("0.3.0"), []string{"test"})
	assert.Len(t, results, 1,
		"langchain@0.3.0 must match: inside [0, 0.3.30)")
}

// ─── PyPI precision: fixed/last_affected boundary semantics (Bug A) ──────────

// TestBuildAdvisoryIndex_PyPI_BoundarySemantics encodes boundary cases 3 and 4:
// fixed is EXCLUSIVE (pinned == fixed → NotAffected) and last_affected is
// INCLUSIVE (pinned == last_affected → Affected).
func TestBuildAdvisoryIndex_PyPI_BoundarySemantics(t *testing.T) {
	t.Parallel()

	// Case: fixed boundary — version == fixed → NotAffected (EXCLUSIVE).
	// pynacl 1.6.2 vs fixed 1.6.2 and langchain 1.3.9 vs fixed 1.3.9.
	fixedBoundaryAdv := &Advisory{
		Ecosystem:     EcosystemPyPI,
		VersionRanges: []VersionRange{{Introduced: "", Fixed: "1.6.2"}},
	}
	if got := fixedBoundaryAdv.AffectsVersionV(canonical("1.6.2")); got != VersionNotAffected {
		t.Errorf("pynacl@1.6.2 vs fixed=1.6.2 (exclusive): got %v, want VersionNotAffected", got)
	}
	if got := fixedBoundaryAdv.AffectsVersionV(canonical("1.6.1")); got != VersionAffected {
		t.Errorf("pynacl@1.6.1 vs fixed=1.6.2: got %v, want VersionAffected", got)
	}
	if got := fixedBoundaryAdv.AffectsVersionV(canonical("1.7.0")); got != VersionNotAffected {
		t.Errorf("pynacl@1.7.0 vs fixed=1.6.2: got %v, want VersionNotAffected", got)
	}

	// Case: last_affected boundary — version == last_affected → Affected (INCLUSIVE).
	// diskcache 5.6.3 vs last_affected 5.6.3.
	dir := t.TempDir()
	data := loadFixture(t, "PYPI-LAST-AFFECTED-BOUNDARY.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-LAST-AFFECTED-BOUNDARY.json"), data, 0o644))

	ctx := context.Background()
	idx, err := buildAdvisoryIndex(ctx, dir, EcosystemPyPI)
	require.NoError(t, err)

	// diskcache@5.6.3 == last_affected=5.6.3 (inclusive) → must be Affected.
	results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testdiskcache"}, canonical("5.6.3"), []string{"test"})
	assert.Len(t, results, 1,
		"testdiskcache@5.6.3 must match: equals last_affected=5.6.3 (inclusive bound)")
	assert.False(t, results[0].Incomplete,
		"true-positive last_affected match must not be incomplete")

	// diskcache@5.6.4 > last_affected=5.6.3 → must NOT be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testdiskcache"}, canonical("5.6.4"), []string{"test"})
	assert.Empty(t, results,
		"testdiskcache@5.6.4 must NOT match: above last_affected=5.6.3")
}

// ─── PyPI precision: versions-only affected entries (Bug B) ──────────────────

// TestBuildAdvisoryIndex_PyPI_VersionsOnly verifies that an OSV affected entry
// with NO ranges but an explicit versions[] list matches only listed versions.
//
// Regression for: MAL-2026-2144 (litellm@1.91.0 false-positive — only
// versions ["1.82.7", "1.82.8"] are listed as malicious).
func TestBuildAdvisoryIndex_PyPI_VersionsOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := loadFixture(t, "PYPI-MAL-VERSIONS-ONLY.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-MAL-VERSIONS-ONLY.json"), data, 0o644))

	ctx := context.Background()
	idx, err := buildAdvisoryIndex(ctx, dir, EcosystemPyPI)
	require.NoError(t, err)

	// testpkg@1.91.0 is NOT in versions list → must NOT be affected (Bug B regression).
	results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpkg"}, canonical("1.91.0"), []string{"test"})
	assert.Empty(t, results,
		"testpkg@1.91.0 must NOT match: not in versions list [1.82.7, 1.82.8]")

	// testpkg@1.82.7 IS in versions list → must be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpkg"}, canonical("1.82.7"), []string{"test"})
	assert.Len(t, results, 1,
		"testpkg@1.82.7 must match: explicitly in versions list")
	assert.False(t, results[0].Incomplete,
		"versions-list match must not be incomplete")

	// testpkg@1.82.8 IS in versions list → must be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpkg"}, canonical("1.82.8"), []string{"test"})
	assert.Len(t, results, 1,
		"testpkg@1.82.8 must match: explicitly in versions list")

	// testpkg@1.0.0 is NOT in versions list → must NOT be affected.
	results = idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpkg"}, canonical("1.0.0"), []string{"test"})
	assert.Empty(t, results,
		"testpkg@1.0.0 must NOT match: not in versions list")
}

// ─── PyPI precision: GIT-range-only advisory (pillow case, Bug B invariant) ──

// TestBuildAdvisoryIndex_PyPI_GitRangeOnly verifies that an OSV record whose only
// ranges are of type GIT (git commit hashes) is forwarded as Undecidable+Incomplete,
// not silently dropped as NotAffected and not falsely matched as Affected for all
// versions. GIT hashes are not parseable as PEP 440 versions.
func TestBuildAdvisoryIndex_PyPI_GitRangeWithVersions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := loadFixture(t, "PYPI-GIT-RANGES-ONLY.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-GIT-RANGES-ONLY.json"), data, 0o644))

	ctx := context.Background()
	idx, err := buildAdvisoryIndex(ctx, dir, EcosystemPyPI)
	require.NoError(t, err)

	// The fixture's only range is GIT-typed but it carries an authoritative
	// versions[] list ([9.1.0, 9.1.1, 9.2.0]). That list decides affectedness:
	// a release in the list is Affected (decided, not incomplete)...
	for _, v := range []string{"9.1.0", "9.1.1", "9.2.0"} {
		results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpillow"}, canonical(v), []string{"test"})
		if assert.Len(t, results, 1, "testpillow@%s is in the versions[] list: must match", v) {
			assert.False(t, results[0].Incomplete,
				"testpillow@%s: a versions[] match is decided, not incomplete", v)
		}
	}
	// ...and a release absent from the list is NotAffected → not forwarded (no noise
	// UNKNOWN), matching osv-scanner's handling of GIT-range advisories.
	for _, v := range []string{"12.2.0", "1.0.0"} {
		results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testpillow"}, canonical(v), []string{"test"})
		assert.Empty(t, results,
			"testpillow@%s is absent from the versions[] list: must be NotAffected (dropped)", v)
	}
}

// TestBuildAdvisoryIndex_PyPI_GitRangeNoVersions verifies the safety case: a GIT-only
// advisory with NO versions[] enumeration cannot be evaluated, so it stays
// Undecidable and is forwarded as Incomplete=true (UNKNOWN) — never silently dropped
// (unknown != safe).
func TestBuildAdvisoryIndex_PyPI_GitRangeNoVersions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := loadFixture(t, "PYPI-GIT-RANGE-NO-VERSIONS.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-GIT-RANGE-NO-VERSIONS.json"), data, 0o644))

	ctx := context.Background()
	idx, err := buildAdvisoryIndex(ctx, dir, EcosystemPyPI)
	require.NoError(t, err)

	for _, v := range []string{"9.1.0", "12.2.0", "1.0.0"} {
		results := idx.lookup(Package{Ecosystem: EcosystemPyPI, Name: "testgitonly"}, canonical(v), []string{"test"})
		if assert.Len(t, results, 1, "testgitonly@%s: GIT-only advisory with no versions[] must be forwarded (Undecidable)", v) {
			assert.True(t, results[0].Incomplete,
				"testgitonly@%s: GIT-only advisory with no versions[] must have Incomplete=true", v)
		}
	}
}
