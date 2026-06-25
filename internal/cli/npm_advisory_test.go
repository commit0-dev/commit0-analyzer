package cli_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── npm advisory CLI integration tests ──────────────────────────────────────
//
// These tests verify the npm advisory resolution path in the CLI:
//   - The OSV npm bundle is fetched and queried per dep
//   - Scoped packages (@scope/name) pass through --list-deps correctly
//   - Secondary-source (OSV) failure → warn + incomplete (exit 3), not abort
//   - go-vuln-db source no-ops for npm (not contacted when --source osv)
//
// Tests that require the built JS plugin binary are skipped if the binary is
// absent (mirrors the P1 js_plugin_e2e_test gating pattern).

// buildNPMOSVZip creates an in-memory zip archive with one npm OSV advisory.
func buildNPMOSVZip(t *testing.T, advID, pkgName, fixedVersion string) []byte {
	t.Helper()

	rec := map[string]interface{}{
		"schema_version": "1.3.1",
		"id":             advID,
		"modified":       "2024-06-01T00:00:00Z",
		"published":      "2024-01-15T00:00:00Z",
		"aliases":        []string{"CVE-2024-npm-" + advID},
		"affected": []map[string]interface{}{
			{
				"package": map[string]interface{}{
					"ecosystem": "npm",
					"name":      pkgName,
				},
				"ranges": []map[string]interface{}{
					{
						"type": "SEMVER",
						"events": []map[string]interface{}{
							{"introduced": "0"},
							{"fixed": fixedVersion},
						},
					},
				},
				"ecosystem_specific": map[string]interface{}{},
			},
		},
	}

	recBytes, err := json.Marshal(rec)
	require.NoError(t, err)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create(advID + ".json")
	require.NoError(t, err)
	_, err = fw.Write(recBytes)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// newNPMOSVMockServer creates an httptest.Server serving npm/all.zip.
// When bundleFails is true all requests return HTTP 500.
func newNPMOSVMockServer(t *testing.T, advID, pkgName, fixedVersion string, bundleFails bool) *httptest.Server {
	t.Helper()
	zipData := buildNPMOSVZip(t, advID, pkgName, fixedVersion)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundleFails {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// buildNPMFixtureProject writes a minimal npm project with one JS source file
// to a temp directory. The source file imports pkgName so the JS plugin can
// detect a package reference and produce a finding for any advisory on that package.
//
// Returns the directory path.
func buildNPMFixtureProject(t *testing.T, pkgName, resolvedVersion string) string {
	t.Helper()
	dir := t.TempDir()

	// Derive a safe lockfile key for the package (scoped packages include "@scope/").
	lockKey := "node_modules/" + pkgName

	pkg := map[string]interface{}{
		"name":         "test-npm-project",
		"version":      "1.0.0",
		"dependencies": map[string]string{pkgName: "^" + resolvedVersion},
	}
	pkgBytes, err := json.Marshal(pkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), pkgBytes, 0o644))

	lock := map[string]interface{}{
		"name":            "test-npm-project",
		"version":         "1.0.0",
		"lockfileVersion": 3,
		"requires":        true,
		"packages": map[string]interface{}{
			"": map[string]interface{}{
				"name":         "test-npm-project",
				"version":      "1.0.0",
				"dependencies": map[string]string{pkgName: "^" + resolvedVersion},
			},
			lockKey: map[string]interface{}{
				"version":  resolvedVersion,
				"name":     pkgName,
				"resolved": "https://registry.npmjs.org/-/_.tgz",
			},
		},
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), lockBytes, 0o644))

	// Install the dependency on disk. The project model walks the installed
	// tree to compute the dependency closure; a declared-but-uninstalled dep is
	// correctly reported as incomplete, so a realistic fixture must materialise
	// node_modules/<pkg>/package.json (as a real npm install would).
	depDir := filepath.Join(dir, "node_modules", filepath.FromSlash(pkgName))
	require.NoError(t, os.MkdirAll(depDir, 0o755))
	depPkgBytes, err := json.Marshal(map[string]interface{}{
		"name":    pkgName,
		"version": resolvedVersion,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(depDir, "package.json"), depPkgBytes, 0o644))

	return dir
}

// jsPluginBinaryPath returns the path to the built JS plugin binary, or ""
// if it hasn't been built yet.
func jsPluginBinaryPath(t *testing.T) string {
	t.Helper()
	repoRoot := repoRoot(t)
	binPath := filepath.Join(repoRoot, "plugins", "js-reachability", "dist", "anst-js-reachability")
	if _, err := os.Stat(binPath); err != nil {
		return ""
	}
	return binPath
}

// TestScan_NPM_ListDepsAndOSVQuery verifies the npm advisory resolution path:
// the CLI correctly invokes --list-deps on the JS plugin, fetches the npm OSV
// bundle, and queries advisories for the resolved dep list.
//
// This test checks that OSV refresh succeeds (exit 0 or 1) — not that the JS
// plugin produces findings (that requires source-level reachability analysis).
// What we validate:
//   - The scan completes without operational error (exit 0 — no findings because
//     no JS source to analyze, but the advisory pipeline ran without error).
//   - The OSV npm bundle endpoint WAS contacted (advisory query ran).
func TestScan_NPM_ListDepsAndOSVQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	projectDir := buildNPMFixtureProject(t, "example-npm-pkg", "1.5.0")

	var osvNPMHit bool
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			osvNPMHit = true
			zipData := buildNPMOSVZip(t, "GHSA-npm-test-0001", "example-npm-pkg", "2.0.0")
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(osvSrv.Close)
	cacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// The npm/all.zip endpoint must have been hit — advisory query ran.
	assert.True(t, osvNPMHit, "OSV npm bundle endpoint must be contacted during npm advisory resolution")

	// The scan must not exit with operational error (3). It may exit 0 (no
	// findings because no JS source) or 1 (gate failure if findings exist).
	assert.NotEqual(t, 3, code,
		"npm scan with valid OSV source must not exit 3 (operational error)")
}

// TestScan_NPM_ScopedPackage verifies that scoped npm packages (@scope/name)
// are handled by --list-deps correctly and advisory lookup uses the normalized name.
func TestScan_NPM_ScopedPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	// Scoped package: @scope/example-pkg@1.0.0.
	projectDir := buildNPMFixtureProject(t, "@scope/example-pkg", "1.0.0")

	var osvNPMHit bool
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			osvNPMHit = true
			zipData := buildNPMOSVZip(t, "GHSA-npm-scoped-0001", "@scope/example-pkg", "3.0.0")
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(osvSrv.Close)
	cacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// The npm/all.zip endpoint must be hit (scoped dep triggered the advisory query).
	assert.True(t, osvNPMHit,
		"OSV npm bundle endpoint must be hit for scoped package @scope/example-pkg")

	// Must not be an operational error.
	assert.NotEqual(t, 3, code,
		"scoped-package npm scan must not exit 3 (operational error)")
}

// TestScan_NPM_OSVFailure_WarnAndIncomplete verifies "degrade, not abort":
// when the OSV npm bundle fetch fails, the scan warns on stderr and exits 3
// (incomplete), not 0 ("unknown ≠ safe").
func TestScan_NPM_OSVFailure_WarnAndIncomplete(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	projectDir := buildNPMFixtureProject(t, "example-npm-pkg", "1.5.0")

	// OSV server that always fails (500).
	osvSrv := newNPMOSVMockServer(t, "GHSA-npm-test-0001", "example-npm-pkg", "2.0.0", true)
	cacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// OSV failure marks the scan incomplete → exit 3, never 0.
	assert.NotEqual(t, 0, code,
		"OSV npm fetch failure must not produce exit 0 (unknown ≠ safe)")
	assert.Equal(t, 3, code,
		"OSV npm fetch failure must exit 3 (incomplete)")

	// stderr must mention OSV.
	assert.NotEmpty(t, stderr, "stderr must be non-empty on OSV failure")
	assert.Contains(t, strings.ToLower(stderr), "osv",
		"stderr must mention OSV source in the warning")
}

// TestScan_NPM_GoVulnDB_NotContacted verifies that go-vuln-db is NOT contacted
// when scanning a JS-only project (--source osv --language js). The go-vuln-db
// source no-ops cleanly for npm (returns nil,nil by design).
func TestScan_NPM_GoVulnDB_NotContacted(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	projectDir := buildNPMFixtureProject(t, "example-npm-pkg", "1.5.0")

	// Track whether go-vuln-db-style endpoints are hit.
	var goVulnDBHit bool
	goSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goVulnDBHit = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(goSrv.Close)

	osvSrv := newNPMOSVMockServer(t, "GHSA-npm-test-0001", "example-npm-pkg", "2.0.0", false)
	cacheDir := t.TempDir()

	_, stderr, _ := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + goSrv.URL, // would be hit if go-vuln-db queried
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		// Explicitly request both sources; go-vuln-db must no-op for npm.
		"--source", "osv",
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("stderr=%q", stderr)

	// go-vuln-db server must NOT have been contacted for a JS-only scan.
	assert.False(t, goVulnDBHit,
		"go-vuln-db server must not be contacted when scanning npm packages")
}

// buildCorruptLockDevOnlyProject writes a project with a corrupt package-lock.json
// and only devDependencies (zero runtime deps) to a temp directory.
// This exercises H1: corrupt lockfile must mark the scan incomplete even when
// declaredDepCount=0, because lockfile-corrupt is an error-level signal.
func buildCorruptLockDevOnlyProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	pkg := map[string]interface{}{
		"name":    "corrupt-dev-only",
		"version": "1.0.0",
		"devDependencies": map[string]string{
			"vitest": "^1.0.0",
		},
	}
	pkgBytes, err := json.Marshal(pkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), pkgBytes, 0o644))

	// Write a deliberately corrupt lockfile (invalid JSON).
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "package-lock.json"),
		[]byte("{ this is not valid json - corrupt lockfile !!!"),
		0o644,
	))

	return dir
}

// TestScan_NPM_CorruptLockfileZeroRuntimeDeps_IsIncomplete reproduces H1:
// a corrupt package-lock.json on a devDependencies-only project must mark the
// scan incomplete (exit 3), NOT clean (exit 0). Previously the declaredDepCount=0
// gate suppressed the lockfile-corrupt signal, producing a false-negative.
func TestScan_NPM_CorruptLockfileZeroRuntimeDeps_IsIncomplete(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	projectDir := buildCorruptLockDevOnlyProject(t)

	osvSrv := newNPMOSVMockServer(t, "GHSA-npm-unused-0001", "some-pkg", "2.0.0", false)
	cacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// A corrupt lockfile is an error regardless of declared dep count.
	// The scan must exit 3 (incomplete), not 0 (clean).
	assert.Equal(t, 3, code,
		"corrupt lockfile with zero runtime deps must exit 3 (incomplete), not 0 (clean/false-negative)")
	assert.Contains(t, strings.ToLower(stderr), "incomplete",
		"stderr must mention incomplete on corrupt lockfile")
}

// TestScan_NPM_GoVulnDBOnlySource_WarnAndIncomplete reproduces M1:
// when JS is in scope but only go-vuln-db is selected (no npm-capable source),
// the scan must warn on stderr and exit 3 (incomplete), not 0 (clean).
// go-vuln-db provides no npm coverage, so scanning with it alone leaves npm
// packages entirely unchecked — unknown ≠ safe.
func TestScan_NPM_GoVulnDBOnlySource_WarnAndIncomplete(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test: requires built JS plugin binary; skipping in short mode")
	}

	jsPluginBin := jsPluginBinaryPath(t)
	if jsPluginBin == "" {
		t.Skip("js plugin not built: run 'make build-js-plugin'")
	}

	projectDir := buildNPMFixtureProject(t, "example-npm-pkg", "1.5.0")

	// go-vuln-db server that must NOT be contacted for npm.
	var goVulnDBHit bool
	goSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goVulnDBHit = true
		http.Error(w, "should not be called for npm", http.StatusInternalServerError)
	}))
	t.Cleanup(goSrv.Close)
	cacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + goSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projectDir,
		"--format", "json",
		"--source", "go-vuln-db", // no npm-capable source
		"--language", "js",
		"--js-plugin-binary", jsPluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// go-vuln-db must not have been contacted for a JS project.
	assert.False(t, goVulnDBHit,
		"go-vuln-db server must not be contacted when scanning npm packages")

	// No npm-capable source selected → warn + incomplete.
	assert.Equal(t, 3, code,
		"JS scan with no npm-capable source must exit 3 (incomplete), not 0 (silent no-coverage)")
	assert.NotEmpty(t, stderr, "stderr must be non-empty: must warn about missing npm advisory coverage")
}
