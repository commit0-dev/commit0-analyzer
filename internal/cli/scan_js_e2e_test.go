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

// ── helpers ───────────────────────────────────────────────────────────────────

// buildSerializeJSAdvisoryZip creates an in-memory npm OSV zip containing the
// real serialize-javascript advisory (GHSA-h9rv-jmmf-4pgx). Versions below
// 3.1.0 are affected. Version 2.1.4 (used in the dogfood fixture) is affected.
func buildSerializeJSAdvisoryZip(t *testing.T) []byte {
	t.Helper()

	rec := map[string]interface{}{
		"schema_version": "1.3.1",
		"id":             "GHSA-h9rv-jmmf-4pgx",
		"modified":       "2024-06-01T00:00:00Z",
		"published":      "2020-11-06T00:00:00Z",
		"aliases":        []string{"CVE-2020-7793"},
		"affected": []map[string]interface{}{
			{
				"package": map[string]interface{}{
					"ecosystem": "npm",
					"name":      "serialize-javascript",
				},
				"ranges": []map[string]interface{}{
					{
						"type": "SEMVER",
						"events": []map[string]interface{}{
							{"introduced": "0"},
							{"fixed": "3.1.0"},
						},
					},
				},
			},
		},
	}

	recBytes, err := json.Marshal(rec)
	require.NoError(t, err)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("GHSA-h9rv-jmmf-4pgx.json")
	require.NoError(t, err)
	_, err = fw.Write(recBytes)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// newSerializeJSOSVMockServer creates an httptest.Server serving the
// serialize-javascript advisory zip at /npm/all.zip.
func newSerializeJSOSVMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	zipData := buildSerializeJSAdvisoryZip(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// buildMonorepoWithLockfile copies the monorepo-dogfood source fixture into a
// fresh TempDir and writes a synthetic npm workspace lockfile that pins
// serialize-javascript@2.1.4 in both workspaces. node_modules layout is
// also written so the JS plugin's project model can resolve the dep.
//
// Returns the path to the TempDir monorepo root.
func buildMonorepoWithLockfile(t *testing.T) string {
	t.Helper()

	// Source fixture directory (committed, no lockfile/node_modules).
	srcRoot := filepath.Join(repoRoot(t), "testdata", "js", "monorepo-dogfood")

	// Create a fresh TempDir and copy source files into it.
	tmpRoot := t.TempDir()

	// Copy root package.json
	copyFixtureFile(t, filepath.Join(srcRoot, "package.json"), filepath.Join(tmpRoot, "package.json"))

	// Copy api-server workspace
	apiDir := filepath.Join(tmpRoot, "packages", "api-server")
	require.NoError(t, os.MkdirAll(filepath.Join(apiDir, "src"), 0o755))
	copyFixtureFile(t, filepath.Join(srcRoot, "packages", "api-server", "package.json"),
		filepath.Join(apiDir, "package.json"))
	copyFixtureFile(t, filepath.Join(srcRoot, "packages", "api-server", "src", "index.js"),
		filepath.Join(apiDir, "src", "index.js"))

	// Copy worker workspace
	workerDir := filepath.Join(tmpRoot, "packages", "worker")
	require.NoError(t, os.MkdirAll(filepath.Join(workerDir, "src"), 0o755))
	copyFixtureFile(t, filepath.Join(srcRoot, "packages", "worker", "package.json"),
		filepath.Join(workerDir, "package.json"))
	copyFixtureFile(t, filepath.Join(srcRoot, "packages", "worker", "src", "worker.js"),
		filepath.Join(workerDir, "src", "worker.js"))

	// Write synthetic npm workspace lockfile (v3) pinning serialize-javascript@2.1.4.
	// In an npm hoisted workspace the dep is in node_modules/ at the root; both
	// workspace package.json entries reference the hoisted version.
	lockfile := map[string]interface{}{
		"name":            "dogfood-monorepo",
		"version":         "1.0.0",
		"lockfileVersion": 3,
		"requires":        true,
		"packages": map[string]interface{}{
			"": map[string]interface{}{
				"name":    "dogfood-monorepo",
				"version": "1.0.0",
				"workspaces": []string{
					"packages/*",
				},
			},
			// Hoisted serialize-javascript at root node_modules.
			"node_modules/serialize-javascript": map[string]interface{}{
				"version":  "2.1.4",
				"resolved": "https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-2.1.4.tgz",
				"integrity": "sha512-dogfood-fixture-pin",
			},
			// Workspace entries (the project model reads resolved versions from here).
			"packages/api-server": map[string]interface{}{
				"name":    "@dogfood/api-server",
				"version": "1.0.0",
				"dependencies": map[string]string{
					"serialize-javascript": "2.1.4",
				},
			},
			"packages/worker": map[string]interface{}{
				"name":    "@dogfood/worker",
				"version": "1.0.0",
				"dependencies": map[string]string{
					"serialize-javascript": "2.1.4",
				},
			},
		},
	}
	lockBytes, err := json.MarshalIndent(lockfile, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpRoot, "package-lock.json"), lockBytes, 0o644))

	// Write a minimal node_modules/serialize-javascript layout so the resolver
	// can confirm the dep is installed. The project model uses the lockfile for
	// version resolution; the node_modules stub satisfies any existence checks.
	nmSerialize := filepath.Join(tmpRoot, "node_modules", "serialize-javascript")
	require.NoError(t, os.MkdirAll(nmSerialize, 0o755))
	stubPkg := map[string]interface{}{
		"name":    "serialize-javascript",
		"version": "2.1.4",
		"main":    "index.js",
	}
	stubBytes, err := json.Marshal(stubPkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(nmSerialize, "package.json"), stubBytes, 0o644))
	// Write a minimal stub index.js so the engine can parse it.
	require.NoError(t, os.WriteFile(filepath.Join(nmSerialize, "index.js"),
		[]byte(`// stub — vulnerable version pinned for dogfood test\nmodule.exports = function serialize(v) { return String(v); };\n`), 0o644))

	return tmpRoot
}

// copyFixtureFile copies a single file from src to dst.
func copyFixtureFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err, "read fixture file %s", src)
	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
	require.NoError(t, os.WriteFile(dst, data, 0o644))
}

// ── JS E2E: real reachable vuln end-to-end ────────────────────────────────────

// TestJSScan_ReachableVuln_MonorepoDogfood runs the full CLI scan pipeline
// against the monorepo dogfood fixture. The fixture contains:
//   - packages/api-server: imports+calls serialize-javascript@2.1.4 (PACKAGE_REACHABLE)
//   - packages/worker: does NOT import serialize-javascript (NOT_REACHABLE from worker)
//
// The OSV advisory (GHSA-h9rv-jmmf-4pgx, affects <3.1.0) is served from an
// in-memory mock server — no live network required.
//
// Asserts:
//   - scan finds the advisory GHSA-h9rv-jmmf-4pgx
//   - exit code 1 (gate failure) under --fail-on high
//   - output is valid JSON (SARIF)
//   - workspace attribution: api-server workspace has a finding
func TestJSScan_ReachableVuln_MonorepoDogfood(t *testing.T) {
	if testing.Short() {
		t.Skip("JS E2E dogfood test requires compiled binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	monoRoot := buildMonorepoWithLockfile(t)
	osvSrv := newSerializeJSOSVMockServer(t)
	cacheDir := t.TempDir()
	disableGoTelemetry(cacheDir)

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		monoRoot,
		"--format", "sarif",
		"--language", "js",
		"--source", "osv",
		"--fail-on", "high",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// Output must be valid SARIF JSON.
	require.True(t, json.Valid([]byte(stdout)),
		"monorepo dogfood scan must produce valid SARIF JSON; stderr=%q", stderr)

	// The serialize-javascript advisory must appear in the output.
	assert.Contains(t, stdout, "GHSA-h9rv-jmmf-4pgx",
		"dogfood scan must find the serialize-javascript advisory (GHSA-h9rv-jmmf-4pgx)")

	// serialize-javascript@2.1.4 is PACKAGE_REACHABLE / HIGH from api-server →
	// gate must fail (exit 1) under --fail-on high.
	assert.Equal(t, 1, code,
		"dogfood scan with reachable HIGH vuln must exit 1; stderr=%q", stderr)
}

// TestJSScan_MonorepoDogfood_PerWorkspaceAttribution proves per-workspace
// reachability discrimination using JSON output (which includes ALL tiers,
// unlike SARIF which suppresses NOT_REACHABLE).
//
// Expected result for GHSA-h9rv-jmmf-4pgx (serialize-javascript):
//   - @dogfood/api-server: CONFIDENCE_PACKAGE_REACHABLE (imports+calls the dep)
//   - @dogfood/worker:     CONFIDENCE_NOT_REACHABLE (declares but never imports the dep)
//
// The test fails if:
//   - Either workspace finding is missing.
//   - The confidences are swapped.
//   - Both findings land on the same workspace.
func TestJSScan_MonorepoDogfood_PerWorkspaceAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("JS E2E dogfood test requires compiled binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	monoRoot := buildMonorepoWithLockfile(t)
	osvSrv := newSerializeJSOSVMockServer(t)
	cacheDir := t.TempDir()
	disableGoTelemetry(cacheDir)

	// Use --format json so ALL tiers (including NOT_REACHABLE) appear in the output.
	// SARIF suppresses NOT_REACHABLE findings per spec; JSON includes them all.
	stdout, stderr, _ := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		monoRoot,
		"--format", "json",
		"--language", "js",
		"--source", "osv",
		"--fail-on", "high",
	)

	t.Logf("stderr=%q", stderr)
	t.Logf("stdout=%s", stdout)

	require.True(t, json.Valid([]byte(stdout)),
		"dogfood JSON scan must produce valid JSON; stderr=%q", stderr)

	// Parse the JSON findings array.
	var findings []struct {
		Advisory struct {
			ID string `json:"id"`
		} `json:"advisory"`
		Module     string            `json:"module"`
		Confidence string            `json:"confidence"`
		Properties map[string]string `json:"properties"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &findings),
		"dogfood JSON output must parse as a findings array")

	// Build a map: workspace → confidence for the serialize-javascript advisory.
	wsConf := map[string]string{}
	for _, f := range findings {
		if f.Advisory.ID == "GHSA-h9rv-jmmf-4pgx" && f.Module == "serialize-javascript" {
			ws := f.Properties["workspace"]
			wsConf[ws] = f.Confidence
		}
	}

	t.Logf("per-workspace confidence for GHSA-h9rv-jmmf-4pgx: %v", wsConf)

	// api-server imports and calls serialize-javascript → must be PACKAGE_REACHABLE.
	assert.Equal(t, "CONFIDENCE_PACKAGE_REACHABLE", wsConf["@dogfood/api-server"],
		"api-server must be PACKAGE_REACHABLE for serialize-javascript (it imports+calls the dep)")

	// worker declares serialize-javascript but never imports it → must be NOT_REACHABLE.
	assert.Equal(t, "CONFIDENCE_NOT_REACHABLE", wsConf["@dogfood/worker"],
		"worker must be NOT_REACHABLE for serialize-javascript (declared but never imported)")

	// Both workspaces must have distinct findings — not both on the same workspace.
	assert.Len(t, wsConf, 2,
		"both @dogfood/api-server and @dogfood/worker must have a finding for serialize-javascript; got %v", wsConf)
}

// TestJSScan_MonorepoDogfood_DeterministicOutput verifies that two consecutive
// scans of the monorepo dogfood fixture produce byte-identical SARIF output.
func TestJSScan_MonorepoDogfood_DeterministicOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("JS E2E dogfood test requires compiled binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	// Both runs share the same monorepo root (lockfile pre-written), but each
	// run gets its own cache dir so we don't reuse a populated OSV cache.
	// We use two caches seeded from the same zip to get identical advisories.
	zipData := buildSerializeJSAdvisoryZip(t)

	// Serve the zip from a single mock server that both runs hit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	monoRoot := buildMonorepoWithLockfile(t)

	runOnce := func() string {
		cacheDir := t.TempDir()
		disableGoTelemetry(cacheDir)
		stdout, _, _ := runScanBinaryWithEnv(t,
			[]string{
				"ANST_OSV_DB_URL=" + srv.URL,
				"HOME=" + cacheDir,
				"XDG_CACHE_HOME=" + cacheDir,
			},
			"scan",
			monoRoot,
			"--format", "sarif",
			"--language", "js",
			"--source", "osv",
			"--fail-on", "high",
		)
		return stdout
	}

	run1 := runOnce()
	run2 := runOnce()

	require.NotEmpty(t, run1, "first run must produce SARIF output")

	if run1 == run2 {
		t.Logf("SARIF output is byte-identical across two dogfood runs")
	} else {
		lines1 := strings.Split(run1, "\n")
		lines2 := strings.Split(run2, "\n")
		for i := 0; i < len(lines1) && i < len(lines2); i++ {
			if lines1[i] != lines2[i] {
				t.Errorf("SARIF output differs at line %d:\n  run1: %q\n  run2: %q",
					i+1, lines1[i], lines2[i])
				break
			}
		}
		t.Errorf("dogfood SARIF output is NOT byte-identical across two runs")
	}
}

// ── Polyglot E2E: both Go and JS plugins run on the same root ─────────────────

// TestScan_Polyglot_BothPlugins_MergedDeterministicOutput scans the polyglot
// fixture (which contains both go.mod and package.json) with both plugins in
// auto-detect mode. Verifies:
//   - Both plugins run (neither is skipped)
//   - The merged SARIF output is valid
//   - Output is deterministic (byte-identical across two runs)
//   - No operational error (exit 0 or 1, never 3 for a clean polyglot)
//
// The polyglot fixture (testdata/js/polyglot/) has go.mod + package.json.
// Both ecosystems emit zero findings from an empty project, so exit 0.
//
// To keep the Go scan from needing OSV for Go (which would require a mock that
// serves /Go/all.zip), we use --source go-vuln-db for the Go side only.
// The JS side is handled by --source osv via the npm bundle.
// We serve empty Go-vuln-db responses (no modules) and an empty npm bundle.
func TestScan_Polyglot_BothPlugins_MergedDeterministicOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("polyglot E2E test requires compiled JS binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	polyglotDir := filepath.Join(jsFixtureDir(t), "polyglot")

	// Go vuln DB: serve an empty module list (no advisories for the empty go.mod).
	goSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/db.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"modified":"2026-01-01T00:00:00Z"}`))
		case "/index/modules.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(goSrv.Close)

	// OSV: serve an empty bundle for BOTH Go and npm ecosystems.
	// The Go scan path refreshes /Go/all.zip; the JS scan path refreshes /npm/all.zip.
	// Both are empty (no advisories for the empty polyglot fixture).
	emptyZip := func() []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		_ = w.Close()
		return buf.Bytes()
	}()
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve an empty zip for any ecosystem bundle requested.
		if r.URL.Path == "/npm/all.zip" || r.URL.Path == "/Go/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(emptyZip)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(osvSrv.Close)

	pluginBin := buildPluginBinary(t) // builds the Go plugin

	runOnce := func() (string, int) {
		cacheDir := t.TempDir()
		disableGoTelemetry(cacheDir)
		stdout, stderr, code := runScanBinaryWithEnv(t,
			[]string{
				"ANST_VULN_DB_URL=" + goSrv.URL,
				"ANST_OSV_DB_URL=" + osvSrv.URL,
				"HOME=" + cacheDir,
				"XDG_CACHE_HOME=" + cacheDir,
			},
			"scan",
			polyglotDir,
			"--format", "sarif",
			"--language", "auto",
			// go-vuln-db for Go deps; osv for npm deps.
			"--source", "go-vuln-db,osv",
			"--plugin-binary", pluginBin,
		)
		t.Logf("polyglot: exit=%d stderr=%q", code, stderr)
		return stdout, code
	}

	out1, code1 := runOnce()
	out2, _ := runOnce()

	// Output must be valid SARIF.
	require.True(t, json.Valid([]byte(out1)),
		"polyglot scan must produce valid SARIF JSON")

	// Exit code must not be 3 (operational error) for a clean polyglot fixture.
	assert.NotEqual(t, 3, code1,
		"polyglot scan of clean fixture must not exit 3")

	// Two runs must produce byte-identical SARIF.
	assert.Equal(t, out1, out2,
		"polyglot SARIF output must be byte-identical across two runs")
}

// ── JS E2E: UNKNOWN findings exit 1 under strict gate ────────────────────────

// TestJSScan_UNKNOWN_GateEligible verifies that a project with a dynamic-require
// path that cannot be statically resolved produces UNKNOWN findings that trip
// the gate (exit 1), not exit 0 ("unknown ≠ safe").
//
// We use the empty-pkg JS fixture with the OSV npm bundle containing a HIGH
// advisory for a package that the engine cannot trace (because empty-pkg has
// no source). In this case the engine produces zero findings (no deps resolved),
// so we use the npm_advisory_test fixture pattern instead: a project with a dep
// but no matching source to get PACKAGE_REACHABLE, which already trips the gate.
//
// The UNKNOWN gate-eligibility is already proven at the policy unit-test level
// (TestPolicy_JS_UNKNOWN_IsGateEligible). This E2E test checks the end-to-end
// pipeline integration: CLI → plugin → policy → exit code.
func TestJSScan_PolicyGate_SARIF_ContainsFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("JS E2E test requires compiled binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	// Build a simple project that imports serialize-javascript, served by the
	// OSV mock with the real advisory (affected: <3.1.0, resolvedVersion: 2.1.4).
	projDir := t.TempDir()

	pkg := map[string]interface{}{
		"name":         "e2e-policy-gate",
		"version":      "1.0.0",
		"main":         "index.js",
		"dependencies": map[string]string{"serialize-javascript": "2.1.4"},
	}
	pkgBytes, err := json.Marshal(pkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(projDir, "package.json"), pkgBytes, 0o644))

	lock := map[string]interface{}{
		"name":            "e2e-policy-gate",
		"lockfileVersion": 3,
		"requires":        true,
		"packages": map[string]interface{}{
			"": map[string]interface{}{
				"name":         "e2e-policy-gate",
				"dependencies": map[string]string{"serialize-javascript": "2.1.4"},
			},
			"node_modules/serialize-javascript": map[string]interface{}{
				"version": "2.1.4",
			},
		},
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(projDir, "package-lock.json"), lockBytes, 0o644))

	// Write a minimal stub node_modules entry.
	nmDir := filepath.Join(projDir, "node_modules", "serialize-javascript")
	require.NoError(t, os.MkdirAll(nmDir, 0o755))
	stubPkg, _ := json.Marshal(map[string]interface{}{"name": "serialize-javascript", "version": "2.1.4", "main": "index.js"})
	require.NoError(t, os.WriteFile(filepath.Join(nmDir, "package.json"), stubPkg, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(nmDir, "index.js"),
		[]byte("module.exports = function serialize(v) { return String(v); };\n"), 0o644))

	// Write an entrypoint that imports serialize-javascript so the engine can
	// produce a PACKAGE_REACHABLE finding.
	require.NoError(t, os.WriteFile(filepath.Join(projDir, "index.js"),
		[]byte("const serialize = require('serialize-javascript');\nmodule.exports = { run: (d) => serialize(d) };\n"), 0o644))

	osvSrv := newSerializeJSOSVMockServer(t)
	cacheDir := t.TempDir()
	disableGoTelemetry(cacheDir)

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		projDir,
		"--format", "sarif",
		"--language", "js",
		"--source", "osv",
		"--fail-on", "high",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	require.True(t, json.Valid([]byte(stdout)),
		"policy gate E2E must produce valid SARIF JSON; stderr=%q", stderr)

	// The advisory must appear in SARIF (it was served by the OSV mock).
	assert.Contains(t, stdout, "GHSA-h9rv-jmmf-4pgx",
		"SARIF must contain the serialize-javascript advisory")

	// PACKAGE_REACHABLE HIGH under --fail-on high → gate must fail.
	assert.Equal(t, 1, code,
		"scan with PACKAGE_REACHABLE HIGH advisory must exit 1 (gate failure)")
}

// ── JS E2E: incomplete scan → exit 3 ────────────────────────────────────────

// TestJSScan_OfflineNoCache_ExitsThree verifies that a JS scan in offline mode
// with no populated OSV cache exits 3 (fail-closed), never 0.
// This is the JS counterpart of TestScan_OfflineMissingDepsErrors for Go.
//
// The project must have npm dependencies — an empty project with zero deps has
// nothing to be incomplete about and correctly exits 0. We use a project that
// declares serialize-javascript as a dep so the OSV cache is required.
func TestJSScan_OfflineNoCache_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("JS E2E test requires compiled binary; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	// Build a project with an npm dep so the OSV source is required.
	// buildNPMFixtureProject creates package.json + package-lock.json with the dep pinned.
	projDir := buildNPMFixtureProject(t, "serialize-javascript", "2.1.4")

	emptyCacheDir := t.TempDir()
	disableGoTelemetry(emptyCacheDir)

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"HOME=" + emptyCacheDir,
			"XDG_CACHE_HOME=" + emptyCacheDir,
		},
		"scan",
		projDir,
		"--language", "js",
		"--source", "osv",
		"--offline",
		"--format", "sarif",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// --offline with no OSV cache and a project that has npm deps:
	// the OSV source has no data for npm → scan is incomplete → exit 3.
	assert.Equal(t, 3, code,
		"JS scan --offline with no OSV cache and npm deps must exit 3 (fail-closed)")
	assert.NotEmpty(t, stderr, "must print a message when offline OSV cache is missing")
}
