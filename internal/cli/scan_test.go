package cli_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot returns the absolute path to the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	// This file is at internal/cli/scan_test.go; repo root is two dirs up.
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// corpusDir returns the absolute path to testdata/corpus/.
func corpusDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "testdata", "corpus")
}

// snapshotDir returns the path to the pinned test snapshot.
func snapshotDir(t *testing.T) string {
	return filepath.Join(corpusDir(t), "db-snapshot")
}

// buildPluginBinary compiles the go-reachability plugin into a temp dir.
// Cached per test binary invocation via t.TempDir (each test gets its own
// temp dir, but since it's a fresh compile it is deterministic).
func buildPluginBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "go-reachability")
	cmd := exec.Command("go", "build", "-o", binPath,
		"github.com/ducthinh993/anst-analyzer/plugins/go-reachability")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build plugin binary:\n%s", out)
	return binPath
}

// runScanBinary runs the anst-analyzer binary with the given args and captures
// stdout/stderr. It returns (stdout, stderr, exitCode).
func runScanBinary(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	// Build the CLI binary fresh.
	cliBin := filepath.Join(t.TempDir(), "anst-analyzer")
	build := exec.Command("go", "build", "-o", cliBin,
		"github.com/ducthinh993/anst-analyzer/cmd/anst")
	build.Env = os.Environ()
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build anst-analyzer CLI:\n%s", out)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(context.Background(), cliBin, args...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	cmd.Env = os.Environ()

	runErr := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if runErr == nil {
		exitCode = 0
	} else {
		var exitErr *exec.ExitError
		if ok := isExitError(runErr, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

func isExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// runScanBinaryWithEnv is like runScanBinary but accepts extra env vars appended
// to the process environment. Used to inject ANST_VULN_DB_URL for mock servers.
func runScanBinaryWithEnv(t *testing.T, extraEnv []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	// Build the CLI binary fresh.
	cliBin := filepath.Join(t.TempDir(), "anst-analyzer")
	build := exec.Command("go", "build", "-o", cliBin,
		"github.com/ducthinh993/anst-analyzer/cmd/anst")
	build.Env = os.Environ()
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build anst-analyzer CLI:\n%s", out)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.CommandContext(context.Background(), cliBin, args...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	cmd.Env = append(os.Environ(), extraEnv...)

	runErr := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if runErr == nil {
		exitCode = 0
	} else {
		var exitErr *exec.ExitError
		if ok := isExitError(runErr, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

// newCorpusMockServer creates an httptest.Server that acts as a vuln.go.dev
// endpoint for the corpus advisory (CORPUS-CVE-001 for example.com/corpusvulnlib).
//
// dbFails, if true, makes /index/db.json return HTTP 500 so we can test the
// probe-failure fallback path (Note #1). moduleFails, if true, makes
// /index/modules.json return HTTP 500 so we can test the hard-fetch-failure path.
func newCorpusMockServer(t *testing.T, dbFails bool, moduleFails bool) *httptest.Server {
	t.Helper()

	// Load CORPUS-CVE-001 from the real db-snapshot fixture.
	corpusCVE, err := os.ReadFile(filepath.Join(snapshotDir(t), "CORPUS-CVE-001.json"))
	require.NoError(t, err, "CORPUS-CVE-001.json must exist in db-snapshot fixture")

	modulesPayload := `[{"path":"example.com/corpusvulnlib","vulns":[{"id":"CORPUS-CVE-001","modified":"2026-06-21T00:00:00Z"}]}]`
	dbPayload := `{"modified":"2026-06-21T00:00:00Z"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules.json":
			if moduleFails {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(modulesPayload))

		case "/index/db.json":
			if dbFails {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(dbPayload))

		case "/ID/CORPUS-CVE-001.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(corpusCVE)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestScan_ReachableCVE_SARIF_ExitsOne is the primary E2E test:
// scanning the reachable-cve corpus fixture with a "high" policy must produce:
//   - SARIF output containing the CORPUS-CVE-001 ruleId
//   - exit code 1 (gate failure) because the finding is SYMBOL_REACHABLE / HIGH.
//
// The go-reachability plugin is driven THROUGH the host (subprocess + gRPC),
// not called in-process. The --plugin-binary flag points to the pre-built binary.
func TestScan_ReachableCVE_SARIF_ExitsOne(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "reachable-cve")
	snap := snapshotDir(t)

	stdout, stderr, code := runScanBinary(t,
		"scan",
		modDir,
		"--format", "sarif",
		"--db-snapshot", snap,
		"--offline",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// SARIF output must be valid JSON.
	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON (SARIF)")

	// The SARIF document must contain CORPUS-CVE-001.
	assert.Contains(t, stdout, "CORPUS-CVE-001",
		"SARIF must contain the advisory rule ID")

	// The finding is SYMBOL_REACHABLE so codeFlows must be present.
	assert.Contains(t, stdout, "codeFlows",
		"SARIF must contain codeFlows for a SYMBOL_REACHABLE finding")

	// Exit code must be 1 (gate failure) — the reachable HIGH finding trips the gate.
	assert.Equal(t, 1, code,
		"exit code must be 1 (gate failure) for a reachable HIGH finding under --fail-on high")
}

// TestScan_NotReachableCVE_ReachableOnly_ExitsZero verifies the reachable-only policy:
// the not-reachable-cve fixture's finding is NOT_REACHABLE, which is the only tier
// excluded by reachable-only. The gate must pass (exit 0) but the finding must still
// appear in the SARIF output as a suppressed result (auditable, not absent).
func TestScan_NotReachableCVE_ReachableOnly_ExitsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "not-reachable-cve")
	snap := snapshotDir(t)

	// Write a reachable-only policy to a temp file.
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(policyFile, []byte("reachable-only: true\nfail-on: high\n"), 0o644))

	stdout, stderr, code := runScanBinary(t,
		"scan",
		modDir,
		"--format", "sarif",
		"--db-snapshot", snap,
		"--offline",
		"--policy", policyFile,
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON (SARIF)")

	// The advisory must still appear in the SARIF output (auditable, not absent).
	assert.Contains(t, stdout, "CORPUS-CVE-001",
		"NOT_REACHABLE finding must appear in SARIF as a suppressed result, never absent")

	// Under reachable-only policy, NOT_REACHABLE does not trip the gate.
	assert.Equal(t, 0, code,
		"exit code must be 0: NOT_REACHABLE is excluded by reachable-only policy")
}

// TestScan_OfflineMissingDepsErrors verifies the offline determinism contract:
// when --offline is used with a missing/empty snapshot, the tool must exit 3
// (operational error) with a clear error message — never silently exit 0.
func TestScan_OfflineMissingDepsErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "reachable-cve")

	// Point to a non-existent snapshot directory.
	emptySnap := filepath.Join(t.TempDir(), "nonexistent-snapshot")

	_, stderr, code := runScanBinary(t,
		"scan",
		modDir,
		"--format", "sarif",
		"--db-snapshot", emptySnap,
		"--offline",
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3 (operational error), never 0.
	assert.Equal(t, 3, code,
		"missing offline snapshot must produce exit 3, never 0")

	// Must produce a clear, human-readable error (not silent).
	assert.NotEmpty(t, stderr, "must print an error message when offline snapshot is missing")
}

// TestScan_ByteIdenticalSARIF_OfflineDeterminism verifies the offline determinism
// contract: two consecutive scans with the same inputs must produce byte-identical
// SARIF output. GOPROXY=off is set to ensure no network calls.
func TestScan_ByteIdenticalSARIF_OfflineDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "reachable-cve")
	snap := snapshotDir(t)

	runWithGoproxyOff := func() string {
		t.Helper()
		cliBin := filepath.Join(t.TempDir(), "anst-analyzer")
		build := exec.Command("go", "build", "-o", cliBin,
			"github.com/ducthinh993/anst-analyzer/cmd/anst")
		build.Env = os.Environ()
		out, err := build.CombinedOutput()
		require.NoError(t, err, "build CLI:\n%s", out)

		var stdoutBuf, stderrBuf bytes.Buffer
		cmd := exec.CommandContext(context.Background(), cliBin,
			"scan", modDir,
			"--format", "sarif",
			"--db-snapshot", snap,
			"--offline",
			"--plugin-binary", pluginBin,
		)
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		// GOPROXY=off ensures no network calls during dep resolution.
		env := os.Environ()
		env = append(env, "GOPROXY=off")
		cmd.Env = env
		_ = cmd.Run() // exit code varies; we only check stdout determinism
		return stdoutBuf.String()
	}

	run1 := runWithGoproxyOff()
	run2 := runWithGoproxyOff()

	require.NotEmpty(t, run1, "first run must produce SARIF output")

	if run1 == run2 {
		t.Logf("SARIF output is byte-identical across two offline runs")
	} else {
		// Find first differing line for diagnostics.
		lines1 := strings.Split(run1, "\n")
		lines2 := strings.Split(run2, "\n")
		for i := 0; i < len(lines1) && i < len(lines2); i++ {
			if lines1[i] != lines2[i] {
				t.Errorf("SARIF output differs at line %d:\n  run1: %q\n  run2: %q",
					i+1, lines1[i], lines2[i])
				break
			}
		}
		t.Errorf("SARIF output is NOT byte-identical across two offline runs")
	}
}

// TestScan_AdversarialBuildTagGated verifies adversarial fixture (a):
// a build-tag/GOOS-gated vuln on a non-linux runner must never produce NOT_REACHABLE.
// The expected result is UNKNOWN (CONFIDENCE_UNKNOWN maps to "CONFIDENCE_UNKNOWN" in JSON).
func TestScan_AdversarialBuildTagGated(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}
	if runtime.GOOS == "linux" {
		t.Skip("build-tag-gated fixture is only adversarial on non-linux runners")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "build-tag-gated")
	snap := snapshotDir(t)

	stdout, _, _ := runScanBinary(t,
		"scan",
		modDir,
		"--format", "json",
		"--db-snapshot", snap,
		"--offline",
		"--plugin-binary", pluginBin,
	)

	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON")

	// The finding must not be NOT_REACHABLE — that would imply safe when we
	// cannot prove it (build-config mismatch → must be UNKNOWN).
	assert.NotContains(t, stdout, "CONFIDENCE_NOT_REACHABLE",
		"build-tag-gated fixture must never produce NOT_REACHABLE on non-linux; got: %s", stdout)
}

// TestScan_AdversarialPrivateReplace verifies adversarial fixture (b):
// a module with a broken private replace must produce UNKNOWN, not a silent drop.
func TestScan_AdversarialPrivateReplace(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	modDir := filepath.Join(corpusDir(t), "cgo-private-replace")
	snap := snapshotDir(t)

	stdout, _, _ := runScanBinary(t,
		"scan",
		modDir,
		"--format", "json",
		"--db-snapshot", snap,
		"--offline",
		"--plugin-binary", pluginBin,
	)

	// Either the scan errors cleanly (exit 3, empty stdout) or produces UNKNOWN.
	// It must NEVER silently produce NOT_REACHABLE.
	if json.Valid([]byte(stdout)) && stdout != "" && stdout != "null" {
		assert.NotContains(t, stdout, "CONFIDENCE_NOT_REACHABLE",
			"broken private-replace module must not produce NOT_REACHABLE; got: %s", stdout)
	}
}

// ─── Online mode (mock vuln.go.dev) ──────────────────────────────────────────

// TestScan_OnlineMode_FetchesAndFindsAdvisory verifies that in online mode
// (no --db-snapshot) the CLI fetches advisories from the mock server into the
// writable cache dir and finds the reachable CVE (exit 1 under --fail-on high).
//
// This is test scenario 1 from the Phase-2 TDD spec.
func TestScan_OnlineMode_FetchesAndFindsAdvisory(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	srv := newCorpusMockServer(t, false, false)

	// Use a fresh temp dir as the writable cache to avoid polluting the real cache.
	cacheDir := t.TempDir()

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + srv.URL,
			// Point XDG_CACHE_HOME at our temp dir so the CLI writes there.
			"XDG_CACHE_HOME=" + cacheDir,
			// macOS: override HOME so os.UserCacheDir() returns our temp dir.
			"HOME=" + cacheDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON (SARIF)")

	// The SARIF output must contain the advisory ID from the mock server.
	assert.Contains(t, stdout, "CORPUS-CVE-001",
		"online scan must find the advisory served by the mock server")

	// The finding is SYMBOL_REACHABLE / HIGH — the gate must fail.
	assert.Equal(t, 1, code,
		"online scan with reachable HIGH finding must exit 1")
}

// TestScan_OfflineEmptyCache_ExitsThree verifies that --offline with no
// pre-populated cache (no --db-snapshot, no prior fetch) exits 3 with a clear
// error and never exits 0.
//
// This is test scenario 2 from the Phase-2 TDD spec.
func TestScan_OfflineEmptyCache_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	// Use a fresh empty temp dir — no cache populated there.
	emptyCacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			// Point UserCacheDir at the empty dir.
			"HOME=" + emptyCacheDir,
			"XDG_CACHE_HOME=" + emptyCacheDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--offline",
		"--format", "sarif",
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3 (operational error), never 0.
	assert.Equal(t, 3, code,
		"--offline with empty cache must exit 3, never 0")

	// Must print a meaningful error.
	assert.NotEmpty(t, stderr, "must print an error when offline cache is missing")
}

// TestScan_FetchFailureNoCache_ExitsThree verifies that when the mock server
// returns 500 for all requests AND the cache is empty, the scan exits 3 (never 0).
// "unknown ≠ safe": a fetch failure with no fallback cache must not produce a pass.
//
// This is test scenario 3 from the Phase-2 TDD spec.
func TestScan_FetchFailureNoCache_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	// Mock server that fails all requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	emptyCacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + srv.URL,
			"HOME=" + emptyCacheDir,
			"XDG_CACHE_HOME=" + emptyCacheDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3 (operational error), never 0.
	assert.Equal(t, 3, code,
		"fetch failure with no cache must exit 3, never 0")

	// Must surface an error message.
	assert.NotEmpty(t, stderr, "must print an error on fetch failure with no cache")
}

// TestScan_ProbeFailureWithValidCache_IncompleteNotZero verifies Note-#1:
// when the staleness probe (/index/db.json) fails BUT a valid cache already
// exists, the scan uses the existing cache, prints a warning, marks the scan
// incomplete, and exits 3 — never exits 0.
//
// This is test scenario 4 from the Phase-2 TDD spec.
func TestScan_ProbeFailureWithValidCache_IncompleteNotZero(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)

	// Step 1: populate a valid local cache using the real corpus mock server.
	populateSrv := newCorpusMockServer(t, false, false)
	cacheBaseDir := t.TempDir()

	_, populateStderr, populateCode := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + populateSrv.URL,
			"HOME=" + cacheBaseDir,
			"XDG_CACHE_HOME=" + cacheBaseDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)
	t.Logf("populate: exit=%d stderr=%q", populateCode, populateStderr)
	// Allow exit 0 or 1 — just need the cache to be populated (not exit 3).
	require.NotEqual(t, 3, populateCode, "cache population must succeed (not exit 3)")

	// Step 2: run again with a mock server where /index/db.json fails (probe fails)
	// but /index/modules.json and /ID/ still work (though they won't be called
	// since a valid cache exists and the fallback kicks in before FetchModules).
	probeFails := newCorpusMockServer(t, true /* dbFails */, false)

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + probeFails.URL,
			"HOME=" + cacheBaseDir,
			"XDG_CACHE_HOME=" + cacheBaseDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)
	t.Logf("probe-fail: exit=%d stderr=%q stdout=%s", code, stderr, stdout)

	// The scan must NOT exit 0 — incomplete scans must never appear as clean passes.
	assert.NotEqual(t, 0, code,
		"probe failure + valid cache must not exit 0 (scan is incomplete)")

	// Should exit 3 (incomplete via EvalFlags.Incomplete → ExitOperationalError).
	assert.Equal(t, 3, code,
		"probe failure + valid cache must exit 3 (incomplete)")

	// A warning must be printed to stderr.
	assert.NotEmpty(t, stderr,
		"probe failure must emit a warning to stderr")
}

// ─── Phase 3: Multi-source and --source flag tests ───────────────────────────

// buildOSVBundleZip creates an in-memory zip archive containing the corpus CVE
// advisory in OSV format, suitable for serving as a mock OSV bundle.
func buildOSVBundleZip(t *testing.T) []byte {
	t.Helper()
	corpusCVE, err := os.ReadFile(filepath.Join(snapshotDir(t), "CORPUS-CVE-001.json"))
	require.NoError(t, err, "CORPUS-CVE-001.json must exist in db-snapshot fixture")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("CORPUS-CVE-001.json")
	require.NoError(t, err)
	_, err = fw.Write(corpusCVE)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// newOSVMockServer creates an httptest.Server that serves the OSV offline bundle
// for the Go ecosystem. It serves a zip containing the corpus CVE.
// When bundleFails is true, all requests return HTTP 500.
func newOSVMockServer(t *testing.T, bundleFails bool) *httptest.Server {
	t.Helper()
	zipData := buildOSVBundleZip(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundleFails {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		// OSV bundle endpoint: /Go/all.zip
		if r.URL.Path == "/Go/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestScan_MultiSource_DefaultBothSources verifies that with the default
// --source flag (go-vuln-db,osv), both sources are queried and results are
// merged (same CVE → one advisory, exit 1 for gate failure).
func TestScan_MultiSource_DefaultBothSources(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	goSrv := newCorpusMockServer(t, false, false)
	osvSrv := newOSVMockServer(t, false)
	cacheBaseDir := t.TempDir()

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + goSrv.URL,
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheBaseDir,
			"XDG_CACHE_HOME=" + cacheBaseDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
		// --source defaults to "go-vuln-db,osv"; specify explicitly for clarity.
		"--source", "go-vuln-db,osv",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON (SARIF)")
	assert.Contains(t, stdout, "CORPUS-CVE-001",
		"merged advisory must appear in SARIF with both sources active")
	// The CORPUS-CVE-001 is SYMBOL_REACHABLE / HIGH → gate fails.
	assert.Equal(t, 1, code,
		"both-source scan with reachable HIGH finding must exit 1")
}

// TestScan_MultiSource_OSVFailure_WarnAndIncomplete verifies "degrade, not abort":
// when the OSV source fails (e.g. network error), the scan:
//   - Continues using Go-DB findings to gate.
//   - Emits a warning to stderr mentioning the OSV source.
//   - Exits 3 (incomplete via EvalFlags.Incomplete), never 0.
func TestScan_MultiSource_OSVFailure_WarnAndIncomplete(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	// Go-DB mock: succeeds normally.
	goSrv := newCorpusMockServer(t, false, false)
	// OSV mock: always fails (500).
	osvSrv := newOSVMockServer(t, true /* bundleFails */)
	cacheBaseDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + goSrv.URL,
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheBaseDir,
			"XDG_CACHE_HOME=" + cacheBaseDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
		"--source", "go-vuln-db,osv",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must NOT be 0: an OSV failure marks the scan incomplete.
	assert.NotEqual(t, 0, code,
		"OSV source failure must not produce exit 0 (incomplete)")
	// Must exit 3 (incomplete, not gate failure — gate failure would be 1 if
	// Go-DB findings were gating, but incomplete overrides to 3).
	assert.Equal(t, 3, code,
		"OSV source failure + incomplete must exit 3")

	// Warning must mention OSV failure.
	assert.Contains(t, strings.ToLower(stderr), "osv",
		"stderr must mention OSV source in the warning")
}

// TestScan_MultiSource_GoDBOnly verifies that --source go-vuln-db queries only
// the Go-DB source (OSV server must NOT be contacted).
func TestScan_MultiSource_GoDBOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	goSrv := newCorpusMockServer(t, false, false)
	cacheBaseDir := t.TempDir()

	// Track whether the OSV server is ever hit — it must NOT be.
	var osvHit bool
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		osvHit = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(osvSrv.Close)

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_VULN_DB_URL=" + goSrv.URL,
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheBaseDir,
			"XDG_CACHE_HOME=" + cacheBaseDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
		"--source", "go-vuln-db",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// OSV server must not have been contacted.
	assert.False(t, osvHit,
		"--source go-vuln-db must not contact the OSV server")

	// Go-DB findings should still gate correctly.
	require.True(t, json.Valid([]byte(stdout)), "output must be valid JSON (SARIF)")
	assert.Contains(t, stdout, "CORPUS-CVE-001")
	assert.Equal(t, 1, code,
		"go-vuln-db-only scan with reachable HIGH finding must exit 1")
}

// TestScan_MultiSource_OfflineMissingOSVCache verifies "offline honesty":
// when --offline is used and the OSV cache has never been populated, the OSV
// source is skipped and the scan exits 3 (incomplete), never silently clean.
// Go-DB uses a pinned snapshot so that part succeeds.
func TestScan_MultiSource_OfflineMissingOSVCache(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	snap := snapshotDir(t)
	// Fresh empty cache dir — OSV has never been populated.
	emptyCacheDir := t.TempDir()

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"HOME=" + emptyCacheDir,
			"XDG_CACHE_HOME=" + emptyCacheDir,
		},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--db-snapshot", snap,
		"--offline",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
		"--source", "go-vuln-db,osv",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3 (incomplete) — OSV cache missing makes scan incomplete.
	assert.Equal(t, 3, code,
		"offline + missing OSV cache must exit 3 (incomplete), never 0")

	// Must print a warning about the missing OSV cache.
	assert.NotEmpty(t, stderr, "must print a warning about the missing OSV cache")
	assert.Contains(t, strings.ToLower(stderr), "osv",
		"warning must mention OSV source being skipped")
}

// TestScan_MultiSource_InvalidSourceFlag verifies that an unknown --source value
// causes exit 3 with a clear error message.
func TestScan_MultiSource_InvalidSourceFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	snap := snapshotDir(t)

	_, stderr, code := runScanBinary(t,
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--db-snapshot", snap,
		"--offline",
		"--plugin-binary", pluginBin,
		"--source", "unknown-source",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	assert.Equal(t, 3, code,
		"unknown --source value must produce exit 3")
	assert.Contains(t, stderr, "unknown-source",
		"error message must name the invalid source")
}

// TestScan_DBSnapshotIsReadOnly verifies that --db-snapshot never causes the
// CLI to fetch or mutate the snapshot directory. After running with --db-snapshot,
// no files in the snapshot dir should have new mtimes.
//
// This is test scenario 5 from the Phase-2 TDD spec.
func TestScan_DBSnapshotIsReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E test requires plugin build; skipping in short mode")
	}

	pluginBin := buildPluginBinary(t)
	snap := snapshotDir(t)

	// Record mtimes before the scan.
	type fileInfo struct{ mod int64 }
	mtimesBefore := map[string]fileInfo{}
	entries, err := os.ReadDir(snap)
	require.NoError(t, err)
	for _, e := range entries {
		info, infoErr := e.Info()
		require.NoError(t, infoErr)
		mtimesBefore[e.Name()] = fileInfo{mod: info.ModTime().UnixNano()}
	}

	// Mock server that records calls. It must NOT be called when --db-snapshot
	// is set, because the pin is read-only.
	var mockHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockHit = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, stderr, _ := runScanBinaryWithEnv(t,
		[]string{"ANST_VULN_DB_URL=" + srv.URL},
		"scan",
		filepath.Join(corpusDir(t), "reachable-cve"),
		"--format", "sarif",
		"--db-snapshot", snap,
		"--offline",
		"--fail-on", "high",
		"--plugin-binary", pluginBin,
	)
	t.Logf("stderr=%q", stderr)

	// The mock server must not have been hit.
	assert.False(t, mockHit,
		"--db-snapshot must never cause a network fetch")

	// File mtimes in the snapshot dir must be unchanged.
	for name, before := range mtimesBefore {
		info, statErr := os.Stat(filepath.Join(snap, name))
		require.NoError(t, statErr)
		assert.Equal(t, before.mod, info.ModTime().UnixNano(),
			"file %s mtime must not change when --db-snapshot is set", name)
	}
}
