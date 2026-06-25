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

	// When a test overrides HOME (to isolate the advisory cache), the scan's
	// internal `go list`/`go build` would otherwise write Go telemetry counter
	// files into that temp HOME asynchronously, racing t.TempDir cleanup
	// ("directory not empty"). Disabling telemetry via the "off" mode file in the
	// overridden HOME avoids the flake. Best-effort; only applied to test HOMEs.
	for _, e := range extraEnv {
		if home, ok := strings.CutPrefix(e, "HOME="); ok {
			disableGoTelemetry(home)
		}
	}

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

// disableGoTelemetry writes an "off" Go telemetry mode file under home so that
// `go` subprocesses run with HOME=home do not write counter files (which race
// t.TempDir cleanup). It covers both the macOS and XDG/Linux config locations.
// Best-effort: errors are ignored.
func disableGoTelemetry(home string) {
	for _, dir := range []string{
		filepath.Join(home, "Library", "Application Support", "go", "telemetry"), // macOS
		filepath.Join(home, ".config", "go", "telemetry"),                        // Linux/XDG default
	} {
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "mode"), []byte("off"), 0o644)
	}
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

// ─── Multi-source and --source flag tests ────────────────────────────────────

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

// ─── Rust plugin wiring tests ────────────────────────────────────────────────

// buildRustPluginBinary compiles the rust-reachability plugin into a temp dir
// and returns the path to the binary.
func buildRustPluginBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "anst-rust-reachability")
	cmd := exec.Command("go", "build", "-o", binPath,
		"github.com/ducthinh993/anst-analyzer/plugins/rust-reachability")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build rust plugin binary:\n%s", out)
	return binPath
}

// TestScan_BuildRustPluginManifest_BinaryAbsent verifies via CLI behavior that
// when --rust-plugin-binary points to a non-existent file, the scan treats
// Rust as unsupported and exits 3 (never 0, never crashes).
// This is the observable CLI effect of buildRustPluginManifest returning (nil, false).
func TestScan_BuildRustPluginManifest_BinaryAbsent(t *testing.T) {
	// Create a minimal Cargo.toml directory.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"test-crate\"\nversion = \"0.1.0\"\n"), 0o644))

	nonExistentBin := filepath.Join(t.TempDir(), "anst-rust-reachability-nonexistent")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		"--source", "osv",
		"--offline",
		"--rust-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	// Absent binary → rust unsupported → incomplete → exit 3.
	assert.Equal(t, 3, code,
		"absent rust plugin binary must produce exit 3 (incomplete), not 0 (false clean)")
	// The warning must mention rust.
	assert.Contains(t, strings.ToLower(stderr), "rust",
		"warning must mention rust when binary is absent")
}

// TestScan_BuildRustPluginManifest_BinaryPresent verifies via CLI behavior that
// when --rust-plugin-binary points to a valid built binary, the scan registers
// the Rust plugin (no "unsupported" warning emitted) and does not crash.
// This is the observable CLI effect of buildRustPluginManifest returning (manifest, true).
func TestScan_BuildRustPluginManifest_BinaryPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}
	// Create a minimal Cargo.toml directory.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"test-crate\"\nversion = \"0.1.0\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.lock"),
		[]byte("# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n"), 0o644))

	rustBin := buildRustPluginBinary(t)
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		"--source", "osv",
		"--offline",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	// The "no rust scan path" warning must NOT be emitted.
	assert.NotContains(t, strings.ToLower(stderr), "no rust scan path",
		"registered rust plugin must not trigger the unsupported-ecosystem warning")
	// Scan must not crash (exit code -1 would indicate a crash).
	assert.NotEqual(t, -1, code, "scan must not crash when rust plugin is registered")
}

// TestScan_RustEcosystem_NoPlugin_IncompleteWarning verifies that when a
// directory contains Cargo.toml but the rust plugin binary is unavailable,
// the scan exits 3 (incomplete) with a warning mentioning rust — never exits 0
// (unknown ≠ safe).
func TestScan_RustEcosystem_NoPlugin_IncompleteWarning(t *testing.T) {
	// Create a minimal Cargo.toml directory (no Go/JS files).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"test-crate\"\nversion = \"0.1.0\"\n"), 0o644))

	// Run with an explicit --rust-plugin-binary pointing to a non-existent path
	// so the plugin is unavailable.
	nonExistentBin := filepath.Join(t.TempDir(), "no-such-rust-plugin")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		"--source", "osv",
		"--offline",
		"--rust-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3: missing plugin binary = incomplete scan (unknown ≠ safe).
	assert.Equal(t, 3, code,
		"rust ecosystem detected but no plugin binary: must exit 3, never 0")
	// Must mention rust in the warning.
	assert.Contains(t, strings.ToLower(stderr), "rust",
		"warning must mention rust when rust plugin is unavailable")
}

// TestScan_RustEcosystem_WithPlugin_RegistersPlugin verifies that when
// --rust-plugin-binary points to a real built binary, the CLI registers the
// plugin and does not print the "no rust scan path" warning. The telemetry span
// scan.plugin.run is exercised on the registered plugin.
//
// The scan is run against a directory with only Cargo.toml (no advisories will
// be found, so exit 0 is expected).
func TestScan_RustEcosystem_WithPlugin_RegistersPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	// Create a minimal Cargo.toml directory.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"test-crate\"\nversion = \"0.1.0\"\n"), 0o644))
	// Also write a minimal Cargo.lock so cargo metadata can run offline.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.lock"),
		[]byte("# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n"), 0o644))

	rustBin := buildRustPluginBinary(t)

	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		"--source", "osv",
		"--offline",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must NOT print the "no rust scan path" warning.
	assert.NotContains(t, strings.ToLower(stderr), "no rust scan path",
		"registered rust plugin must not trigger the unsupported-ecosystem warning")
	// In offline mode with an empty OSV cache and --source osv (explicit),
	// the missing crates.io OSV cache is an incomplete signal (unknown ≠ safe).
	// Cargo metadata on the empty-lockfile fixture also signals incomplete.
	// Exit 3 (incomplete) is the ONLY acceptable outcome — exit 0 would be a
	// false-clean (the scan was partial; we cannot certify the repo is clean).
	assert.Equal(t, 3, code,
		"offline scan with empty OSV cache and empty lockfile must exit 3 (incomplete), never 0")
}

// TestScan_LanguageRustFilter_NoCargoToml verifies that --language rust on a
// directory without Cargo.toml exits 3 with an error (nothing to scan).
func TestScan_LanguageRustFilter_NoCargoToml(t *testing.T) {
	// Create a directory with go.mod only (no Cargo.toml).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/test\ngo 1.21\n"), 0o644))

	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		"--source", "osv",
		"--offline",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// With --language rust but no Cargo.toml, no ecosystem is detected → exit 3.
	assert.Equal(t, 3, code,
		"--language rust on a dir without Cargo.toml must exit 3")
	assert.NotEmpty(t, stderr, "must print an error message")
}

// buildCratesIOOSVZip creates an in-memory zip archive containing one crates.io
// OSV advisory in the format expected by OSVBundleSource. The advisory covers
// pkgName at versions < fixedVersion.
func buildCratesIOOSVZip(t *testing.T, advID, pkgName, fixedVersion string) []byte {
	t.Helper()

	rec := map[string]interface{}{
		"schema_version": "1.3.1",
		"id":             advID,
		"modified":       "2024-06-01T00:00:00Z",
		"published":      "2024-01-15T00:00:00Z",
		"aliases":        []string{"CVE-2024-rust-" + advID},
		"affected": []map[string]interface{}{
			{
				"package": map[string]interface{}{
					"ecosystem": "crates.io",
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

// newCratesIOOSVMockServer creates an httptest.Server serving crates.io/all.zip
// with one advisory. When bundleFails is true, all requests return HTTP 500.
func newCratesIOOSVMockServer(t *testing.T, advID, pkgName, fixedVersion string, bundleFails bool) *httptest.Server {
	t.Helper()
	zipData := buildCratesIOOSVZip(t, advID, pkgName, fixedVersion)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundleFails {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/crates.io/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// buildRustFixtureProject creates a minimal Rust project with no external deps
// in a temp directory and returns the directory path. The project has a lib
// target so `cargo metadata` succeeds without a prior registry fetch.
// The crate is named pkgName at version pkgVersion.
//
// A minimal Cargo.lock is written alongside Cargo.toml so that both the host's
// listCargoDeps and the Rust plugin's internal cargo call can run without network
// access. Without Cargo.lock, cargo metadata --offline fails even for a
// no-dependency project on some Cargo versions.
func buildRustFixtureProject(t *testing.T, pkgName, pkgVersion string) string {
	t.Helper()
	dir := t.TempDir()

	libName := strings.ReplaceAll(pkgName, "-", "_")
	cargoToml := "[package]\nname = \"" + pkgName + "\"\nversion = \"" + pkgVersion + "\"\nedition = \"2021\"\n\n[lib]\nname = \"" + libName + "\"\npath = \"src/lib.rs\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml), 0o644))

	// Minimal Cargo.lock for a no-dependency project (Cargo v3 format).
	// The single [[package]] entry is the workspace member itself. This lets
	// both the host's listCargoDeps and the Rust plugin's internal cargo call
	// run with --offline on any Cargo version that requires a lock file.
	cargoLock := "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n\n[[package]]\nname = \"" + pkgName + "\"\nversion = \"" + pkgVersion + "\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(cargoLock), 0o644))

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "lib.rs"), []byte("// test\n"), 0o644))

	return dir
}

// TestScan_RustPlugin_WithAdvisory_PACKAGE_REACHABLE verifies the complete
// Rust advisory pipeline: when the crates.io OSV bundle contains an advisory
// matching a crate in the project's Cargo closure (the workspace member itself),
// the Rust plugin produces a PACKAGE_REACHABLE finding and the scan exits 1
// (gate failure under --fail-on high).
//
// This test proves all three previously-broken invariants are fixed:
//  1. listCargoDeps populates cargoDeps from cargo metadata.
//  2. The Rust plugin receives the advisory (non-empty Advisories field).
//  3. hasPartialityMarker honors Finding.Incomplete (no false-clean from partial).
func TestScan_RustPlugin_WithAdvisory_PACKAGE_REACHABLE(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build and cargo; skipping in short mode")
	}

	rustBin := buildRustPluginBinary(t)

	// The workspace member itself ("vuln-crate" at 0.1.0) is the "vulnerable" crate.
	// Advisory covers 0.1.0 (fixed at 1.0.0) → version 0.1.0 is affected.
	const (
		pkgName      = "vuln-crate"
		pkgVersion   = "0.1.0"
		advID        = "RUST-TEST-ADV-0001"
		fixedVersion = "1.0.0"
	)

	projectDir := buildRustFixtureProject(t, pkgName, pkgVersion)
	osvSrv := newCratesIOOSVMockServer(t, advID, pkgName, fixedVersion, false)
	cacheDir := t.TempDir()

	// Preserve RUSTUP_HOME so cargo can locate the toolchain when HOME is
	// overridden for cache isolation. RUSTUP_HOME defaults to ~/.rustup; if the
	// env var is not set, construct the default path from the real HOME.
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		realHome, err := os.UserHomeDir()
		if err == nil {
			rustupHome = filepath.Join(realHome, ".rustup")
		}
	}

	extraEnv := []string{
		"ANST_OSV_DB_URL=" + osvSrv.URL,
		"HOME=" + cacheDir,
		"XDG_CACHE_HOME=" + cacheDir,
	}
	if rustupHome != "" {
		extraEnv = append(extraEnv, "RUSTUP_HOME="+rustupHome)
	}

	stdout, stderr, code := runScanBinaryWithEnv(t,
		extraEnv,
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "rust",
		"--fail-on", "high",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// The advisory must appear in the JSON output.
	assert.Contains(t, stdout, advID,
		"advisory ID must appear in findings when the crate is in the Cargo closure")

	// The finding must be PACKAGE_REACHABLE (workspace member = always reachable).
	assert.Contains(t, stdout, "CONFIDENCE_PACKAGE_REACHABLE",
		"workspace member matched by advisory must be PACKAGE_REACHABLE, not UNKNOWN or NOT_REACHABLE")

	// A PACKAGE_REACHABLE finding at default HIGH severity trips the gate → exit 1.
	// If the scan exits 3 instead, the advisory pipeline failed (the plugin received empty advisories).
	// If the scan exits 0, the finding was suppressed (false-clean).
	assert.Equal(t, 1, code,
		"PACKAGE_REACHABLE HIGH finding must trip the gate (exit 1); exit 0 is a false-clean; exit 3 means the advisory pipeline is broken")
}

// TestScan_RustPlugin_PartialResolve_ExitsThree verifies that when cargo
// metadata fails (binary absent or returning non-zero), the host marks the
// scan incomplete and exits 3 — never exits 0 (unknown ≠ safe).
//
// This exercises the hasPartialityMarker(Finding.Incomplete) path: the Rust
// plugin emits UNKNOWN+Incomplete=true for every advisory when ClosureUnknown
// is set, and the host reads Finding.Incomplete to propagate incomplete=true.
func TestScan_RustPlugin_PartialResolve_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	rustBin := buildRustPluginBinary(t)

	// Serve a crates.io advisory so the plugin receives at least one advisory
	// to degrade to UNKNOWN+Incomplete=true.
	const (
		pkgName      = "vuln-crate"
		pkgVersion   = "0.1.0"
		advID        = "RUST-TEST-ADV-0002"
		fixedVersion = "1.0.0"
	)

	// Create a project dir with ONLY Cargo.toml (no src/, no Cargo.lock).
	// cargo metadata --offline will fail because there is no Cargo.lock and
	// no internet access to resolve deps. This simulates a partial resolve.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"vuln-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
		0o644))

	osvSrv := newCratesIOOSVMockServer(t, advID, pkgName, fixedVersion, false)
	cacheDir := t.TempDir()

	// Preserve RUSTUP_HOME so cargo can locate the toolchain when HOME is overridden.
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		if realHome, err := os.UserHomeDir(); err == nil {
			rustupHome = filepath.Join(realHome, ".rustup")
		}
	}
	extraEnv := []string{
		"ANST_OSV_DB_URL=" + osvSrv.URL,
		"HOME=" + cacheDir,
		"XDG_CACHE_HOME=" + cacheDir,
	}
	if rustupHome != "" {
		extraEnv = append(extraEnv, "RUSTUP_HOME="+rustupHome)
	}

	_, stderr, code := runScanBinaryWithEnv(t,
		extraEnv,
		"scan",
		dir,
		"--format", "json",
		"--source", "osv",
		"--language", "rust",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// A partial or failed cargo resolve must NEVER produce exit 0 (false-clean).
	// The scan is incomplete: either the host marks incomplete from listCargoDeps
	// failure, or the plugin emits UNKNOWN+Incomplete=true which hasPartialityMarker detects.
	assert.NotEqual(t, 0, code,
		"partial cargo resolve must not exit 0 (unknown ≠ safe)")
	// The canonical incomplete exit code is 3.
	assert.Equal(t, 3, code,
		"partial cargo resolve must exit 3 (incomplete), not 1 (gate failure) or 0 (false-clean)")
}

// ─── Python plugin wiring tests ──────────────────────────────────────────────

// TestScan_BuildPythonPluginManifest_BinaryAbsent verifies via CLI behavior that
// when --python-plugin-binary points to a non-existent file, the scan treats
// Python as unsupported and exits 3 (never 0, never crashes).
// This is the observable CLI effect of buildPythonPluginManifest returning (nil, false).
func TestScan_BuildPythonPluginManifest_BinaryAbsent(t *testing.T) {
	// Create a minimal pyproject.toml directory.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project]\nname = \"test-project\"\nversion = \"0.1.0\"\n"), 0o644))

	nonExistentBin := filepath.Join(t.TempDir(), "anst-python-reachability-nonexistent")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "python",
		"--source", "osv",
		"--offline",
		"--python-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	// Absent binary → python unsupported → incomplete → exit 3.
	assert.Equal(t, 3, code,
		"absent python plugin binary must produce exit 3 (incomplete), not 0 (false clean)")
	// The warning must mention python.
	assert.Contains(t, strings.ToLower(stderr), "python",
		"warning must mention python when binary is absent")
}

// TestScan_PythonEcosystem_NoPlugin_IncompleteWarning verifies that when a
// directory contains pyproject.toml but the python plugin binary is unavailable,
// the scan exits 3 (incomplete) with a warning mentioning python — never exits 0
// (unknown ≠ safe).
func TestScan_PythonEcosystem_NoPlugin_IncompleteWarning(t *testing.T) {
	// Create a minimal pyproject.toml directory (no Go/JS/Rust files).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project]\nname = \"test-project\"\nversion = \"0.1.0\"\n"), 0o644))

	// Run with an explicit --python-plugin-binary pointing to a non-existent path
	// so the plugin is unavailable.
	nonExistentBin := filepath.Join(t.TempDir(), "no-such-python-plugin")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "python",
		"--source", "osv",
		"--offline",
		"--python-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3: missing plugin binary = incomplete scan (unknown ≠ safe).
	assert.Equal(t, 3, code,
		"python ecosystem detected but no plugin binary: must exit 3, never 0")
	// Must mention python in the warning.
	assert.Contains(t, strings.ToLower(stderr), "python",
		"warning must mention python when python plugin is unavailable")
}

// TestScan_PythonEcosystem_RequirementsTxt_NoPlugin verifies that when a
// directory contains requirements.txt (rather than pyproject.toml), the Python
// ecosystem is still detected and the scan exits 3 when no plugin binary is
// available — confirming both detection manifest files trigger the ecosystem.
func TestScan_PythonEcosystem_RequirementsTxt_NoPlugin(t *testing.T) {
	// Create a minimal requirements.txt directory (no Go/JS/Rust files).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("requests==2.28.0\n"), 0o644))

	nonExistentBin := filepath.Join(t.TempDir(), "no-such-python-plugin")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "python",
		"--source", "osv",
		"--offline",
		"--python-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3: requirements.txt detected + no plugin = incomplete (unknown ≠ safe).
	assert.Equal(t, 3, code,
		"requirements.txt ecosystem detected but no plugin binary: must exit 3, never 0")
	assert.Contains(t, strings.ToLower(stderr), "python",
		"warning must mention python when python plugin is unavailable")
}

// TestScan_LanguagePythonFilter_NoPythonManifest verifies that --language python on a
// directory without pyproject.toml or requirements.txt exits 3 with an error
// (nothing to scan) — mirroring the Rust behavior.
func TestScan_LanguagePythonFilter_NoPythonManifest(t *testing.T) {
	// Create a directory with go.mod only (no Python manifest files).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/test\ngo 1.21\n"), 0o644))

	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "python",
		"--source", "osv",
		"--offline",
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// With --language python but no pyproject.toml/requirements.txt,
	// no ecosystem is detected → exit 3.
	assert.Equal(t, 3, code,
		"--language python on a dir without pyproject.toml/requirements.txt must exit 3")
	assert.NotEmpty(t, stderr, "must print an error message")
}

// TestScan_PythonEcosystem_AutoDetect_NoPlugin verifies that in auto-detect mode
// (no --language flag), a directory with pyproject.toml is detected as Python
// and the scan exits 3 when no plugin binary is available — confirming auto-detect
// runs all ecosystems including Python.
func TestScan_PythonEcosystem_AutoDetect_NoPlugin(t *testing.T) {
	// Create a directory with only pyproject.toml (no Go/JS/Rust files).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project]\nname = \"test-project\"\nversion = \"0.1.0\"\n"), 0o644))

	nonExistentBin := filepath.Join(t.TempDir(), "no-such-python-plugin")
	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		// No --language flag: auto-detect mode.
		"--source", "osv",
		"--offline",
		"--python-plugin-binary", nonExistentBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Auto-detect must run Python when pyproject.toml is present.
	// No plugin binary → incomplete → exit 3 (not 0, not crash).
	assert.Equal(t, 3, code,
		"auto-detect with pyproject.toml and no python plugin must exit 3 (unknown ≠ safe)")
	assert.Contains(t, strings.ToLower(stderr), "python",
		"warning must mention python in auto-detect mode")
}

// ─── Python plugin binary-present tests ──────────────────────────────────────

// buildPythonPluginBinary compiles the python-reachability plugin into a temp
// dir and returns the path to the binary. Mirrors buildRustPluginBinary.
func buildPythonPluginBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "anst-python-reachability")
	cmd := exec.Command("go", "build", "-o", binPath,
		"github.com/ducthinh993/anst-analyzer/plugins/python-reachability")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build python plugin binary:\n%s", out)
	return binPath
}

// buildPyPIOSVZip creates an in-memory zip containing one PyPI OSV advisory.
// The advisory covers pkgName at versions < fixedVersion.
func buildPyPIOSVZip(t *testing.T, advID, pkgName, fixedVersion string) []byte {
	t.Helper()

	rec := map[string]interface{}{
		"schema_version": "1.3.1",
		"id":             advID,
		"modified":       "2024-06-01T00:00:00Z",
		"published":      "2024-01-15T00:00:00Z",
		"aliases":        []string{"CVE-2024-python-" + advID},
		"affected": []map[string]interface{}{
			{
				"package": map[string]interface{}{
					"ecosystem": "PyPI",
					"name":      pkgName,
				},
				"ranges": []map[string]interface{}{
					{
						"type": "ECOSYSTEM",
						"events": []map[string]interface{}{
							{"introduced": "0"},
							{"fixed": fixedVersion},
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
	fw, err := w.Create(advID + ".json")
	require.NoError(t, err)
	_, err = fw.Write(recBytes)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// newPyPIOSVMockServer creates an httptest.Server serving PyPI/all.zip with
// one advisory. When bundleFails is true all requests return HTTP 500.
func newPyPIOSVMockServer(t *testing.T, advID, pkgName, fixedVersion string, bundleFails bool) *httptest.Server {
	t.Helper()
	zipData := buildPyPIOSVZip(t, advID, pkgName, fixedVersion)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundleFails {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/PyPI/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestScan_PythonPlugin_RequirementsTxt_AdvisoryFound_ExitsThree verifies the
// full Python advisory pipeline when the binary is present:
//   - requirements.txt with a pinned dep is parsed by --list-deps
//   - The PyPI OSV advisory for that dep is found and included in output
//   - The scan exits 3 (incomplete) because requirements.txt is ALWAYS an
//     incomplete closure (not the full transitive dep graph)
//
// This exercises the step-5d block (scan.go:756-860): the PyPI advisory query
// loop, the pyIncomplete-forces-incomplete path, and the plugin Analyze call.
// It is the Python analog of TestScan_RustPlugin_PartialResolve_ExitsThree.
func TestScan_PythonPlugin_RequirementsTxt_AdvisoryFound_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	pythonBin := buildPythonPluginBinary(t)

	const (
		pkgName      = "requests"
		pkgVersion   = "2.28.0"
		advID        = "PYPI-TEST-ADV-0001"
		fixedVersion = "2.32.0"
	)

	// A requirements.txt with a pinned dep is always an incomplete closure.
	// The plugin --list-deps returns: {deps: [{name:"requests",version:"2.28.0"}], incomplete:true}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte(pkgName+"=="+pkgVersion+"\n"), 0o644))

	osvSrv := newPyPIOSVMockServer(t, advID, pkgName, fixedVersion, false)
	cacheDir := t.TempDir()

	stdout, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		dir,
		"--format", "json",
		"--source", "osv",
		"--language", "python",
		"--python-plugin-binary", pythonBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// The advisory must appear in the JSON output: the PyPI OSV query loop ran.
	assert.Contains(t, stdout, advID,
		"advisory ID must appear in findings: the step-5d PyPI advisory query loop must have executed")

	// requirements.txt is always an incomplete closure → pyIncomplete=true →
	// scan.go:769-777 forces incomplete=true → exit 3 (never exit 0 or 1).
	assert.Equal(t, 3, code,
		"requirements.txt always signals incomplete closure; scan must exit 3 (never 0 = false-clean, never 1 = wrong gate)")

	// The stderr must include the incomplete warning.
	assert.Contains(t, strings.ToLower(stderr), "incomplete",
		"incomplete degradation warning must appear in stderr")
}

// TestScan_PythonPlugin_ManifestOnly_NoLockfile_ExitsThree verifies the
// manifest-only / no-venv degradation path:
//   - Only pyproject.toml present (no lockfile, no requirements.txt)
//   - Plugin --list-deps returns {deps:[], incomplete:true}
//   - scan.go:769-777 forces incomplete=true on pyIncomplete signal
//   - Scan exits 3 (never 0, never 1)
//
// This is the "no-venv run -> incomplete=true + all UNKNOWN" path required by
// the node verify clause.
func TestScan_PythonPlugin_ManifestOnly_NoLockfile_ExitsThree(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	pythonBin := buildPythonPluginBinary(t)

	// Serve a PyPI OSV advisory so the pipeline is exercised even on the empty-deps path.
	osvSrv := newPyPIOSVMockServer(t, "PYPI-TEST-ADV-0002", "requests", "2.32.0", false)
	cacheDir := t.TempDir()

	// Only pyproject.toml — no lockfile, no requirements.txt.
	// listDeps in the plugin finds no lockfile and returns (nil, true, nil).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project]\nname = \"my-app\"\nversion = \"0.1.0\"\n"), 0o644))

	_, stderr, code := runScanBinaryWithEnv(t,
		[]string{
			"ANST_OSV_DB_URL=" + osvSrv.URL,
			"HOME=" + cacheDir,
			"XDG_CACHE_HOME=" + cacheDir,
		},
		"scan",
		dir,
		"--format", "json",
		"--source", "osv",
		"--language", "python",
		"--python-plugin-binary", pythonBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Manifest-only (no lockfile / no venv) signals pyIncomplete=true.
	// scan.go:769-777 forces incomplete=true → exit 3 (never 0 = false-clean).
	assert.Equal(t, 3, code,
		"manifest-only project (no lockfile) must exit 3; exit 0 is a false-clean; exit 1 is wrong")

	// The incomplete warning must appear.
	assert.Contains(t, strings.ToLower(stderr), "incomplete",
		"incomplete degradation warning must appear when no lockfile is present")
}

// ─── False-clean guard tests (Task 4) ────────────────────────────────────────
//
// When a Rust or Python ecosystem is detected and the plugin binary is present,
// but no OSV-capable source is selected (e.g. --source go-vuln-db only),
// the host must warn and mark incomplete → exit 3 (never 0 = false-clean).

// TestScan_RustEcosystem_GoDBOnly_IncompleteGuard verifies that when Rust deps
// are present and the plugin binary is available, but --source go-vuln-db (no
// OSV coverage for crates.io) is selected, the scan exits 3 (incomplete) and
// warns about unchecked rust packages — never exits 0 (false-clean).
func TestScan_RustEcosystem_GoDBOnly_IncompleteGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	rustBin := buildRustPluginBinary(t)

	// Minimal Cargo.toml with a Cargo.lock so cargo metadata can run offline.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"),
		[]byte("[package]\nname = \"test-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.lock"),
		[]byte("# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n"), 0o644))

	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "rust",
		// go-vuln-db has NO crates.io coverage — the guard must fire.
		"--source", "go-vuln-db",
		"--offline",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3: rust ecosystem in scope but no advisory-capable source selected.
	assert.Equal(t, 3, code,
		"rust ecosystem + no crates.io-capable source must exit 3 (false-clean guard)")
	// Must mention rust in the warning.
	assert.Contains(t, strings.ToLower(stderr), "rust",
		"warning must mention rust when crates.io advisory source is absent")
}

// TestScan_PythonEcosystem_GoDBOnly_IncompleteGuard verifies that when Python deps
// are present and the plugin binary is available, but --source go-vuln-db (no
// OSV coverage for PyPI) is selected, the scan exits 3 (incomplete) and warns —
// never exits 0 (false-clean).
func TestScan_PythonEcosystem_GoDBOnly_IncompleteGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build; skipping in short mode")
	}

	pythonBin := buildPythonPluginBinary(t)

	// Minimal requirements.txt — simple enough for listPythonDeps to parse.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("requests==2.28.0\n"), 0o644))

	_, stderr, code := runScanBinary(t,
		"scan",
		dir,
		"--language", "python",
		// go-vuln-db has NO PyPI coverage — the guard must fire.
		"--source", "go-vuln-db",
		"--offline",
		"--python-plugin-binary", pythonBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)

	// Must exit 3: python ecosystem in scope but no advisory-capable source selected.
	assert.Equal(t, 3, code,
		"python ecosystem + no PyPI-capable source must exit 3 (false-clean guard)")
	// Must mention python in the warning.
	assert.Contains(t, strings.ToLower(stderr), "python",
		"warning must mention python when PyPI advisory source is absent")
}

// ─── Severity join tests (Task 2) ────────────────────────────────────────────

// TestScan_SeverityJoin_OSVAdvisoryWithCVSS verifies that when the OSV bundle
// contains a crates.io advisory with CVSS severity data, the Finding.severity in
// the JSON output reflects the advisory's severity (not SEVERITY_UNSPECIFIED or
// the conservative HIGH default). This tests stampAdvisorySeverity via the CLI.
//
// The test uses a synthetic crates.io OSV advisory with CVSS v3 base score 9.8
// (CRITICAL), which should map to SEVERITY_CRITICAL in the output.
func TestScan_SeverityJoin_OSVAdvisoryWithCVSS(t *testing.T) {
	if testing.Short() {
		t.Skip("requires plugin build and cargo; skipping in short mode")
	}

	rustBin := buildRustPluginBinary(t)

	const (
		pkgName      = "vuln-crate-sev"
		pkgVersion   = "0.1.0"
		advID        = "RUST-SEV-ADV-0001"
		fixedVersion = "1.0.0"
	)

	// Build an OSV advisory with explicit CVSS v3 severity (score 9.8 = CRITICAL).
	rec := map[string]interface{}{
		"schema_version": "1.3.1",
		"id":             advID,
		"modified":       "2024-06-01T00:00:00Z",
		"published":      "2024-01-15T00:00:00Z",
		"severity": []map[string]interface{}{
			{
				"type":  "CVSS_V3",
				"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		},
		"affected": []map[string]interface{}{
			{
				"package": map[string]interface{}{
					"ecosystem": "crates.io",
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
			},
		},
	}
	recBytes, err := json.Marshal(rec)
	require.NoError(t, err)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, zipErr := w.Create(advID + ".json")
	require.NoError(t, zipErr)
	_, _ = fw.Write(recBytes)
	require.NoError(t, w.Close())
	zipData := buf.Bytes()

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crates.io/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(osvSrv.Close)

	projectDir := buildRustFixtureProject(t, pkgName, pkgVersion)
	cacheDir := t.TempDir()

	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		if realHome, err2 := os.UserHomeDir(); err2 == nil {
			rustupHome = filepath.Join(realHome, ".rustup")
		}
	}
	extraEnv := []string{
		"ANST_OSV_DB_URL=" + osvSrv.URL,
		"HOME=" + cacheDir,
		"XDG_CACHE_HOME=" + cacheDir,
	}
	if rustupHome != "" {
		extraEnv = append(extraEnv, "RUSTUP_HOME="+rustupHome)
	}

	stdout, stderr, code := runScanBinaryWithEnv(t,
		extraEnv,
		"scan",
		projectDir,
		"--format", "json",
		"--source", "osv",
		"--language", "rust",
		"--fail-on", "critical",
		"--rust-plugin-binary", rustBin,
	)

	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	// The advisory must appear in the output.
	assert.Contains(t, stdout, advID,
		"advisory ID must appear when the crate is in the Cargo closure")

	// The severity in the output must be CRITICAL (from CVSS 9.8), not UNSPECIFIED.
	// stampAdvisorySeverity fills it from the advisory; stampDefaultSeverity would
	// set HIGH as fallback — CRITICAL proves the advisory join ran.
	assert.Contains(t, stdout, "SEVERITY_CRITICAL",
		"severity must be CRITICAL from advisory CVSS data (not the HIGH default)")
}
