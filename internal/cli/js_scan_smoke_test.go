package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsFixtureDir returns the absolute path to testdata/js/.
func jsFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "testdata", "js")
}

// jsPluginBuilt returns true when the compiled JS plugin dist exists.
// If the dist is absent the caller should skip rather than fail.
func jsPluginBuilt(t *testing.T) bool {
	t.Helper()
	root := repoRoot(t)
	sidecar := filepath.Join(root, "plugins", "js-reachability", "dist",
		"oxc-binding",
		"parser."+runtime.GOOS+"-"+runtime.GOARCH+".node",
	)
	_, errBin := os.Stat(filepath.Join(root, "plugins", "js-reachability", "dist", "commit0-js-reachability"))
	_, errSidecar := os.Stat(sidecar)
	return errBin == nil && errSidecar == nil
}

// TestJSScan_EmptyPkg_ZeroFindings scans the empty-pkg JS fixture and
// asserts:
//   - exit code 0 (no policy violation)
//   - stdout is valid SARIF JSON
//   - SARIF contains zero results (no findings from an empty package)
func TestJSScan_EmptyPkg_ZeroFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("JS scan E2E test requires compiled plugin; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	emptyPkgDir := filepath.Join(jsFixtureDir(t), "empty-pkg")

	stdout, stderr, code := runScanBinary(t,
		"scan",
		emptyPkgDir,
		"--language", "js",
		"--format", "sarif",
	)
	t.Logf("exit=%d stderr=%q", code, stderr)
	t.Logf("stdout=%s", stdout)

	require.Equal(t, 0, code, "empty JS package must exit 0 (no policy violation); stderr=%q", stderr)

	require.True(t, json.Valid([]byte(stdout)), "output must be valid SARIF JSON")

	// Parse just enough SARIF to assert zero results.
	var sarif struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &sarif), "SARIF must be decodable")
	require.NotEmpty(t, sarif.Runs, "SARIF must contain at least one run")
	assert.Empty(t, sarif.Runs[0].Results, "empty JS package must produce zero SARIF results")
}

// TestJSScan_Polyglot_JSOnly_ZeroFindings verifies that a polyglot directory
// (containing both go.mod and package.json) can be scanned in JS-only mode
// using --language js. It does NOT prove both plugins run concurrently; it
// exercises the detection path for a polyglot directory and ensures the JS
// plugin starts, completes, and exits 0 with zero findings from an empty
// package. A full both-plugins auto-mode E2E is covered at the detection layer
// by resolveLanguage tests in scan_test.go.
func TestJSScan_Polyglot_JSOnly_ZeroFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("JS scan E2E test requires compiled plugin; skipping in short mode")
	}
	if !jsPluginBuilt(t) {
		t.Skip("js-reachability dist not built; run 'make build-js-plugin' then re-run")
	}

	polyglotDir := filepath.Join(jsFixtureDir(t), "polyglot")

	// JS-only mode against the polyglot dir: must exit 0 and return valid SARIF.
	stdout, stderr, code := runScanBinary(t,
		"scan",
		polyglotDir,
		"--language", "js",
		"--format", "sarif",
	)
	t.Logf("js-only: exit=%d stderr=%q", code, stderr)
	t.Logf("js-only: stdout=%s", stdout)

	require.Equal(t, 0, code,
		"polyglot dir scanned with --language js must exit 0; stderr=%q", stderr)
	require.True(t, json.Valid([]byte(stdout)), "output must be valid SARIF JSON")

	var sarif struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &sarif))
	require.NotEmpty(t, sarif.Runs)
	assert.Empty(t, sarif.Runs[0].Results,
		"polyglot dir with no JS deps must produce zero SARIF results")
}
