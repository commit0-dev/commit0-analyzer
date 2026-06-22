package host_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/internal/host"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// TestJSPlugin_CrashIsolation_SyntheticUnknown verifies that when the JS plugin
// crashes before sending any findings (simulated by the Go testplugin in crash
// mode, registered under a JS plugin name), the host:
//   - Does NOT return a Run-level error (crash isolation).
//   - Returns a PluginResult with Err set.
//   - Appends a synthetic CONFIDENCE_UNKNOWN finding so coverage is never
//     silently dropped ("unknown ≠ safe" plan invariant).
//
// The crash-isolation path in host.Run is language-agnostic (it handles any
// plugin subprocess error identically), so using the Go testplugin as a stand-in
// for the JS plugin is correct and does not require the JS binary to be built.
func TestJSPlugin_CrashIsolation_SyntheticUnknown(t *testing.T) {
	if pluginBinPath == "" {
		t.Skip("testplugin not built (TestMain not run)")
	}

	// Register the testplugin under a JS-plugin name with crash mode.
	t.Setenv("TESTPLUGIN_MODE", "crash")

	reg := host.NewRegistry()
	require.NoError(t, reg.Add(&host.Manifest{
		Name:      "js-reachability-crash",
		ExecPath:  pluginBinPath,
		Pillar:    "sca",
		Languages: []string{"js", "ts"},
	}), "registry must accept testplugin manifest")

	ctx := context.Background()
	results, runErr := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})

	// Run itself must not return an error — crash isolation.
	require.NoError(t, runErr,
		"host.Run must not return a top-level error when a plugin crashes (crash isolation)")

	require.Len(t, results, 1, "one PluginResult expected for one registered plugin")
	r := results[0]

	// The PluginResult must carry a non-nil Err.
	require.Error(t, r.Err,
		"PluginResult.Err must be set when the plugin crashes")

	// A synthetic UNKNOWN finding must be present so coverage is not silently dropped.
	assertHasSyntheticUnknown(t, r.Findings)
	assert.Equal(t, "js-reachability-crash", r.Manifest.Name,
		"PluginResult.Manifest.Name must match the registered plugin name")
}

// TestJSPlugin_CrashIsolation_WithRealBinary_TamperedLaunch verifies crash
// isolation through the full launch path using a tampered real binary.
// When the JS binary is available, this test copies it, flips a byte, then
// verifies that Run returns a PluginResult with Err set (not a Run-level error)
// and a synthetic UNKNOWN finding.
//
// Skipped when the JS plugin has not been built.
func TestJSPlugin_CrashIsolation_WithRealBinary_TamperedLaunch(t *testing.T) {
	if testing.Short() {
		t.Skip("JS crash-isolation test with real binary skipped in short mode")
	}

	distDir := jsDistDir(t)
	if distDir == "" {
		t.Skip("cannot locate js-reachability dist directory; skipping")
	}

	mainBin := filepath.Join(distDir, "anst-js-reachability")
	if _, err := os.Stat(mainBin); err != nil {
		t.Skipf("js-reachability binary not built (run 'make build-js-plugin'): %v", err)
	}

	// Copy the real binary to a temp dir so we can corrupt it without affecting
	// the real dist.
	tmpDir := t.TempDir()
	corruptBin := filepath.Join(tmpDir, "anst-js-reachability-corrupt")
	data, err := os.ReadFile(mainBin)
	require.NoError(t, err, "read real JS binary")
	require.NotEmpty(t, data, "JS binary must not be empty")

	// Flip the first byte to corrupt the binary — the OS will refuse to exec it.
	corrupt := make([]byte, len(data))
	copy(corrupt, data)
	corrupt[0] ^= 0xFF
	require.NoError(t, os.WriteFile(corruptBin, corrupt, 0o755))

	m := &host.Manifest{
		Name:      "js-reachability-corrupt",
		ExecPath:  corruptBin,
		Pillar:    "sca",
		Languages: []string{"js", "ts"},
	}

	reg := host.NewRegistry()
	require.NoError(t, reg.Add(m))

	ctx := context.Background()
	results, runErr := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})

	require.NoError(t, runErr,
		"host.Run must not return a top-level error on corrupt-binary launch failure")
	require.Len(t, results, 1)

	r := results[0]
	require.Error(t, r.Err,
		"PluginResult.Err must be set when the JS binary cannot be exec'd")

	// Synthetic UNKNOWN must mark the gap in coverage.
	assertHasSyntheticUnknown(t, r.Findings)
}

// TestJSPlugin_CrashIsolation_PartialFindings_ViaTestPlugin verifies that when
// a plugin crashes mid-stream the host correctly signals scan incompleteness:
// PluginResult.Err is set and a synthetic CONFIDENCE_UNKNOWN finding is appended.
// This uses the Go testplugin in crash mode as a stand-in for any plugin (the
// crash-isolation path in host.Run is language-agnostic).
//
// The testplugin in crash mode calls stream.Send(finding) then os.Exit(1). Whether
// the pre-crash finding survives is inherently racy: the host's stream.Recv() may
// receive it before the crash error surfaces (if gRPC flushes in time) or may not
// (if the process exits before the write buffer drains). The run.go drain loop at
// line "partial findings already collected remain" handles the case where Recv()
// succeeds before the crash, but we cannot guarantee it in a deterministic test.
// We assert the invariants that ARE deterministic: Err is set and UNKNOWN is present.
// The partial-findings-preserved path is exercised by the drain loop in run.go and
// is verifiable via integration (the pre-crash finding appears in some runs).
//
// This test reuses the testplugin infrastructure already available in the
// host_test package, so it does not require the JS binary to be built.
func TestJSPlugin_CrashIsolation_PartialFindings_ViaTestPlugin(t *testing.T) {
	// This test uses testplugin which is built in TestMain (same package).
	if pluginBinPath == "" {
		t.Skip("testplugin not built (TestMain not run)")
	}

	// TESTPLUGIN_MODE=crash causes the plugin to emit one finding and then exit.
	t.Setenv("TESTPLUGIN_MODE", "crash")

	// Register the testplugin as if it were the JS plugin to exercise the
	// language-agnostic crash-isolation code path.
	reg := host.NewRegistry()
	require.NoError(t, reg.Add(&host.Manifest{
		Name:      "js-reachability-simulated-crash",
		ExecPath:  pluginBinPath,
		Pillar:    "sca",
		Languages: []string{"js", "ts"},
	}))

	ctx := context.Background()
	results, runErr := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})

	require.NoError(t, runErr,
		"host.Run must not return a top-level error on mid-stream crash (crash isolation)")
	require.Len(t, results, 1)

	r := results[0]
	require.Error(t, r.Err,
		"PluginResult.Err must be set after a mid-stream crash")

	// Synthetic UNKNOWN must be present — coverage must not be silently dropped.
	assertHasSyntheticUnknown(t, r.Findings)

	// Scan must be marked incomplete: the caller (CLI) checks r.Err and sets
	// incomplete=true. The policy gate then exits 3. We verify the invariant at
	// the host level: Err is non-nil so the CLI will set incomplete.
	assert.NotNil(t, r.Err,
		"non-nil Err signals the caller to mark scan incomplete (→ exit 3 via policy gate)")

	// Best-effort check: if the pre-crash finding (GO-TEST-0000) was received
	// before the crash error surfaced, it must be present in Findings.
	// This is not asserted as a hard requirement because gRPC buffer flush timing
	// after os.Exit(1) is nondeterministic in the testplugin crash scenario.
	for _, f := range r.Findings {
		if f.GetAdvisory().GetId() == "GO-TEST-0000" {
			// Pre-crash finding arrived — verify its index property.
			assert.Equal(t, "0", f.GetProperties()["index"],
				"pre-crash finding must have index=0")
			break
		}
	}
}
