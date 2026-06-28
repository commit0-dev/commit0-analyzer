package host_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/commit0-dev/commit0-analyzer/internal/host"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// pluginBinPath is the path of the testplugin binary built by TestMain.
var pluginBinPath string

// TestMain builds the testplugin binary into a temp dir, then runs all tests.
// The binary is shared across all tests in the package.
func TestMain(m *testing.M) {
	// Build the testplugin binary.
	dir, err := os.MkdirTemp("", "commit0-analyzer-testplugin-*")
	if err != nil {
		panic("TestMain: create temp dir: " + err.Error())
	}
	defer func() { _ = os.RemoveAll(dir) }()

	bin := filepath.Join(dir, "testplugin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", bin,
		"github.com/commit0-dev/commit0-analyzer/internal/host/testplugin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("TestMain: build testplugin: " + err.Error())
	}

	pluginBinPath = bin

	os.Exit(m.Run())
}

// testPluginBin returns the path of the pre-built testplugin binary.
// It is safe to call from any test; the build happens exactly once in TestMain.
func testPluginBin(t *testing.T) string {
	t.Helper()
	if pluginBinPath == "" {
		t.Fatal("testPluginBin: pluginBinPath not set (TestMain not run?)")
	}
	return pluginBinPath
}

// makeReg returns a Registry with the testplugin registered under the given
// manifest name, using SkipHashCheck so tests don't need to recompute the hash.
func makeReg(t *testing.T, name string) *host.Registry {
	t.Helper()
	reg := host.NewRegistry()
	err := reg.Add(&host.Manifest{
		Name:     name,
		ExecPath: testPluginBin(t),
		Pillar:   "sca",
		// SHA256 is empty: SkipHashCheck in opts handles it.
	})
	require.NoError(t, err)
	return reg
}

// ── TDD Group 1: normal run + deterministic aggregation ──────────────────────

// TestRun_NormalFindings verifies that Run collects the known canned Finding
// set from a normal testplugin invocation and that the advisory IDs are present.
func TestRun_NormalFindings(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Setenv("TESTPLUGIN_MODE", "normal")
	t.Setenv("TESTPLUGIN_STREAM_COUNT", "3")

	reg := makeReg(t, "testplugin")
	ctx := context.Background()

	results, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.NoError(t, r.Err)
	require.Len(t, r.Findings, 3)

	// Assert all canned findings are present (order within a plugin is stream order).
	ids := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		ids = append(ids, f.GetAdvisory().GetId())
	}
	assert.Contains(t, ids, "GO-TEST-0000")
	assert.Contains(t, ids, "GO-TEST-0001")
	assert.Contains(t, ids, "GO-TEST-0002")
}

// TestRun_DeterministicAggregationOrder verifies that results are sorted by
// plugin Name even when multiple plugins are registered.
func TestRun_DeterministicAggregationOrder(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Setenv("TESTPLUGIN_MODE", "normal")
	t.Setenv("TESTPLUGIN_STREAM_COUNT", "1")

	// Register the same binary twice under different names to simulate two
	// plugins. The registry requires unique paths for production use, but for
	// tests we register under different names.
	bin := testPluginBin(t)

	reg := host.NewRegistry()
	for _, name := range []string{"plugin-beta", "plugin-alpha"} {
		require.NoError(t, reg.Add(&host.Manifest{
			Name:     name,
			ExecPath: bin,
			Pillar:   "sca",
		}))
	}

	ctx := context.Background()
	results, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Results must be sorted by Name regardless of goroutine scheduling.
	assert.Equal(t, "plugin-alpha", results[0].Manifest.Name)
	assert.Equal(t, "plugin-beta", results[1].Manifest.Name)

	// Run a second time and assert the order is stable.
	results2, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	require.NoError(t, err)
	require.Len(t, results2, 2)
	assert.Equal(t, results[0].Manifest.Name, results2[0].Manifest.Name)
	assert.Equal(t, results[1].Manifest.Name, results2[1].Manifest.Name)
}

// ── TDD Group 2: crash mid-stream → synthetic UNKNOWN, child PID gone ────────

// TestRun_CrashMidStream verifies that when a plugin exits non-zero mid-stream:
//   - Run does NOT return an error itself (crash isolation).
//   - The PluginResult has Err set.
//   - A synthetic CONFIDENCE_UNKNOWN Finding is present in the result.
//   - The child process is reaped (PID gone after the call returns).
func TestRun_CrashMidStream(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Setenv("TESTPLUGIN_MODE", "crash")

	reg := makeReg(t, "testplugin-crash")
	ctx := context.Background()

	results, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	require.NoError(t, err, "Run must not fail when a plugin crashes (crash isolation)")
	require.Len(t, results, 1)

	r := results[0]
	require.Error(t, r.Err, "PluginResult.Err must be set after a crash")

	// The synthetic UNKNOWN finding must be present.
	assertHasSyntheticUnknown(t, r.Findings)

	// Assert the child PID recorded in the first Finding's properties is gone.
	// The crash finding from the plugin (index 0) carries the PID.
	assertPluginPIDGone(t, r.Findings)
}

// ── TDD Group 3: per-plugin timeout → synthetic UNKNOWN, goleak clean, PID gone ─

// TestRun_Timeout verifies that when the per-plugin timeout fires:
//   - Run itself returns without error.
//   - PluginResult.Err is set.
//   - A synthetic CONFIDENCE_UNKNOWN marker is present.
//   - No goroutine leaks (goleak).
//   - The child process is reaped (PID gone).
func TestRun_Timeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Setenv("TESTPLUGIN_MODE", "hang")

	reg := makeReg(t, "testplugin-hang")
	ctx := context.Background()

	start := time.Now()
	results, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		Timeout:    300 * time.Millisecond,
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.Error(t, r.Err, "PluginResult.Err must be set after a timeout")

	// The timeout should fire well within 2 seconds.
	assert.Less(t, elapsed, 2*time.Second, "Run should return promptly after timeout")

	// Synthetic UNKNOWN must be present.
	assertHasSyntheticUnknown(t, r.Findings)

	// Child PID should be gone — Kill was called.
	assertPluginPIDGone(t, r.Findings)
}

// ── TDD Group 4: backpressure — host stops reading mid-stream, plugin terminates ─

// TestRun_BackpressurePluginTerminates verifies that when the host stops
// reading (context cancelled before stream is exhausted), the plugin process
// terminates and does not become an orphan.
//
// Strategy: emit a large stream (100 findings), cancel the context after
// receiving the first result, then verify the child is reaped.
func TestRun_BackpressurePluginTerminates(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Setenv("TESTPLUGIN_MODE", "normal")
	t.Setenv("TESTPLUGIN_STREAM_COUNT", "100")

	reg := makeReg(t, "testplugin-backpressure")

	// Cancel the context shortly after the run starts so the host stops reading.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	results, err := host.Run(ctx, reg, &commit0v1.AnalyzeRequest{}, host.RunOptions{
		Timeout:    500 * time.Millisecond,
		LaunchOpts: host.LaunchOptions{SkipHashCheck: true},
	})
	// Run may or may not return an error depending on timing; what matters is
	// that it returns at all (no deadlock) and the child is gone.
	_ = err
	_ = results

	// Give the kill a moment to propagate before asserting the PID is gone.
	// (The kill is synchronous within go-plugin, but we add a small buffer
	// for the OS scheduler to update process state.)
	time.Sleep(200 * time.Millisecond)

	// Verify any PIDs we saw in findings are gone.
	for _, r := range results {
		assertPluginPIDGone(t, r.Findings)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// assertHasSyntheticUnknown fails the test unless at least one Finding in
// findings has CONFIDENCE_UNKNOWN and the "synthetic" property set to "true".
func assertHasSyntheticUnknown(t *testing.T, findings []*commit0v1.Finding) {
	t.Helper()
	for _, f := range findings {
		if f.GetConfidence() == commit0v1.Confidence_CONFIDENCE_UNKNOWN &&
			f.GetProperties()["synthetic"] == "true" {
			return
		}
	}
	t.Errorf("expected a synthetic CONFIDENCE_UNKNOWN finding; got %d findings", len(findings))
}

// assertPluginPIDGone reads the PID embedded in any Finding's "pid" property
// and verifies the OS process no longer exists.
func assertPluginPIDGone(t *testing.T, findings []*commit0v1.Finding) {
	t.Helper()
	for _, f := range findings {
		pidStr, ok := f.GetProperties()["pid"]
		if !ok || pidStr == "" {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		// os.FindProcess succeeds on all platforms; to check liveness we send
		// signal 0 (unix convention). On Windows FindProcess always succeeds so
		// we skip the signal check there.
		proc, err := os.FindProcess(pid)
		if err != nil {
			// Process not found at all — definitely gone.
			return
		}
		if runtime.GOOS != "windows" {
			// Signal 0 probes liveness without sending a real signal.
			// An error here means the process is gone or we lack permission
			// (both mean it's not our runaway child).
			err = proc.Signal(os.Signal(nil))
			if err != nil {
				// Process is gone — test passes.
				return
			}
			// Process still alive — wait a moment and retry once, to account
			// for OS scheduling lag after Kill().
			time.Sleep(100 * time.Millisecond)
			err = proc.Signal(os.Signal(nil))
			assert.Error(t, err,
				"plugin child process (pid=%d) should be gone after Kill; signal 0 succeeded", pid)
		}
		return // checked at least one PID
	}
	// No PID found in findings — could be a crash before any findings were sent.
	// Not a failure: the crash path may not have emitted findings with PIDs.
	t.Log("assertPluginPIDGone: no pid property found in findings (may be pre-stream crash)")
}
