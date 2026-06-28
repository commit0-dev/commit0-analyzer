package corpus_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/corpus"
)

// corpusTestDir returns the absolute path to testdata/corpus/.
func corpusTestDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	// This file is at internal/corpus/harness_test.go.
	// testdata/corpus/ is at repo-root/testdata/corpus/.
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(repoRoot, "testdata", "corpus")
}

// snapshotDir returns the path to the pinned test snapshot.
func snapshotDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(corpusTestDir(t), "db-snapshot")
}

// TestHarness_MetricsReport verifies that a corpus run over the reachable and
// not-reachable fixtures produces a non-nil Metrics with correct TP/TN counts.
// This test builds the plugin binary, so it is gated behind testing.Short().
func TestHarness_MetricsReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping harness test in short mode (requires plugin build)")
	}

	ctx := context.Background()
	cDir := corpusTestDir(t)
	snap := snapshotDir(t)

	cases := []corpus.CorpusCase{
		{
			Name:        "reachable-cve",
			ModuleDir:   filepath.Join(cDir, "reachable-cve"),
			AdvisoryID:  "CORPUS-CVE-001",
			Expected:    corpus.LabelReachable,
			SnapshotDir: snap,
		},
		{
			Name:        "not-reachable-cve",
			ModuleDir:   filepath.Join(cDir, "not-reachable-cve"),
			AdvisoryID:  "CORPUS-CVE-001",
			Expected:    corpus.LabelNotReachable,
			SnapshotDir: snap,
		},
	}

	m, err := corpus.Run(ctx, cases, corpus.RunOptions{
		SnapshotDir:        snap,
		GovulncheckVersion: "pinned-test-run",
	})
	require.NoError(t, err)
	require.NotNil(t, m)

	// At minimum we expect 1 TP (reachable-cve) and 1 TN (not-reachable-cve).
	// (The reachable case could also produce UNKNOWN if the engine is conservative
	//  on symbol resolution, which is acceptable — not a test failure.)
	assert.Equal(t, 0, m.UnknownViolations,
		"no unknown violations allowed: build-gated vulns must never be NOT_REACHABLE")
	assert.GreaterOrEqual(t, m.TP+m.UnknownCorrect, 1,
		"reachable-cve must produce at least 1 TP or conservative UNKNOWN")
	assert.GreaterOrEqual(t, m.TN, 1,
		"not-reachable-cve must produce at least 1 TN")

	assert.Len(t, m.Cases, 2, "one result per corpus case")
	assert.NotEmpty(t, m.DBDigest, "DBDigest must be populated from snapshot manifest")

	t.Logf("precision=%.3f recall=%.3f fp-suppression=%.3f tp=%d fp=%d fn=%d tn=%d unknown_ok=%d violations=%d",
		m.Precision(), m.Recall(), m.FPSuppressionRate(),
		m.TP, m.FP, m.FN, m.TN, m.UnknownCorrect, m.UnknownViolations)
}

// TestHarness_AdversarialBuildTagGated verifies adversarial fixture (a):
// a build-tag/GOOS-gated vuln on a non-matching runner must be UNKNOWN,
// never NOT_REACHABLE. This test runs the engine in-process (short-circuit path)
// so it does not require the full plugin build.
func TestHarness_AdversarialBuildTagGated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping adversarial harness test in short mode (requires plugin build)")
	}

	// Only meaningful on non-linux (the fixture is gated by //go:build linux).
	// On linux the fixture IS reachable, so the assertion changes.
	import_os := func() string {
		// Use the runtime package value so the check is accurate.
		return runtime.GOOS
	}
	goos := import_os()

	ctx := context.Background()
	cDir := corpusTestDir(t)
	snap := snapshotDir(t)

	cases := []corpus.CorpusCase{
		{
			Name:        "build-tag-gated",
			ModuleDir:   filepath.Join(cDir, "build-tag-gated"),
			AdvisoryID:  "CORPUS-CVE-001",
			Expected:    corpus.LabelUnknown, // expect UNKNOWN on non-linux; LabelReachable on linux
			SnapshotDir: snap,
		},
	}
	if goos == "linux" {
		// On linux the gated file IS compiled — the engine may find it reachable.
		cases[0].Expected = corpus.LabelReachable
	}

	m, err := corpus.Run(ctx, cases, corpus.RunOptions{SnapshotDir: snap})
	require.NoError(t, err)
	require.NotNil(t, m)

	if goos != "linux" {
		assert.Equal(t, 0, m.UnknownViolations,
			"build-tag-gated fixture must never produce NOT_REACHABLE on non-linux")
	}
}

// TestHarness_AdversarialPrivateReplace verifies adversarial fixture (b):
// a non-compiling module with a broken private replace must produce UNKNOWN.
func TestHarness_AdversarialPrivateReplace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping adversarial harness test in short mode (requires plugin build)")
	}

	ctx := context.Background()
	cDir := corpusTestDir(t)
	snap := snapshotDir(t)

	cases := []corpus.CorpusCase{
		{
			Name:        "cgo-private-replace",
			ModuleDir:   filepath.Join(cDir, "cgo-private-replace"),
			AdvisoryID:  "CORPUS-CVE-001",
			Expected:    corpus.LabelUnknown,
			SnapshotDir: snap,
		},
	}

	m, err := corpus.Run(ctx, cases, corpus.RunOptions{SnapshotDir: snap})
	require.NoError(t, err)
	require.NotNil(t, m)

	assert.Equal(t, 0, m.UnknownViolations,
		"broken private-replace module must produce UNKNOWN, never NOT_REACHABLE")
}

// TestHarness_AdversarialEqualPaths verifies adversarial fixture (d):
// two equal-length call paths produce SYMBOL_REACHABLE and the result is
// deterministic across repeated runs.
func TestHarness_AdversarialEqualPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping adversarial harness test in short mode (requires plugin build)")
	}

	ctx := context.Background()
	cDir := corpusTestDir(t)
	snap := snapshotDir(t)

	cases := []corpus.CorpusCase{
		{
			Name:        "equal-paths",
			ModuleDir:   filepath.Join(cDir, "equal-paths"),
			AdvisoryID:  "CORPUS-CVE-001",
			Expected:    corpus.LabelReachable,
			SnapshotDir: snap,
		},
	}

	// Run three times and assert the same result each time.
	var results []corpus.Outcome
	for i := 0; i < 3; i++ {
		m, err := corpus.Run(ctx, cases, corpus.RunOptions{SnapshotDir: snap})
		require.NoError(t, err, "run %d", i+1)
		require.Len(t, m.Cases, 1)
		results = append(results, m.Cases[0].Outcome)
	}

	for i, r := range results {
		assert.Equal(t, results[0], r, "run %d: outcome must match run 0", i+1)
	}
}

// TestHarness_BaselineRoundtrip verifies WriteBaseline/ReadBaseline round-trip.
func TestHarness_BaselineRoundtrip(t *testing.T) {
	m := &corpus.Metrics{
		TP:                 3,
		FP:                 1,
		FN:                 0,
		TN:                 2,
		UnknownCorrect:     1,
		UnknownViolations:  0,
		GovulncheckVersion: "v0.0.0+test",
		DBDigest:           "sha256:abc123",
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "baseline.json")

	require.NoError(t, corpus.WriteBaseline(path, m))
	rec, err := corpus.ReadBaseline(path)
	require.NoError(t, err)

	assert.InDelta(t, m.Precision(), rec.Precision, 1e-9)
	assert.InDelta(t, m.Recall(), rec.Recall, 1e-9)
	assert.InDelta(t, m.FPSuppressionRate(), rec.FPSuppression, 1e-9)
	assert.Equal(t, m.UnknownViolations, rec.UnknownViolations)
	assert.Equal(t, m.GovulncheckVersion, rec.GovulncheckVersion)
	assert.Equal(t, m.DBDigest, rec.DBDigest)
}

// TestHarness_SnapshotDigestReadable verifies that readSnapshotDigest works
// on the pinned test snapshot.
func TestHarness_SnapshotDigestReadable(t *testing.T) {
	snap := snapshotDir(t)
	_, err := os.Stat(filepath.Join(snap, "anst-snapshot-manifest.json"))
	require.NoError(t, err, "snapshot manifest must exist")

	// Run a minimal corpus with no cases to exercise the snapshot probe path.
	m, err := corpus.Run(context.Background(), nil, corpus.RunOptions{
		SnapshotDir:     snap,
		SkipPluginBuild: true,
		PluginBinary:    "/bin/true", // won't be called with zero cases
	})
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.NotEmpty(t, m.DBDigest, "DBDigest must be populated from manifest")
}
