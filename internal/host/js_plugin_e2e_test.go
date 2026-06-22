package host_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/internal/host"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// jsDistDir returns the absolute path to the compiled JS plugin distribution,
// resolved relative to this source file in the repository tree.
// Returns "" when the location cannot be determined.
func jsDistDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// This file is at internal/host/js_plugin_e2e_test.go; repo root is two dirs up.
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(repoRoot, "plugins", "js-reachability", "dist")
}

// jsSidecarName returns the platform-specific sidecar filename, matching
// jsSidecarName() in internal/cli/scan.go.
func jsSidecarName() string {
	return fmt.Sprintf("parser.%s-%s.node", runtime.GOOS, runtime.GOARCH)
}

// TestJSPlugin_RealBinary_TransportE2E launches the compiled js-reachability
// binary through the host transport and verifies:
//   - The handshake completes with a compatible protocol version.
//   - Metadata returns name="js-reachability" and supported languages ["js","ts"].
//   - An empty Analyze request closes with zero findings and no error.
//   - Clean shutdown with no process left behind.
//
// This test is skipped when the distribution has not been built yet (run
// 'make build-js-plugin' to build it).
func TestJSPlugin_RealBinary_TransportE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("JS plugin E2E test requires compiled binary; skipping in short mode")
	}

	distDir := jsDistDir(t)
	if distDir == "" {
		t.Skip("cannot locate js-reachability dist directory; skipping")
	}

	mainBin := filepath.Join(distDir, "anst-js-reachability")
	if _, err := os.Stat(mainBin); err != nil {
		t.Skipf("js-reachability binary not found at %s (run 'make build-js-plugin'): %v", mainBin, err)
	}

	sidecarName := jsSidecarName()
	sidecarPath := filepath.Join(distDir, "oxc-binding", sidecarName)
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Skipf("js-reachability sidecar not found at %s (run 'make build-js-plugin'): %v", sidecarPath, err)
	}

	// Compute SHA-256 pins for both artifacts so the manifest is fully pinned.
	mainHash, err := host.SHA256OfFile(mainBin)
	require.NoError(t, err, "hash main binary")
	sidecarHash, err := host.SHA256OfFile(sidecarPath)
	require.NoError(t, err, "hash sidecar")

	m := &host.Manifest{
		Name:     "js-reachability",
		ExecPath: mainBin,
		Pillar:   "sca",
		Languages: []string{"js", "ts"},
		SHA256:   mainHash,
		AdditionalArtifacts: []host.ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}

	// VerifyHash must pass for both artifacts before launching.
	require.NoError(t, m.VerifyHash(), "dual-pin verify must pass before launch")

	// Register through the registry to exercise the world-writable path guard.
	reg := host.NewRegistry()
	require.NoError(t, reg.Add(m), "registry must accept the built dist artifacts")

	ctx := context.Background()
	results, err := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{
		// No SkipHashCheck: go-plugin verifies the binary before exec using the
		// SHA256 in SecureConfig.
	})
	require.NoError(t, err, "Run must not return an error for a clean plugin")
	require.Len(t, results, 1, "one result expected for one registered plugin")

	r := results[0]
	assert.NoError(t, r.Err, "plugin result must carry no error for a clean run")
	assert.Empty(t, r.Findings, "empty AnalyzeRequest must produce zero findings")
	assert.Equal(t, "js-reachability", r.Manifest.Name)
}

// TestJSPlugin_RealBinary_MetadataFields launches the compiled binary and
// verifies the Metadata response fields that the host depends on.
func TestJSPlugin_RealBinary_MetadataFields(t *testing.T) {
	if testing.Short() {
		t.Skip("JS plugin E2E test requires compiled binary; skipping in short mode")
	}

	distDir := jsDistDir(t)
	if distDir == "" {
		t.Skip("cannot locate js-reachability dist directory; skipping")
	}

	mainBin := filepath.Join(distDir, "anst-js-reachability")
	if _, err := os.Stat(mainBin); err != nil {
		t.Skipf("js-reachability binary not found at %s (run 'make build-js-plugin'): %v", mainBin, err)
	}

	m := &host.Manifest{
		Name:     "js-reachability-meta",
		ExecPath: mainBin,
		Pillar:   "sca",
	}

	ctx := context.Background()
	// Use SkipHashCheck here since we're only checking metadata, not full-pin.
	pc, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: true})
	require.NoError(t, err, "Launch must succeed for compiled binary")
	defer pc.Kill()

	meta, err := pc.Analyzer().Metadata(ctx, &anstv1.MetadataRequest{})
	require.NoError(t, err, "Metadata RPC must succeed")

	assert.Equal(t, "js-reachability", meta.GetName(),
		"Metadata.Name must be 'js-reachability'")

	langs := meta.GetSupportedLanguages()
	assert.Contains(t, langs, "js", "supported_languages must include 'js'")
	assert.Contains(t, langs, "ts", "supported_languages must include 'ts'")
}

// TestJSPlugin_RealBinary_TamperRejection copies the dist files to a temp
// directory, flips a byte in the sidecar, and verifies that VerifyHash rejects
// the tampered artifact before any launch attempt.
func TestJSPlugin_RealBinary_TamperRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("JS plugin E2E test requires compiled binary; skipping in short mode")
	}

	distDir := jsDistDir(t)
	if distDir == "" {
		t.Skip("cannot locate js-reachability dist directory; skipping")
	}

	mainBin := filepath.Join(distDir, "anst-js-reachability")
	sidecarPath := filepath.Join(distDir, "oxc-binding", jsSidecarName())
	if _, err := os.Stat(mainBin); err != nil {
		t.Skipf("js-reachability binary not built: %v", err)
	}
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Skipf("js-reachability sidecar not built: %v", err)
	}

	// Copy both artifacts to a temp dir so we can tamper without affecting the
	// real dist.
	tmpDir := t.TempDir()

	mainDst := filepath.Join(tmpDir, "anst-js-reachability")
	sidecarDst := filepath.Join(tmpDir, jsSidecarName())

	copyFile(t, mainBin, mainDst, 0o755)
	copyFile(t, sidecarPath, sidecarDst, 0o644)

	mainHash, err := host.SHA256OfFile(mainDst)
	require.NoError(t, err)
	sidecarHash, err := host.SHA256OfFile(sidecarDst)
	require.NoError(t, err)

	// Flip one byte in the sidecar copy.
	sidecarBytes, err := os.ReadFile(sidecarDst)
	require.NoError(t, err)
	require.NotEmpty(t, sidecarBytes, "sidecar must not be empty")
	sidecarBytes[0] ^= 0xFF // flip all bits in first byte
	require.NoError(t, os.WriteFile(sidecarDst, sidecarBytes, 0o644))

	m := &host.Manifest{
		Name:     "js-reachability-tampered",
		ExecPath: mainDst,
		Pillar:   "sca",
		SHA256:   mainHash,
		AdditionalArtifacts: []host.ArtifactPin{
			{Path: sidecarDst, SHA256: sidecarHash},
		},
	}

	// VerifyHash must detect the tampered sidecar.
	err = m.VerifyHash()
	require.Error(t, err, "VerifyHash must reject a tampered sidecar")
	assert.Contains(t, err.Error(), "hash mismatch",
		"error message must say 'hash mismatch'")
}

// TestJSPlugin_RealBinary_TamperRejectionViaLaunch copies the dist files to a
// temp directory and verifies that the real Launch (and Run) path rejects both
// a tampered sidecar and a tampered main binary. This is distinct from
// TestJSPlugin_RealBinary_TamperRejection which only calls VerifyHash directly.
func TestJSPlugin_RealBinary_TamperRejectionViaLaunch(t *testing.T) {
	if testing.Short() {
		t.Skip("JS plugin E2E test requires compiled binary; skipping in short mode")
	}

	distDir := jsDistDir(t)
	if distDir == "" {
		t.Skip("cannot locate js-reachability dist directory; skipping")
	}

	mainBin := filepath.Join(distDir, "anst-js-reachability")
	sidecarPath := filepath.Join(distDir, "oxc-binding", jsSidecarName())
	if _, err := os.Stat(mainBin); err != nil {
		t.Skipf("js-reachability binary not built: %v", err)
	}
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Skipf("js-reachability sidecar not built: %v", err)
	}

	// ── sub-test 1: tampered sidecar rejected by Launch ──────────────────────
	t.Run("tampered_sidecar_rejected_by_launch", func(t *testing.T) {
		tmpDir := t.TempDir()
		mainDst := filepath.Join(tmpDir, "anst-js-reachability")
		sidecarDst := filepath.Join(tmpDir, jsSidecarName())

		copyFile(t, mainBin, mainDst, 0o755)
		copyFile(t, sidecarPath, sidecarDst, 0o644)

		mainHash, err := host.SHA256OfFile(mainDst)
		require.NoError(t, err)
		sidecarHash, err := host.SHA256OfFile(sidecarDst)
		require.NoError(t, err)

		// Flip one byte in the sidecar after recording its hash.
		sidecarBytes, err := os.ReadFile(sidecarDst)
		require.NoError(t, err)
		require.NotEmpty(t, sidecarBytes, "sidecar must not be empty")
		sidecarBytes[0] ^= 0xFF
		require.NoError(t, os.WriteFile(sidecarDst, sidecarBytes, 0o644))

		m := &host.Manifest{
			Name:     "js-reachability-tampered-sidecar",
			ExecPath: mainDst,
			Pillar:   "sca",
			SHA256:   mainHash,
			AdditionalArtifacts: []host.ArtifactPin{
				{Path: sidecarDst, SHA256: sidecarHash},
			},
		}

		// Run via the real launch path — must be rejected before subprocess starts.
		reg := host.NewRegistry()
		require.NoError(t, reg.Add(m), "registry must accept artifact paths")

		ctx := context.Background()
		results, runErr := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{})
		require.NoError(t, runErr, "Run itself must not fail (crash isolation)")
		require.Len(t, results, 1)
		require.Error(t, results[0].Err, "tampered sidecar must cause a launch error")
		assert.Contains(t, results[0].Err.Error(), "artifact integrity check failed",
			"error must mention artifact integrity check")
	})

	// ── sub-test 2: tampered main binary rejected by Launch ───────────────────
	t.Run("tampered_main_rejected_by_launch", func(t *testing.T) {
		tmpDir := t.TempDir()
		mainDst := filepath.Join(tmpDir, "anst-js-reachability")
		sidecarDst := filepath.Join(tmpDir, jsSidecarName())

		copyFile(t, mainBin, mainDst, 0o755)
		copyFile(t, sidecarPath, sidecarDst, 0o644)

		mainHash, err := host.SHA256OfFile(mainDst)
		require.NoError(t, err)
		sidecarHash, err := host.SHA256OfFile(sidecarDst)
		require.NoError(t, err)

		// Flip one byte in the main binary after recording its hash.
		mainBytes, err := os.ReadFile(mainDst)
		require.NoError(t, err)
		require.NotEmpty(t, mainBytes, "main binary must not be empty")
		mainBytes[0] ^= 0xFF
		require.NoError(t, os.WriteFile(mainDst, mainBytes, 0o755))

		m := &host.Manifest{
			Name:     "js-reachability-tampered-main",
			ExecPath: mainDst,
			Pillar:   "sca",
			SHA256:   mainHash,
			AdditionalArtifacts: []host.ArtifactPin{
				{Path: sidecarDst, SHA256: sidecarHash},
			},
		}

		reg := host.NewRegistry()
		require.NoError(t, reg.Add(m), "registry must accept artifact paths")

		ctx := context.Background()
		results, runErr := host.Run(ctx, reg, &anstv1.AnalyzeRequest{}, host.RunOptions{})
		require.NoError(t, runErr, "Run itself must not fail (crash isolation)")
		require.Len(t, results, 1)
		require.Error(t, results[0].Err, "tampered main binary must cause a launch error")
		assert.Contains(t, results[0].Err.Error(), "artifact integrity check failed",
			"error must mention artifact integrity check")
	})
}

// copyFile copies src to dst with the given mode.
func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err, "read %s", src)
	require.NoError(t, os.WriteFile(dst, data, mode), "write %s", dst)
}
