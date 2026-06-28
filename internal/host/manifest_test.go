package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTempFile creates a regular file at dir/name with the given content and
// returns its absolute path. The file is 0755 (executable, not world-writable).
func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, content, 0o755))
	return p
}

// TestManifest_SingleArtifact_VerifiesClean checks that a manifest with no
// additional artifacts (the Go plugin shape) verifies clean when the primary
// binary hash matches.
func TestManifest_SingleArtifact_VerifiesClean(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/true\ngo-plugin-binary\n")
	bin := writeTempFile(t, dir, "go-reachability", content)

	hash, err := SHA256OfFile(bin)
	require.NoError(t, err)

	m := &Manifest{
		Name:     "go-reachability",
		ExecPath: bin,
		SHA256:   hash,
	}
	require.NoError(t, m.VerifyHash(), "single-artifact manifest with matching hash must verify clean")
}

// TestManifest_SingleArtifact_TamperedRejected checks that a tampered primary
// binary is rejected even with an empty additional artifacts list.
func TestManifest_SingleArtifact_TamperedRejected(t *testing.T) {
	dir := t.TempDir()
	bin := writeTempFile(t, dir, "go-reachability", []byte("original content"))

	hash, err := SHA256OfFile(bin)
	require.NoError(t, err)

	// Tamper the binary after hashing.
	require.NoError(t, os.WriteFile(bin, []byte("tampered content"), 0o755))

	m := &Manifest{
		Name:     "go-reachability",
		ExecPath: bin,
		SHA256:   hash,
	}
	require.Error(t, m.VerifyHash(), "tampered primary binary must be rejected")
}

// TestManifest_DualArtifact_BothMatch verifies that a manifest with a primary
// binary and one additional sidecar artifact verifies clean when both hashes match.
func TestManifest_DualArtifact_BothMatch(t *testing.T) {
	dir := t.TempDir()
	mainContent := []byte("#!/bin/true\njs-plugin-main\n")
	sidecarContent := []byte("\x7fELF napi-sidecar-content\n")

	mainBin := writeTempFile(t, dir, "commit0-js-reachability", mainContent)
	sidecarPath := writeTempFile(t, dir, "parser.darwin-arm64.node", sidecarContent)

	mainHash, err := SHA256OfFile(mainBin)
	require.NoError(t, err)
	sidecarHash, err := SHA256OfFile(sidecarPath)
	require.NoError(t, err)

	m := &Manifest{
		Name:     "js-reachability",
		ExecPath: mainBin,
		SHA256:   mainHash,
		AdditionalArtifacts: []ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}
	require.NoError(t, m.VerifyHash(), "dual-artifact manifest with matching hashes must verify clean")
}

// TestManifest_DualArtifact_TamperedSidecarRejected verifies that tampering the
// sidecar artifact causes VerifyHash to return an error even when the primary
// binary hash is correct.
func TestManifest_DualArtifact_TamperedSidecarRejected(t *testing.T) {
	dir := t.TempDir()
	mainBin := writeTempFile(t, dir, "commit0-js-reachability", []byte("main-binary-content"))
	sidecarPath := writeTempFile(t, dir, "parser.darwin-arm64.node", []byte("original-sidecar"))

	mainHash, err := SHA256OfFile(mainBin)
	require.NoError(t, err)
	sidecarHash, err := SHA256OfFile(sidecarPath)
	require.NoError(t, err)

	// Tamper the sidecar after recording its hash.
	require.NoError(t, os.WriteFile(sidecarPath, []byte("tampered-sidecar"), 0o755))

	m := &Manifest{
		Name:     "js-reachability",
		ExecPath: mainBin,
		SHA256:   mainHash,
		AdditionalArtifacts: []ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}
	require.Error(t, m.VerifyHash(), "tampered sidecar must be rejected")
}

// TestManifest_DualArtifact_TamperedMainRejected verifies that tampering the
// primary binary is still caught even when the sidecar is intact.
func TestManifest_DualArtifact_TamperedMainRejected(t *testing.T) {
	dir := t.TempDir()
	mainBin := writeTempFile(t, dir, "commit0-js-reachability", []byte("original-main-content"))
	sidecarPath := writeTempFile(t, dir, "parser.darwin-arm64.node", []byte("sidecar-content"))

	mainHash, err := SHA256OfFile(mainBin)
	require.NoError(t, err)
	sidecarHash, err := SHA256OfFile(sidecarPath)
	require.NoError(t, err)

	// Tamper only the main binary.
	require.NoError(t, os.WriteFile(mainBin, []byte("tampered-main-content"), 0o755))

	m := &Manifest{
		Name:     "js-reachability",
		ExecPath: mainBin,
		SHA256:   mainHash,
		AdditionalArtifacts: []ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}
	require.Error(t, m.VerifyHash(), "tampered primary binary must be rejected even with intact sidecar")
}

// TestManifest_EmptySHA256_Skips verifies the test-only escape hatch: an empty
// SHA256 on the primary skips all hash verification (including additional artifacts).
func TestManifest_EmptySHA256_Skips(t *testing.T) {
	dir := t.TempDir()
	mainBin := writeTempFile(t, dir, "commit0-js-reachability", []byte("any-content"))
	sidecarPath := writeTempFile(t, dir, "parser.node", []byte("any-sidecar"))

	m := &Manifest{
		Name:     "js-reachability",
		ExecPath: mainBin,
		SHA256:   "", // empty → skip (test-only escape hatch)
		AdditionalArtifacts: []ArtifactPin{
			{Path: sidecarPath, SHA256: "deliberately-wrong-hash"},
		},
	}
	// When primary SHA256 is empty, the whole check is skipped.
	require.NoError(t, m.VerifyHash(), "empty primary SHA256 must skip all hash checks")
}
