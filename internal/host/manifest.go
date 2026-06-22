package host

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ArtifactPin holds the path and expected SHA-256 digest of a plugin artifact
// beyond the primary executable (e.g. a native napi sidecar .node file).
// Both Path and SHA256 must be set; an empty SHA256 is only valid when the
// parent Manifest's SHA256 is also empty (test-only escape hatch).
type ArtifactPin struct {
	// Path is the absolute path to the artifact file.
	Path string

	// SHA256 is the expected lowercase hex-encoded SHA-256 digest of the file.
	SHA256 string
}

// Manifest describes a single plugin binary that the host is allowed to load.
// It is the unit of configuration for the plugin allowlist: only binaries
// explicitly listed here (with matching path + hash) will be launched.
//
// Security: two checks gate execution:
//  1. Path allowlist  – the file must be at a known, non-world-writable location.
//  2. Hash pinning    – the binary must match the expected content hash exactly.
//
// Either check failing causes the plugin to be refused before execution.
//
// Caveat (MVP): in the default flow the host builds the plugin itself and hashes
// the artifact it just produced (see internal/cli buildPlugin), so the SHA-256
// only closes the TOCTOU window between hashing and exec — it is NOT a
// supply-chain integrity guarantee. Genuine pinning requires an expected hash
// obtained out-of-band from a trusted source (roadmap).
type Manifest struct {
	// Name is a human-readable identifier for this plugin (e.g. "go-reachability").
	// Used in log messages, synthetic findings, and the self-test scope label.
	Name string

	// ExecPath is the absolute path to the plugin binary.
	ExecPath string

	// Pillar is the security pillar this plugin covers (e.g. "sca", "sast", "secrets").
	// Stamped onto every Finding emitted by this plugin so the host can fan-out
	// across multiple pillars without ambiguity.
	Pillar string

	// Languages is the set of language tags this plugin handles (e.g. ["go"]).
	// Reserved for multi-plugin language routing; the single-plugin MVP fans out
	// to every registered plugin and does not yet filter on this field.
	Languages []string

	// SHA256 is the expected lowercase hex-encoded SHA-256 digest of the plugin
	// binary. go-plugin's SecureConfig uses this to reject tampered binaries.
	// Leave empty only in tests that explicitly opt out of hash checking.
	SHA256 string

	// AdditionalArtifacts lists extra files that must be present and hash-verified
	// alongside the primary binary (e.g. a native napi sidecar .node file).
	// A single-file plugin (e.g. the Go plugin) leaves this nil or empty.
	// VerifyHash checks each entry; the registry's world-writable guard applies
	// to each path as well.
	AdditionalArtifacts []ArtifactPin
}

// VerifyHash reads the plugin binary at m.ExecPath and returns an error if its
// SHA-256 digest does not match m.SHA256. An empty m.SHA256 skips the check
// (test-only escape hatch — production manifests must always set the hash).
// When AdditionalArtifacts is non-empty, each artifact's hash is also verified.
func (m *Manifest) VerifyHash() error {
	if m.SHA256 == "" {
		return nil // caller opted out (tests only)
	}

	if err := verifyFileHash(m.ExecPath, m.SHA256, fmt.Sprintf("manifest %s: binary", m.Name)); err != nil {
		return err
	}

	for i, a := range m.AdditionalArtifacts {
		label := fmt.Sprintf("manifest %s: artifact[%d] %s", m.Name, i, a.Path)
		if err := verifyFileHash(a.Path, a.SHA256, label); err != nil {
			return err
		}
	}
	return nil
}

// verifyFileHash opens path, computes its SHA-256, and returns an error if it
// does not match want. label is used in the error message for context.
func verifyFileHash(path, want, label string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: open: %w", label, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("%s: hash: %w", label, err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("%s: hash mismatch: want %s, got %s", label, want, got)
	}
	return nil
}

// SHA256OfFile is a helper that returns the lowercase hex SHA-256 of a file.
// Callers use this to generate the hash to embed in a Manifest.
func SHA256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("sha256: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("sha256: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
