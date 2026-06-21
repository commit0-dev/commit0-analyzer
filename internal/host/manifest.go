package host

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Manifest describes a single plugin binary that the host is allowed to load.
// It is the unit of configuration for the plugin allowlist: only binaries
// explicitly listed here (with matching path + hash) will be launched.
//
// Security: the combination of an explicit allowlist path and a SHA-256 hash
// provides two independent trust checks:
//  1. Path allowlist  – the file must be at a known, non-world-writable location.
//  2. Hash pinning    – the binary must match the expected content hash exactly.
//
// Either check failing causes the plugin to be refused before execution.
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
	// Used for routing: the host only sends a request to a plugin whose language
	// set overlaps with the target project's languages.
	Languages []string

	// SHA256 is the expected lowercase hex-encoded SHA-256 digest of the plugin
	// binary. go-plugin's SecureConfig uses this to reject tampered binaries.
	// Leave empty only in tests that explicitly opt out of hash checking.
	SHA256 string
}

// VerifyHash reads the plugin binary at m.ExecPath and returns an error if its
// SHA-256 digest does not match m.SHA256. An empty m.SHA256 skips the check
// (test-only escape hatch — production manifests must always set the hash).
func (m *Manifest) VerifyHash() error {
	if m.SHA256 == "" {
		return nil // caller opted out (tests only)
	}

	f, err := os.Open(m.ExecPath)
	if err != nil {
		return fmt.Errorf("manifest %s: open binary: %w", m.Name, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("manifest %s: hash binary: %w", m.Name, err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != m.SHA256 {
		return fmt.Errorf(
			"manifest %s: binary hash mismatch: want %s, got %s",
			m.Name, m.SHA256, got,
		)
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
