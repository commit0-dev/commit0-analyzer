package host_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/host"
)

// TestHandshake_IncompatibleMajor verifies that Launch rejects a plugin that
// advertises a MAJOR protocol version the host cannot accept.
//
// The testplugin binary is built once in TestMain (see run_test.go).
// TESTPLUGIN_MODE=incompatible makes it return ProtocolVersion "99.0".
func TestHandshake_IncompatibleMajor(t *testing.T) {
	bin := testPluginBin(t)

	m := &host.Manifest{
		Name:     "testplugin-incompatible",
		ExecPath: bin,
		Pillar:   "sca",
	}

	t.Setenv("TESTPLUGIN_MODE", "incompatible")

	ctx := context.Background()
	_, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: true})
	require.Error(t, err, "Launch must reject a plugin with incompatible major version")
	assert.Contains(t, err.Error(), "incompatible protocol version",
		"error message should mention protocol version")
}

// TestHandshake_CompatibleVersion verifies that Launch accepts a plugin whose
// protocol version is compatible with the host (same major, minor ≤ host minor).
//
// Normal mode returns "0.1" which is exactly the host version — always compatible.
func TestHandshake_CompatibleVersion(t *testing.T) {
	bin := testPluginBin(t)

	m := &host.Manifest{
		Name:     "testplugin-compatible",
		ExecPath: bin,
		Pillar:   "sca",
	}

	t.Setenv("TESTPLUGIN_MODE", "normal")

	ctx := context.Background()
	pc, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: true})
	require.NoError(t, err, "Launch must succeed for a compatible plugin")
	require.NotNil(t, pc)
	// Kill the subprocess so the test exits cleanly.
	pc.Kill()
}

// TestHandshake_SelfTestRejectsEmptyName verifies that Launch rejects a plugin
// that passes the version check but returns an empty Name in Metadata.
// This is the "self-test sentinel" (Red Team #7): version compat ≠ authentication.
func TestHandshake_SelfTestRejectsEmptyName(t *testing.T) {
	bin := testPluginBin(t)

	m := &host.Manifest{
		Name:     "testplugin-empty",
		ExecPath: bin,
		Pillar:   "sca",
	}

	t.Setenv("TESTPLUGIN_MODE", "empty")

	ctx := context.Background()
	_, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: true})
	require.Error(t, err, "Launch must reject a plugin with empty Metadata Name")
	assert.Contains(t, err.Error(), "self-test failed",
		"error message should mention self-test failure")
}

// TestHashPinning_WrongHash verifies that Launch rejects a plugin binary whose
// SHA-256 does not match the manifest value.
func TestHashPinning_WrongHash(t *testing.T) {
	bin := testPluginBin(t)

	// Provide a deliberately wrong hash (all zeros).
	m := &host.Manifest{
		Name:     "testplugin-badhash",
		ExecPath: bin,
		Pillar:   "sca",
		SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
	}

	t.Setenv("TESTPLUGIN_MODE", "normal")

	ctx := context.Background()
	_, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: false})
	require.Error(t, err, "Launch must reject a binary with a mismatched hash")
}

// TestHashPinning_CorrectHash verifies that Launch succeeds when the manifest
// SHA-256 exactly matches the compiled binary.
func TestHashPinning_CorrectHash(t *testing.T) {
	bin := testPluginBin(t)

	hash, err := host.SHA256OfFile(bin)
	require.NoError(t, err)

	m := &host.Manifest{
		Name:     "testplugin-goodhash",
		ExecPath: bin,
		Pillar:   "sca",
		SHA256:   hash,
	}

	t.Setenv("TESTPLUGIN_MODE", "normal")

	ctx := context.Background()
	pc, err := host.Launch(ctx, m, host.LaunchOptions{SkipHashCheck: false})
	require.NoError(t, err, "Launch must succeed with a correct hash")
	require.NotNil(t, pc)
	pc.Kill()
}

// TestRegistry_RejectsNonAbsolutePath verifies that the registry refuses a
// manifest whose ExecPath is relative.
func TestRegistry_RejectsNonAbsolutePath(t *testing.T) {
	reg := host.NewRegistry()
	err := reg.Add(&host.Manifest{
		Name:     "relative",
		ExecPath: "bin/relative-plugin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

// TestRegistry_RejectsWorldWritablePath verifies that the registry refuses a
// manifest whose binary resides on a world-writable path.
func TestRegistry_RejectsWorldWritablePath(t *testing.T) {
	// Create a temporary file and make it world-writable.
	f, err := os.CreateTemp(t.TempDir(), "world-writable-*")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chmod(f.Name(), 0o777))

	reg := host.NewRegistry()
	err = reg.Add(&host.Manifest{
		Name:     "worldwritable",
		ExecPath: f.Name(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "world-writable")
}
