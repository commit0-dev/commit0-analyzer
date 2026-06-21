package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeRegularFile creates a non-world-writable regular file (a stand-in for a
// plugin binary) at dir/name and returns its path.
func writeRegularFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/true\n"), 0o755))
	return p
}

// TestRegistry_StickyWorldWritableDirAllowed verifies that a binary inside a
// world-writable directory WITH the sticky bit (mode 1777, like /tmp) is
// accepted. This is the case that broke on Linux CI: os.MkdirTemp("") resolves
// under /tmp, whose 1777 mode must not trip the world-writable guard.
func TestRegistry_StickyWorldWritableDirAllowed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sticky")
	require.NoError(t, os.Mkdir(dir, 0o777))
	// Add the sticky bit → mode 1777, mirroring /tmp.
	require.NoError(t, os.Chmod(dir, 0o777|os.ModeSticky))

	bin := writeRegularFile(t, dir, "plugin")
	reg := NewRegistry()
	err := reg.Add(&Manifest{Name: "sticky-ok", ExecPath: bin})
	require.NoError(t, err, "sticky world-writable dir (1777) must be accepted")
	require.Equal(t, 1, reg.Len())
}

// TestRegistry_NonStickyWorldWritableDirRejected verifies that a world-writable
// directory WITHOUT the sticky bit (mode 0777) is still refused — an attacker
// could rename the binary and drop a malicious one (TOCTOU).
func TestRegistry_NonStickyWorldWritableDirRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(dir, 0o777))
	require.NoError(t, os.Chmod(dir, 0o777)) // no sticky bit

	bin := writeRegularFile(t, dir, "plugin")
	reg := NewRegistry()
	err := reg.Add(&Manifest{Name: "open-bad", ExecPath: bin})
	require.Error(t, err, "non-sticky world-writable dir must be rejected")
	require.Contains(t, err.Error(), "world-writable")
}

// TestRegistry_WorldWritableFileRejected verifies that a world-writable binary
// file itself is refused regardless of its directory — the sticky exemption
// applies only to directories.
func TestRegistry_WorldWritableFileRejected(t *testing.T) {
	dir := t.TempDir() // 0700, not world-writable
	bin := filepath.Join(dir, "plugin")
	require.NoError(t, os.WriteFile(bin, []byte("x"), 0o644))
	// chmod after creation: WriteFile's mode is masked by umask, but chmod is not.
	require.NoError(t, os.Chmod(bin, 0o777)) // force world-writable file

	reg := NewRegistry()
	err := reg.Add(&Manifest{Name: "ww-file", ExecPath: bin})
	require.Error(t, err, "world-writable binary file must be rejected")
	require.Contains(t, err.Error(), "world-writable")
}
