package host

import (
	"fmt"
	"os"
	"path/filepath"
)

// Registry holds the set of plugin manifests the host is allowed to load.
// It is the single source of truth for which plugins exist and where their
// binaries live.
//
// Security properties (Red Team #7):
//   - Explicit allowlist only: plugins must be registered via Add or AddAll.
//     Conventional-path discovery (e.g. scanning $PATH or a plugins/ dir) is
//     OFF and is not exposed by this package.
//   - World-writable path check: before accepting a manifest the registry
//     verifies that neither the binary nor any of its parent directories (up
//     to the fs root) are world-writable. A world-writable path lets an
//     unprivileged process swap the binary between the hash check and exec.
type Registry struct {
	manifests []*Manifest
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Add validates and registers a single Manifest.
// It returns an error if:
//   - the binary path is not absolute
//   - the binary does not exist or is not a regular file
//   - any path component (file or directory) is world-writable
func (r *Registry) Add(m *Manifest) error {
	if !filepath.IsAbs(m.ExecPath) {
		return fmt.Errorf("registry: plugin %q: exec path must be absolute, got %q", m.Name, m.ExecPath)
	}

	fi, err := os.Stat(m.ExecPath)
	if err != nil {
		return fmt.Errorf("registry: plugin %q: stat binary: %w", m.Name, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("registry: plugin %q: exec path is not a regular file: %q", m.Name, m.ExecPath)
	}

	if err := checkNotWorldWritable(m.ExecPath); err != nil {
		return fmt.Errorf("registry: plugin %q: %w", m.Name, err)
	}

	r.manifests = append(r.manifests, m)
	return nil
}

// AddAll registers a slice of Manifests, stopping and returning the first error.
func (r *Registry) AddAll(ms []*Manifest) error {
	for _, m := range ms {
		if err := r.Add(m); err != nil {
			return err
		}
	}
	return nil
}

// All returns a copy of the registered manifests in registration order.
func (r *Registry) All() []*Manifest {
	out := make([]*Manifest, len(r.manifests))
	copy(out, r.manifests)
	return out
}

// Len returns the number of registered plugins.
func (r *Registry) Len() int { return len(r.manifests) }

// checkNotWorldWritable returns an error if the given path or any of its
// parent directories (walking up to the root) has the world-writable bit set.
//
// Rationale: an attacker with write access to any directory component can
// rename the legitimate binary and drop a malicious one in its place between
// the time we hash-check and the time we exec — a classic TOCTOU attack.
// Rejecting world-writable paths raises the bar significantly.
//
// Note: this check is OS-best-effort on Unix (mode bits). It does not cover
// ACLs, extended attributes, or Windows DACLs; those environments should rely
// on OS-level controls (e.g. NTFS permissions, SELinux labels).
func checkNotWorldWritable(path string) error {
	// Walk every component from the file up to the root.
	cur := path
	for {
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("world-writable check: lstat %q: %w", cur, err)
		}
		if fi.Mode()&0o002 != 0 {
			return fmt.Errorf("path component %q is world-writable (mode %04o): refusing to load plugin from this location",
				cur, fi.Mode().Perm())
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the root.
			break
		}
		cur = parent
	}
	return nil
}
