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
//     to the fs root) are unsafely world-writable. A world-writable path lets an
//     unprivileged process swap the binary between the hash check and exec.
//     A world-writable directory with the sticky bit set (e.g. /tmp, mode 1777)
//     is exempt: the sticky bit prevents non-owners from renaming/deleting the
//     binary, so the TOCTOU swap is not possible.
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

	for i, a := range m.AdditionalArtifacts {
		if !filepath.IsAbs(a.Path) {
			return fmt.Errorf("registry: plugin %q: artifact[%d] path must be absolute, got %q", m.Name, i, a.Path)
		}
		ai, err := os.Stat(a.Path)
		if err != nil {
			return fmt.Errorf("registry: plugin %q: artifact[%d] stat: %w", m.Name, i, err)
		}
		if !ai.Mode().IsRegular() {
			return fmt.Errorf("registry: plugin %q: artifact[%d] %q is not a regular file", m.Name, i, a.Path)
		}
		if err := checkNotWorldWritable(a.Path); err != nil {
			return fmt.Errorf("registry: plugin %q: artifact[%d]: %w", m.Name, i, err)
		}
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
// A world-writable directory with the sticky bit set (e.g. /tmp, mode 1777) is
// treated as safe: the sticky bit restricts rename/delete to the file owner, so
// an attacker cannot swap the binary. A world-writable file, or a world-writable
// directory WITHOUT the sticky bit, is rejected.
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
		mode := fi.Mode()
		// Exempt sticky world-writable directories (e.g. /tmp): the sticky bit
		// blocks non-owners from replacing the binary, defeating the TOCTOU swap.
		sticky := mode.IsDir() && mode&os.ModeSticky != 0
		if mode&0o002 != 0 && !sticky {
			return fmt.Errorf("path component %q is world-writable (mode %04o): refusing to load plugin from this location",
				cur, mode.Perm())
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
