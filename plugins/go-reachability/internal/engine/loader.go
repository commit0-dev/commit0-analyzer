// Package engine implements the Go reachability analysis engine.
// It provides the Analyze function and all supporting primitives for loading
// packages, building SSA, constructing call graphs, resolving advisory symbols,
// and computing reachability with correct confidence-tier assignment.
package engine

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/tools/go/packages"
)

// LoadConfig holds resolved loader parameters.
type LoadConfig struct {
	Dir    string
	GOOS   string
	GOARCH string
	Tags   []string
	// Patterns are the package patterns passed to packages.Load.
	Patterns []string
}

// loadMode is the full set of facts needed for SSA + call-graph analysis.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedModule |
	packages.NeedTypesSizes

// LoadPackages loads all packages rooted at cfg.Dir using the given config.
// It returns the loaded packages, a shared FileSet, and any hard errors.
// Soft errors (IllTyped packages) are embedded in the returned pkgs so callers
// can inspect pkg.Errors and emit CONFIDENCE_UNKNOWN per Red Team Crit #4.
func LoadPackages(cfg LoadConfig) ([]*packages.Package, *token.FileSet, error) {
	fset := token.NewFileSet()

	env := os.Environ()
	if cfg.GOOS != "" {
		env = setenv(env, "GOOS", cfg.GOOS)
	}
	if cfg.GOARCH != "" {
		env = setenv(env, "GOARCH", cfg.GOARCH)
	}

	var buildFlags []string
	if len(cfg.Tags) > 0 {
		buildFlags = append(buildFlags, "-tags="+strings.Join(cfg.Tags, ","))
	}

	pcfg := &packages.Config{
		Mode:       loadMode,
		Dir:        cfg.Dir,
		Fset:       fset,
		Env:        env,
		BuildFlags: buildFlags,
		Tests:      true,
	}

	patterns := cfg.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	pkgs, err := packages.Load(pcfg, patterns...)
	if err != nil {
		return nil, nil, fmt.Errorf("packages.Load: %w", err)
	}
	return pkgs, fset, nil
}

// setenv replaces or appends key=value in env.
func setenv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			out := make([]string, len(env))
			copy(out, env)
			out[i] = prefix + value
			return out
		}
	}
	return append(env, prefix+value)
}

// EffectiveGOOS returns goos if non-empty, otherwise runtime.GOOS.
func EffectiveGOOS(goos string) string {
	if goos != "" {
		return goos
	}
	return runtime.GOOS
}

// EffectiveGOARCH returns goarch if non-empty, otherwise runtime.GOARCH.
func EffectiveGOARCH(goarch string) string {
	if goarch != "" {
		return goarch
	}
	return runtime.GOARCH
}

// ResolveModuleRoot validates that dir contains a go.mod and returns the
// canonical absolute path. Returns an error if go.mod is not found.
func ResolveModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve module root %q: %w", dir, err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		return "", fmt.Errorf("no go.mod in %q: %w", abs, err)
	}
	return abs, nil
}
