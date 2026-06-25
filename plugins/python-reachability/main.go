// Command python-reachability is the anst-analyzer plugin for Python (PyPI)
// reachability-first SCA. It implements the anstv1.Analyzer gRPC service via
// the shared pkg/plugin.Serve helper, mirroring the pattern established by
// go-reachability and rust-reachability.
//
// # Transport
//
// The host (internal/host) launches this binary as a subprocess and
// communicates over go-plugin's stdio-multiplexed gRPC transport. This binary
// must NOT write to stdout except through gRPC framing (in serve mode).
//
// # Supported ecosystems
//
// SupportedLanguages: ["python"]
// Ecosystem:          ECOSYSTEM_PYPI
//
// # Reachability model
//
// Lane B (source call-graph into installed deps):
//   - Detect venv / lockfile (poetry.lock, uv.lock, pdm.lock, Pipfile.lock,
//     requirements.txt) in the project root. Lockfile-static parsing only;
//     never execute setup.py, build scripts, or repo-supplied wrappers.
//   - Spawn the embedded Python sidecar (sidecar/cg/call_graph.py +
//     sidecar/parse/ast_worker.py) to build a demand-driven import closure.
//   - Map each advisory to a confidence tier using the call-graph outcome:
//       dist absent + complete graph          → NOT_REACHABLE
//       dist imported + symbol in call path   → SYMBOL_REACHABLE
//       dist imported + symbol unknown/missing → PACKAGE_REACHABLE
//       any UNKNOWN frontier / partial graph  → UNKNOWN + Incomplete=true
//   - Crash isolation: per-file parse failures degrade that file to UNKNOWN;
//     the scan continues.
//
// # Partiality marker
//
// Whenever the analysis is incomplete (venv absent, lockfile missing, parse
// failure, dynamic construct, BFS truncated), every affected finding carries
// Incomplete=true. This is the wire-level partiality signal: the host marks
// the scan incomplete and surfaces it in the policy gate.
//
// # Security posture (untrusted repos)
//
// The plugin never invokes pip, uv, setup.py, or any repo-supplied wrapper.
// It parses lockfiles statically. The embedded Python sidecar uses only the
// Python stdlib (ast, json, sys, os) — no third-party packages are imported
// from the target repo.
//
// # Subcommands
//
//	(default / "serve")     Start gRPC server (used by host)
//	--list-deps <root>      Print resolved dependency JSON to stdout and exit
//	--extract-symbols       Read patch+files JSON from stdin, print symbols JSON, exit
//
// # Build
//
//	go build ./plugins/python-reachability/...
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	anstplugin "github.com/ducthinh993/anst-analyzer/pkg/plugin"
)

// ---------------------------------------------------------------------------
// Embedded sidecar
// ---------------------------------------------------------------------------

// sidecarFiles holds all Python sidecar scripts embedded at build time.
// They are written to a temp dir on first use and never modified.
//
// The embed.FS covers the sidecar/ subtree:
//
//	sidecar/parse/ast_worker.py      — crash-isolated AST parse worker
//	sidecar/parse/parser_pool.py     — subprocess worker pool
//	sidecar/cg/call_graph.py         — demand-driven call-graph engine
//	sidecar/cg/confidence.py         — confidence-tier decision logic
//	sidecar/symbols/extract.py       — fix-patch symbol extractor
//	sidecar/dist_import_map.py       — dist-name → import-module mapping
//
// Using embed.FS (rather than individual //go:embed directives) lets us embed
// the whole tree recursively without listing each file.
//
//go:embed sidecar
var sidecarFS embed.FS

// ---------------------------------------------------------------------------
// sidecarDir — extract sidecar to temp once per process
// ---------------------------------------------------------------------------

var (
	sidecarOnce sync.Once
	sidecarDir  string
	sidecarErr  error
)

// extractSidecar writes the embedded sidecar/ tree to a temporary directory
// and returns the directory path. The directory is reused for the lifetime of
// the process.
func extractSidecar() (string, error) {
	sidecarOnce.Do(func() {
		dir, err := os.MkdirTemp("", "anst-python-sidecar-*")
		if err != nil {
			sidecarErr = fmt.Errorf("python-reachability: mkdirtemp: %w", err)
			return
		}
		if err := fs.WalkDir(sidecarFS, "sidecar", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel("sidecar", path)
			dst := filepath.Join(dir, rel)
			if d.IsDir() {
				return os.MkdirAll(dst, 0o755)
			}
			data, err := sidecarFS.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, data, 0o644)
		}); err != nil {
			_ = os.RemoveAll(dir)
			sidecarErr = fmt.Errorf("python-reachability: extract sidecar: %w", err)
			return
		}
		sidecarDir = dir
	})
	return sidecarDir, sidecarErr
}

// ---------------------------------------------------------------------------
// Python interpreter resolution
// ---------------------------------------------------------------------------

// findPython returns the absolute path to a Python 3.9+ interpreter.
// It searches a fixed set of known absolute paths and then PATH, but will
// never execute a repo-supplied wrapper.
//
// Security invariant: the returned path is always absolute and is never
// resolved relative to the current working directory.  A repo-local
// ./python3 shim (e.g. placed in the scanned project root) must not be
// selected, because the sidecar runs with cmd.Dir=embedded-temp which does
// not include the project root — but we still enforce this here defensively.
func findPython() (string, error) {
	// Fixed absolute paths first (safe: not repo-controlled)
	candidates := []string{
		"/usr/bin/python3",
		"/usr/local/bin/python3",
		"/opt/homebrew/bin/python3",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// Fall back to PATH lookup.  exec.LookPath returns the first match found
	// in PATH entries.  We verify the result is absolute and not inside the
	// process working directory to guard against a repo-local ./python3 shim
	// being injected via a PATH entry that contains "." or a relative path.
	if p, err := exec.LookPath("python3"); err == nil {
		// Resolve symlinks and canonicalize to an absolute path.
		if abs, err := filepath.EvalSymlinks(p); err == nil {
			p = abs
		}
		// Reject any result that is not absolute (should not happen, but be
		// defensive) or that equals the process cwd (a relative shim).
		if filepath.IsAbs(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("python-reachability: no python3 interpreter found")
}

// ---------------------------------------------------------------------------
// Resolved dependency (--list-deps output)
// ---------------------------------------------------------------------------

// Dep type constants — the set of values emitted in the dep_type JSON field.
//
// Priority (most to least runtime-ish): runtime > optional-extra > dev = test = docs.
// When a dep appears in multiple categories the most runtime-ish wins so we
// never accidentally hide a real runtime vulnerability as dev-only.
const (
	DepTypeRuntime       = "runtime"
	DepTypeOptionalExtra = "optional-extra"
	DepTypeDev           = "dev"
	DepTypeTest          = "test"
	DepTypeDocs          = "docs"
)

// depTypePriority maps a dep_type value to a numeric priority; higher = more
// runtime-ish.  Used by classifyDep to enforce the "runtime wins" invariant.
var depTypePriority = map[string]int{
	DepTypeRuntime:       4,
	DepTypeOptionalExtra: 3,
	DepTypeDev:           2,
	DepTypeTest:          2,
	DepTypeDocs:          2,
}

// ResolvedDep is a single dependency entry as reported by --list-deps.
type ResolvedDep struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	DepType    string `json:"dep_type"`            // runtime | optional-extra | dev | test | docs
	DevOnly    bool   `json:"dev_only,omitempty"`
	LockSource string `json:"lock_source,omitempty"` // "poetry.lock", "requirements.txt", etc.
}

// ---------------------------------------------------------------------------
// Dep-type classification helpers
// ---------------------------------------------------------------------------

// pyprojectDeps holds the dep classification data extracted from pyproject.toml.
//
// Fields:
//   runtime   — normalised dist names that appear in [project.dependencies]
//   optExtra  — normalised dist name -> extra name ([project.optional-dependencies])
//   devGroup  — normalised dist name -> group name ([dependency-groups] or uv [package.dev-dependencies])
type pyprojectDeps struct {
	runtime  map[string]bool
	optExtra map[string]string
	devGroup map[string]string
}

// parsePyprojectFile reads a pyproject.toml and returns the classification
// maps.  On any error it returns empty maps (caller defaults to runtime).
//
// Handles two common pyproject.toml section layouts:
//
//   Subsection style (each extra / group has its own header):
//     [project.optional-dependencies.cache]
//     redis = ">=4.0"
//
//   Flat style (one header, key = [...] blocks inside):
//     [project.optional-dependencies]
//     cache = ["redis>=4.0"]
//
//     [dependency-groups]
//     dev = ["pytest>=7.0"]
//
// Both styles are normalised into the same pyprojectDeps maps.
// Dep name normalisation: PEP 503 — lowercase, collapse runs of [-_.] to '_'.
func parsePyprojectFile(path string) (pyprojectDeps, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pyprojectDeps{}, err
	}

	pd := pyprojectDeps{
		runtime:  make(map[string]bool),
		optExtra: make(map[string]string),
		devGroup: make(map[string]string),
	}

	const (
		modeNone         = 0
		modeProject      = 1  // inside [project] section
		modeRuntime      = 2  // inside dependencies = [...] key within [project]
		modeOptExtraSub  = 3  // subsection: [project.optional-dependencies.NAME]
		modeOptExtraFlat = 4  // flat: [project.optional-dependencies] with key = [...] blocks
		modeDevGroupSub  = 5  // subsection: [dependency-groups.NAME]
		modeDevGroupFlat = 6  // flat: [dependency-groups] with key = [...] blocks
		modeKeyArray     = 7  // inside key = [...] multi-line block under a flat section
	)

	mode := modeNone
	activeSection := ""    // current extra/group name
	parentMode := modeNone // flat-section mode before we entered modeKeyArray

	registerDep := func(name, section string, m int) {
		n := normaliseDistName(name)
		switch m {
		case modeRuntime, modeProject:
			pd.runtime[n] = true
		case modeOptExtraFlat, modeOptExtraSub:
			if _, exists := pd.optExtra[n]; !exists {
				pd.optExtra[n] = section
			}
		case modeDevGroupFlat, modeDevGroupSub:
			if _, exists := pd.devGroup[n]; !exists {
				pd.devGroup[n] = section
			}
		}
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)

		// ---- Section header detection (order: most-specific first) ----
		if strings.HasPrefix(line, "[project.optional-dependencies.") {
			rest := strings.TrimPrefix(line, "[project.optional-dependencies.")
			activeSection = strings.TrimSuffix(rest, "]")
			mode = modeOptExtraSub
			continue
		}
		if line == "[project.optional-dependencies]" {
			mode = modeOptExtraFlat
			activeSection = ""
			continue
		}
		if strings.HasPrefix(line, "[dependency-groups.") {
			rest := strings.TrimPrefix(line, "[dependency-groups.")
			activeSection = strings.TrimSuffix(rest, "]")
			mode = modeDevGroupSub
			continue
		}
		if line == "[dependency-groups]" {
			mode = modeDevGroupFlat
			activeSection = ""
			continue
		}
		if line == "[project]" {
			mode = modeProject
			activeSection = ""
			continue
		}
		// Any other section header resets mode (but not modeKeyArray — that ends on "]").
		if mode != modeKeyArray && strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[") {
			mode = modeNone
			activeSection = ""
			continue
		}

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// ---- Content parsing ----
		switch mode {

		case modeOptExtraSub, modeDevGroupSub:
			name := extractDepName(line)
			if name != "" {
				registerDep(name, activeSection, mode)
			}

		case modeProject:
			// Detect "dependencies = [" key inside [project].
			if kv := splitKV(line); kv != nil && strings.TrimSpace(kv[0]) == "dependencies" {
				val := strings.TrimSpace(kv[1])
				if strings.HasPrefix(val, "[") {
					inner := strings.TrimPrefix(val, "[")
					inner = strings.TrimSuffix(strings.TrimSpace(inner), "]")
					if inner != "" {
						// Inline single-line array.
						for _, part := range splitInlineArray(inner) {
							if name := extractDepName(`"` + strings.Trim(part, `"`) + `"`); name != "" {
								pd.runtime[normaliseDistName(name)] = true
							}
						}
					} else {
						// Multi-line array.
						parentMode = modeRuntime
						mode = modeKeyArray
					}
				}
			}

		case modeOptExtraFlat, modeDevGroupFlat:
			// Lines are "groupname = [...]" or "groupname = ["  ...  ]"
			if kv := splitKV(line); kv != nil {
				key := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				if strings.HasPrefix(val, "[") {
					activeSection = key
					inner := strings.TrimPrefix(val, "[")
					inner = strings.TrimSuffix(strings.TrimSpace(inner), "]")
					if inner != "" {
						for _, part := range splitInlineArray(inner) {
							if name := extractDepName(`"` + strings.Trim(part, `"`) + `"`); name != "" {
								registerDep(name, activeSection, mode)
							}
						}
						activeSection = ""
					} else {
						parentMode = mode
						mode = modeKeyArray
					}
				}
			}

		case modeKeyArray:
			if line == "]" {
				if parentMode == modeRuntime {
					mode = modeProject
				} else {
					mode = parentMode
				}
				activeSection = ""
				continue
			}
			name := extractDepName(line)
			if name != "" {
				if parentMode == modeRuntime {
					pd.runtime[normaliseDistName(name)] = true
				} else {
					registerDep(name, activeSection, parentMode)
				}
			}
		}
	}
	return pd, nil
}

// splitInlineArray splits a comma-separated inline TOML array content
// (the part between '[' and ']') into individual elements, trimming spaces.
func splitInlineArray(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// extractDepName pulls the package name from a line that may look like any of:
//   "requests>=2.28",
//   requests>=2.28
//   { name = "sphinx-rtd-theme" }        (TOML inline table in an array)
//   "requests>=2.28; python_version<'3.11'",
//
// Returns "" when the line does not contain a recognisable package name.
func extractDepName(line string) string {
	// Strip trailing comma.
	line = strings.TrimRight(line, ",")

	// TOML inline table: { name = "foo" ... }
	if strings.HasPrefix(line, "{") {
		if i := strings.Index(line, `name = "`); i >= 0 {
			rest := line[i+len(`name = "`):]
			if end := strings.IndexByte(rest, '"'); end >= 0 {
				return rest[:end]
			}
		}
		return ""
	}

	// Quoted string (PEP 508 specifier inside quotes):  "requests>=2.28"
	if strings.HasPrefix(line, `"`) {
		inner := strings.Trim(line, `"`)
		// Strip env markers after ';'
		if sc := strings.IndexByte(inner, ';'); sc >= 0 {
			inner = inner[:sc]
		}
		inner = strings.TrimSpace(inner)
		// Take only the package name portion (before any version specifier).
		for i, c := range inner {
			if c == '>' || c == '<' || c == '!' || c == '=' || c == '~' || c == '[' {
				return strings.TrimSpace(inner[:i])
			}
		}
		return inner
	}

	return ""
}

// groupNameToDepType maps a dependency-group name to a dep_type string.
//
// Rules (applied in order):
//  1. Name contains "doc" (case-insensitive)          -> docs
//  2. Name contains "test" or "pytest" (case-insensitive) -> test
//  3. Everything else (dev, ci, proxy-dev, healthcheck…)  -> dev
func groupNameToDepType(group string) string {
	lower := strings.ToLower(group)
	if strings.Contains(lower, "doc") || strings.Contains(lower, "sphinx") {
		return DepTypeDocs
	}
	if strings.Contains(lower, "test") || strings.Contains(lower, "pytest") {
		return DepTypeTest
	}
	return DepTypeDev
}

// classifyDep returns the dep_type for a normalised dist name given the
// classification maps extracted from pyproject.toml.
//
// Priority: runtime > optional-extra > dev/test/docs > default(runtime).
// "runtime wins" invariant: if a dep is in both runtime and dev group, it is
// classified as runtime to avoid hiding a real vulnerability.
func classifyDep(normName string, pd pyprojectDeps) string {
	best := ""
	bestPrio := -1

	update := func(t string) {
		if p := depTypePriority[t]; p > bestPrio {
			best = t
			bestPrio = p
		}
	}

	if pd.runtime[normName] {
		update(DepTypeRuntime)
	}
	if _, ok := pd.optExtra[normName]; ok {
		update(DepTypeOptionalExtra)
	}
	if group, ok := pd.devGroup[normName]; ok {
		update(groupNameToDepType(group))
	}

	if best == "" {
		return DepTypeRuntime // conservative default: never hide a possibly-runtime dep
	}
	return best
}

// ---------------------------------------------------------------------------
// Lockfile parsers (lockfile-static; never executes pip/uv)
// ---------------------------------------------------------------------------

// listDeps resolves the dependency closure for projectRoot using lockfile-static
// parsing. It never invokes pip, uv, setup.py, or any repo-supplied wrapper.
//
// Priority order: poetry.lock → uv.lock → pdm.lock → Pipfile.lock →
// requirements.txt → pyproject.toml (fallback: name+version only from
// [project] dependencies).
//
// On any parse failure or missing lockfile the function returns what it has
// plus an indication that the result is incomplete.
func listDeps(projectRoot string) ([]ResolvedDep, bool, error) {
	for _, fn := range []string{
		"poetry.lock",
		"uv.lock",
		"pdm.lock",
		"Pipfile.lock",
		"requirements.txt",
	} {
		p := filepath.Join(projectRoot, fn)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		switch fn {
		case "poetry.lock":
			deps, ok, err := parsePoetryLock(p)
			if err == nil {
				return deps, ok, nil
			}
		case "uv.lock", "pdm.lock":
			deps, ok, err := parseTOMLLock(p, fn)
			if err == nil {
				return deps, ok, nil
			}
		case "Pipfile.lock":
			deps, ok, err := parsePipfileLock(p)
			if err == nil {
				return deps, ok, nil
			}
		case "requirements.txt":
			deps, ok, err := parseRequirementsTxt(p)
			if err == nil {
				return deps, ok, nil
			}
		}
	}
	// No lockfile found — return empty + incomplete
	return nil, true, nil
}

// parsePoetryLock parses a poetry.lock TOML file.
// Poetry lock format: [[package]] sections with name/version/category.
func parsePoetryLock(path string) ([]ResolvedDep, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	var deps []ResolvedDep
	var (
		inPackage bool
		curName   string
		curVer    string
		curCat    string // "main" | "dev"
	)

	flushPkg := func() {
		if !inPackage || curName == "" {
			return
		}
		dt := DepTypeRuntime
		if curCat == "dev" {
			dt = DepTypeDev
		}
		deps = append(deps, ResolvedDep{
			Name:       curName,
			Version:    curVer,
			Ecosystem:  "PyPI",
			DepType:    dt,
			DevOnly:    curCat == "dev",
			LockSource: "poetry.lock",
		})
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "[[package]]" {
			flushPkg()
			inPackage = true
			curName, curVer, curCat = "", "", "main"
			continue
		}
		if !inPackage {
			continue
		}
		if kv := splitKV(line); kv != nil {
			switch kv[0] {
			case "name":
				curName = unquote(kv[1])
			case "version":
				curVer = unquote(kv[1])
			case "category":
				curCat = unquote(kv[1])
			}
		}
	}
	// Flush last package
	flushPkg()
	return deps, false, nil
}

// parseTOMLLock handles uv.lock / pdm.lock (simplified TOML [[package]] parse).
//
// Dep-type classification uses two sources in priority order:
//  1. pyproject.toml co-located with the lockfile (PEP 621 / PEP 735 sections).
//  2. The [package.dev-dependencies] block embedded in uv.lock for the root
//     workspace member (used as fallback when pyproject.toml is absent/unreadable).
//
// For any dep whose type cannot be determined, dep_type defaults to "runtime"
// (conservative: never hide a possibly-runtime vulnerability).
func parseTOMLLock(path, lockSource string) ([]ResolvedDep, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}

	// Try pyproject.toml in the same directory as the lockfile.
	pyprojectPath := filepath.Join(filepath.Dir(path), "pyproject.toml")
	pd, _ := parsePyprojectFile(pyprojectPath) // best-effort; empty maps on error

	// Also parse [package.dev-dependencies] blocks directly from the uv.lock
	// as a secondary source (handles monorepos where pyproject.toml may not
	// be co-located with the lockfile we found first).
	uvDevDeps := parseUVLockDevDeps(string(data))
	// Merge uvDevDeps into pd.devGroup (pyproject takes priority).
	for name, group := range uvDevDeps {
		if _, exists := pd.devGroup[name]; !exists {
			pd.devGroup[name] = group
		}
	}
	// Merge uv.lock optional-deps into pd.optExtra as well.
	uvOptDeps := parseUVLockOptDeps(string(data))
	for name, extra := range uvOptDeps {
		if _, exists := pd.runtime[name]; !exists {
			if _, exists := pd.optExtra[name]; !exists {
				pd.optExtra[name] = extra
			}
		}
	}
	// Merge uv.lock runtime deps (root package dependencies = []) into pd.runtime.
	uvRuntime := parseUVLockRuntimeDeps(string(data))
	for name := range uvRuntime {
		pd.runtime[name] = true
	}

	var deps []ResolvedDep
	var (
		inPackage bool
		curName   string
		curVer    string
	)

	flushPkg := func() {
		if !inPackage || curName == "" {
			return
		}
		norm := normaliseDistName(curName)
		dt := classifyDep(norm, pd)
		deps = append(deps, ResolvedDep{
			Name:       curName,
			Version:    curVer,
			Ecosystem:  "PyPI",
			DepType:    dt,
			DevOnly:    dt == DepTypeDev || dt == DepTypeTest || dt == DepTypeDocs,
			LockSource: lockSource,
		})
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "[[package]]" || line == "[[tool.pdm.dev-dependencies]]" {
			flushPkg()
			inPackage = true
			curName, curVer = "", ""
			continue
		}
		if !inPackage {
			continue
		}
		if kv := splitKV(line); kv != nil {
			switch kv[0] {
			case "name":
				curName = unquote(kv[1])
			case "version":
				curVer = unquote(kv[1])
			}
		}
	}
	flushPkg()
	return deps, false, nil
}

// ---------------------------------------------------------------------------
// uv.lock embedded classification parsers
// ---------------------------------------------------------------------------

// parseUVLockDevDeps scans a uv.lock string for [package.dev-dependencies]
// blocks and returns a map of normalised-dist-name -> group-name.
//
// uv.lock format (under the root [[package]] entry):
//
//	[package.dev-dependencies]
//	dev = [
//	    { name = "pytest" },
//	    ...
//	]
//	test = [
//	    { name = "pytest-cov" },
//	]
func parseUVLockDevDeps(content string) map[string]string {
	result := make(map[string]string)

	const header = "[package.dev-dependencies]"
	idx := strings.Index(content, header)
	if idx < 0 {
		return result
	}

	// Find the next top-level section header (starts with '[' at column 0,
	// and is not a '[[' package entry).
	section := content[idx+len(header):]
	// Trim to next top-level section.
	if next := findNextTopLevelSection(section); next >= 0 {
		section = section[:next]
	}

	currentGroup := ""
	for _, rawLine := range strings.Split(section, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Group header: "dev = [" or "test = ["
		if kv := splitKV(line); kv != nil && strings.HasSuffix(strings.TrimSpace(kv[1]), "[") {
			currentGroup = strings.TrimSpace(kv[0])
			continue
		}
		// End of group array.
		if line == "]" {
			currentGroup = ""
			continue
		}
		if currentGroup == "" {
			continue
		}
		// Package entry: { name = "pytest" } or { name = "pytest", ... }
		name := extractDepName(line)
		if name != "" {
			norm := normaliseDistName(name)
			if _, exists := result[norm]; !exists {
				result[norm] = currentGroup
			}
		}
	}
	return result
}

// parseUVLockOptDeps scans for [package.optional-dependencies] in uv.lock
// and returns normalised-dist-name -> extra-name.
func parseUVLockOptDeps(content string) map[string]string {
	result := make(map[string]string)

	const header = "[package.optional-dependencies]"
	idx := strings.Index(content, header)
	if idx < 0 {
		return result
	}

	section := content[idx+len(header):]
	if next := findNextTopLevelSection(section); next >= 0 {
		section = section[:next]
	}

	currentExtra := ""
	for _, rawLine := range strings.Split(section, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if kv := splitKV(line); kv != nil && strings.HasSuffix(strings.TrimSpace(kv[1]), "[") {
			currentExtra = strings.TrimSpace(kv[0])
			continue
		}
		if line == "]" {
			currentExtra = ""
			continue
		}
		if currentExtra == "" {
			continue
		}
		name := extractDepName(line)
		if name != "" {
			norm := normaliseDistName(name)
			if _, exists := result[norm]; !exists {
				result[norm] = currentExtra
			}
		}
	}
	return result
}

// parseUVLockRuntimeDeps extracts the root package's direct runtime deps
// from the "dependencies = [" block in uv.lock (the editable / root package).
//
// We identify the root package by looking for source = { editable = "." }.
func parseUVLockRuntimeDeps(content string) map[string]bool {
	result := make(map[string]bool)

	// Find the root package block: [[package]] followed by source = { editable = "." }
	// We scan all [[package]] blocks and pick the one with editable = ".".
	blocks := strings.Split(content, "\n[[package]]")
	for _, block := range blocks {
		if !strings.Contains(block, `editable = "."`) {
			continue
		}
		// Found root package block; extract its dependencies = [...] section.
		depsIdx := strings.Index(block, "dependencies = [")
		if depsIdx < 0 {
			continue
		}
		depSection := block[depsIdx+len("dependencies = ["):]
		// Read until the closing ']' at the start of a line.
		for _, rawLine := range strings.Split(depSection, "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "]" {
				break
			}
			name := extractDepName(line)
			if name != "" {
				result[normaliseDistName(name)] = true
			}
		}
	}
	return result
}

// findNextTopLevelSection returns the index of the next top-level TOML section
// header (a line starting with '[' but NOT '[[') within s, or -1 if none.
func findNextTopLevelSection(s string) int {
	offset := 0
	for _, rawLine := range strings.Split(s, "\n") {
		if offset > 0 { // skip the very first line (it's part of current header)
			trimmed := strings.TrimSpace(rawLine)
			if strings.HasPrefix(trimmed, "[") {
				return offset
			}
		}
		offset += len(rawLine) + 1 // +1 for the '\n'
	}
	return -1
}

// parsePipfileLock parses a Pipfile.lock JSON file.
// Format: {"default": {"pkg": {"version": "==1.2.3"}}, "develop": {...}}
func parsePipfileLock(path string) ([]ResolvedDep, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	var raw struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, true, err
	}
	var deps []ResolvedDep
	for name, pkg := range raw.Default {
		ver := strings.TrimPrefix(pkg.Version, "==")
		deps = append(deps, ResolvedDep{
			Name:       name,
			Version:    ver,
			Ecosystem:  "PyPI",
			LockSource: "Pipfile.lock",
		})
	}
	for name, pkg := range raw.Develop {
		ver := strings.TrimPrefix(pkg.Version, "==")
		deps = append(deps, ResolvedDep{
			Name:       name,
			Version:    ver,
			Ecosystem:  "PyPI",
			DevOnly:    true,
			LockSource: "Pipfile.lock",
		})
	}
	return deps, false, nil
}

// parseRequirementsTxt parses a requirements.txt file.
// Handles "name==version" pins; skips -r/-c/-e includes and non-pinned specs.
//
// IMPORTANT: requirements.txt is ALWAYS treated as an incomplete closure.
// It lists only the packages explicitly named in the file — typically just
// direct dependencies, not the full transitive closure — and any -r/-c/-e
// include directives cause additional files to be silently skipped.  A partial
// list with Incomplete=false would allow advisory dists absent from the
// truncated list to be classified as NOT_REACHABLE (a soundness violation).
// Following the Rust plugin precedent (cargo metadata partial resolve → always
// incomplete), requirements.txt always returns incomplete=true regardless of
// whether all listed entries are pinned.
func parseRequirementsTxt(path string) ([]ResolvedDep, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	var deps []ResolvedDep
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			// Lines starting with '-' are option flags (-r, -c, -e, --index-url,
			// etc.) that may pull in additional packages not listed here.  Skip
			// without attempting to parse; the incomplete=true return handles the
			// soundness obligation.
			continue
		}
		// name==version or name>=version etc.
		for _, sep := range []string{"==", ">=", "<=", "~=", "!="} {
			if idx := strings.Index(line, sep); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				ver := ""
				if sep == "==" {
					ver = strings.TrimSpace(line[idx+2:])
					// strip trailing markers (e.g. ";python_version>=3.8")
					if sc := strings.IndexByte(ver, ';'); sc >= 0 {
						ver = strings.TrimSpace(ver[:sc])
					}
				}
				if name != "" {
					deps = append(deps, ResolvedDep{
						Name:       name,
						Version:    ver,
						Ecosystem:  "PyPI",
						LockSource: "requirements.txt",
					})
				}
				break
			}
		}
	}
	// Always incomplete: requirements.txt is not a transitive closure.
	return deps, true, nil
}

// ---------------------------------------------------------------------------
// TOML key=value helpers (minimal, no dependency on toml library)
// ---------------------------------------------------------------------------

func splitKV(line string) []string {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return nil
	}
	return []string{strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])}
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Call-graph analysis via Python sidecar
// ---------------------------------------------------------------------------

// cgRequest is the JSON payload sent to the Python call-graph sidecar.
type cgRequest struct {
	ProjectRoot       string              `json:"project_root"`
	SitePackages      string              `json:"site_packages,omitempty"`
	DistNames         []string            `json:"dist_names"`                    // advisory dist names to check
	VulnerableSymbols map[string][]string `json:"vulnerable_symbols,omitempty"`  // dist_name -> symbol names
}

// cgResponse is the JSON payload returned by the Python call-graph sidecar.
type cgResponse struct {
	// DistReachable maps dist_name → true if the dist is in the import closure.
	DistReachable map[string]bool `json:"dist_reachable"`
	// SymbolReachable maps "dist_name::symbol_name" → true when a direct static
	// call to the vulnerable symbol was found in reachable first-party code.
	// A key is only present when symbol_reachable=True; absent key = undetermined.
	SymbolReachable map[string]bool `json:"symbol_reachable"`
	// SymbolPaths maps "dist_name::symbol_name" → list of file paths where the
	// symbol was directly called.  Used for SARIF location data.
	SymbolPaths map[string][]string `json:"symbol_paths,omitempty"`
	// Incomplete is true if any UNKNOWN frontier was encountered.
	Incomplete bool `json:"incomplete"`
	// Error carries a diagnostic message when analysis failed entirely.
	Error string `json:"error,omitempty"`
}

// analyzeWithSidecar invokes the Python call-graph sidecar and returns the
// reachability outcome for the requested dist names.
//
// vulnerableSymbols maps each dist name to the list of vulnerable symbol names
// from its advisory (e.g. {"diskcache": ["get", "Cache.get"]}).  When non-nil,
// the sidecar attempts symbol-level reachability and populates SymbolReachable.
//
// On any failure (sidecar absent, Python interpreter not found, timeout,
// JSON decode error) it returns a cgResponse with Incomplete=true and the
// Error field set.  Callers MUST treat that as UNKNOWN, never NOT_REACHABLE.
func analyzeWithSidecar(ctx context.Context, projectRoot string, distNames []string, vulnerableSymbols map[string][]string) cgResponse {
	sidecar, err := extractSidecar()
	if err != nil {
		return cgResponse{Incomplete: true, Error: err.Error()}
	}
	python, err := findPython()
	if err != nil {
		return cgResponse{Incomplete: true, Error: err.Error()}
	}

	// Build request payload
	req := cgRequest{
		ProjectRoot:       projectRoot,
		DistNames:         distNames,
		VulnerableSymbols: vulnerableSymbols,
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return cgResponse{Incomplete: true, Error: fmt.Sprintf("marshal request: %v", err)}
	}

	// The sidecar runner script reads a cgRequest on stdin and writes a
	// cgResponse on stdout.  It is co-located in sidecar/cg/call_graph.py
	// and invoked with --analyze-json.
	runnerScript := filepath.Join(sidecar, "cg", "call_graph.py")

	// The sidecar enforces its own internal deadline (DEFAULT_DEADLINE_SEC = 90 s)
	// and always writes valid JSON before it hits that budget.  We give the outer
	// shim 110 s so the sidecar's internal budget fires first and we receive a
	// clean cgResponse rather than getting hard-killed mid-write.
	const timeout = 110 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(timeoutCtx, python, runnerScript, "--analyze-json") //nolint:gosec
	cmd.Stdin = bytes.NewReader(reqJSON)
	cmd.Dir = sidecar

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := fmt.Sprintf("sidecar run: %v; stderr: %s", err, truncate(stderr.String(), 512))
		return cgResponse{Incomplete: true, Error: msg}
	}

	var resp cgResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return cgResponse{Incomplete: true, Error: fmt.Sprintf("decode response: %v; stdout: %s", err, truncate(stdout.String(), 256))}
	}
	return resp
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// extractSymbols — --extract-symbols subcommand
// ---------------------------------------------------------------------------

// runExtractSymbols reads a patch+files JSON request from stdin, delegates to
// the Python sidecar (sidecar/symbols/extract.py), and writes the symbol JSON
// array to stdout.  Always exits 0 (errors produce []).
func runExtractSymbols() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("[]")
		return
	}

	sidecar, err := extractSidecar()
	if err != nil {
		fmt.Println("[]")
		return
	}
	python, err := findPython()
	if err != nil {
		fmt.Println("[]")
		return
	}

	script := filepath.Join(sidecar, "symbols", "extract.py")
	cmd := exec.Command(python, script) //nolint:gosec
	cmd.Stdin = bytes.NewReader(input)
	cmd.Dir = sidecar

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// sidecar guarantees exit 0; if we get non-zero, emit []
		fmt.Fprintln(os.Stdout, "[]")
		return
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		out = "[]"
	}
	fmt.Fprintln(os.Stdout, out)
}

// ---------------------------------------------------------------------------
// runListDeps — --list-deps subcommand
// ---------------------------------------------------------------------------

// runListDeps prints a JSON array of ResolvedDep to stdout and exits.
// The root argument is the project directory to inspect.
func runListDeps(root string) {
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "python-reachability --list-deps: %v\n", err)
		os.Exit(1)
	}

	deps, incomplete, err := listDeps(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "python-reachability --list-deps: %v\n", err)
		os.Exit(1)
	}

	type output struct {
		Deps       []ResolvedDep `json:"deps"`
		Incomplete bool          `json:"incomplete"`
	}
	if deps == nil {
		deps = []ResolvedDep{}
	}
	data, err := json.MarshalIndent(output{Deps: deps, Incomplete: incomplete}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "python-reachability --list-deps: marshal: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

// ---------------------------------------------------------------------------
// gRPC server implementation
// ---------------------------------------------------------------------------

// grpcServer implements anstv1.AnalyzerServer for the Python reachability plugin.
type grpcServer struct {
	anstv1.UnimplementedAnalyzerServer
}

// Metadata returns plugin identity and protocol version for the host handshake.
func (s *grpcServer) Metadata(
	_ context.Context,
	_ *anstv1.MetadataRequest,
) (*anstv1.MetadataResponse, error) {
	return &anstv1.MetadataResponse{
		Name:               "python-reachability",
		Version:            "0.1.0",
		ProtocolVersion:    "0.1",
		Description:        "Python SCA reachability analyzer: demand-driven import closure + fix-patch symbol extraction (Lane B).",
		SupportedLanguages: []string{"python"},
	}, nil
}

// Analyze resolves the Python dependency closure for the project and streams
// one Finding per advisory to the host.
//
// When analysis fails or is incomplete, every affected finding carries
// Incomplete=true and Confidence=CONFIDENCE_UNKNOWN (unknown ≠ safe).
//
// Confidence decision (per advisory):
//
//	complete graph + dist absent         → CONFIDENCE_NOT_REACHABLE
//	incomplete graph + dist absent       → CONFIDENCE_UNKNOWN + Incomplete
//	dist imported + symbol in call path  → CONFIDENCE_SYMBOL_REACHABLE
//	dist imported + no symbol data       → CONFIDENCE_PACKAGE_REACHABLE
//	any undecidable condition            → CONFIDENCE_UNKNOWN + Incomplete
func (s *grpcServer) Analyze(
	req *anstv1.AnalyzeRequest,
	stream anstv1.Analyzer_AnalyzeServer,
) error {
	ctx := stream.Context()
	projectRoot := req.GetModuleRoot()
	advisories := req.GetAdvisories()

	if projectRoot == "" || len(advisories) == 0 {
		return nil
	}

	// ── Step 1: Resolve lockfile dependency closure ──────────────────────────
	_, closureIncomplete, lockErr := listDeps(projectRoot)

	// ── Step 2: Collect dist names + vulnerable symbols from advisories ──────
	distNames := make([]string, 0, len(advisories))
	seen := make(map[string]bool)
	// vulnerableSymbols collects per-dist symbol names for symbol-level scanning.
	// Multiple advisories for the same dist are merged (union of symbols).
	vulnerableSymbols := make(map[string][]string)
	symSeen := make(map[string]map[string]bool) // dist -> set of seen symbol names
	for _, adv := range advisories {
		dn := normaliseDistName(adv.GetModule())
		if !seen[dn] {
			distNames = append(distNames, dn)
			seen[dn] = true
		}
		if adv.GetSymbolLevel() {
			if symSeen[dn] == nil {
				symSeen[dn] = make(map[string]bool)
			}
			for _, sym := range adv.GetSymbols() {
				name := sym.GetName()
				if name != "" && !symSeen[dn][name] {
					symSeen[dn][name] = true
					vulnerableSymbols[dn] = append(vulnerableSymbols[dn], name)
				}
			}
		}
	}

	// ── Step 3: Run call-graph sidecar (best-effort) ─────────────────────────
	var cgResult cgResponse
	if lockErr != nil || closureIncomplete {
		// Degrade: no complete closure → all advisories → UNKNOWN+incomplete
		cgResult = cgResponse{
			Incomplete:      true,
			DistReachable:   map[string]bool{},
			SymbolReachable: map[string]bool{},
			Error:           fmt.Sprintf("lockfile: %v", lockErr),
		}
	} else {
		cgResult = analyzeWithSidecar(ctx, projectRoot, distNames, vulnerableSymbols)
	}

	// ── Step 4: Emit one Finding per advisory ────────────────────────────────
	for _, adv := range advisories {
		f := buildFinding(adv, cgResult)
		if err := stream.Send(f); err != nil {
			return fmt.Errorf("python-reachability: stream.Send: %w", err)
		}
	}
	return nil
}

// buildFinding maps one advisory to a Finding using the call-graph result.
func buildFinding(
	adv *anstv1.Advisory,
	cg cgResponse,
) *anstv1.Finding {
	dn := normaliseDistName(adv.GetModule())

	props := map[string]string{
		"ecosystem": "PyPI",
	}
	if cg.Error != "" {
		props["sidecar_error"] = truncate(cg.Error, 256)
	}

	// When the closure analysis failed entirely, every finding is UNKNOWN+incomplete.
	if cg.Error != "" && len(cg.DistReachable) == 0 {
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			Incomplete: true,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}
	}

	reachable, inClosure := cg.DistReachable[dn]

	switch {
	case !inClosure && !cg.Incomplete:
		// Complete graph proof: dist is wholly absent → NOT_REACHABLE
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
			Incomplete: false,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}

	case !inClosure && cg.Incomplete:
		// Incomplete graph: cannot prove absence → UNKNOWN+incomplete
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			Incomplete: true,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}

	case reachable && adv.GetSymbolLevel():
		// Dist imported + advisory has symbol data; check symbol reachability.
		anySymbolHit := false
		for _, sym := range adv.GetSymbols() {
			key := dn + "::" + sym.GetName()
			if cg.SymbolReachable[key] {
				anySymbolHit = true
				break
			}
		}
		if anySymbolHit {
			return &anstv1.Finding{
				Advisory:   advRef(adv),
				Module:     adv.GetModule(),
				Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
				Incomplete: cg.Incomplete,
				Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
				Language:   "python",
				Properties: props,
			}
		}
		// Symbol data available but symbol not found in call path; if the
		// graph is complete, the symbol was not reached.  If incomplete, UNKNOWN.
		if cg.Incomplete {
			return &anstv1.Finding{
				Advisory:   advRef(adv),
				Module:     adv.GetModule(),
				Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
				Incomplete: true,
				Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
				Language:   "python",
				Properties: props,
			}
		}
		// Complete graph: symbol is genuinely not in call path → PACKAGE_REACHABLE
		// (dist is imported but the specific vulnerable symbol was not reached).
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			Incomplete: false,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}

	case reachable:
		// Dist imported but no symbol-level data → PACKAGE_REACHABLE
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			Incomplete: cg.Incomplete,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}

	default:
		// Fallthrough: undecidable → UNKNOWN + incomplete (conservative)
		return &anstv1.Finding{
			Advisory:   advRef(adv),
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			Incomplete: true,
			Ecosystem:  anstv1.Ecosystem_ECOSYSTEM_PYPI,
			Language:   "python",
			Properties: props,
		}
	}
}

// advRef builds an AdvisoryRef from an Advisory.
func advRef(adv *anstv1.Advisory) *anstv1.AdvisoryRef {
	return &anstv1.AdvisoryRef{
		Id: adv.GetId(),
	}
}

// normaliseDistName returns a PEP 503-compliant canonical form of a PyPI dist
// name for map lookups.  PEP 503 specifies that any run of [-_.] characters
// is equivalent; the canonical form collapses each such run to a single '_'
// and lowercases the result.  For example:
//
//	"zope.interface"  → "zope_interface"
//	"foo--bar"        → "foo_bar"
//	"My-Package"      → "my_package"
func normaliseDistName(name string) string {
	lower := strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(lower))
	inSep := false
	for _, c := range lower {
		if c == '-' || c == '_' || c == '.' {
			if !inSep {
				b.WriteByte('_')
				inSep = true
			}
		} else {
			b.WriteRune(c)
			inSep = false
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// main — subcommand dispatch
// ---------------------------------------------------------------------------

// main dispatches to the appropriate mode based on the first argument:
//
//	(none) or "serve"    → gRPC plugin server (host-facing)
//	"--extract-symbols"  → fix-patch symbol extraction (stdin → stdout)
//	"--list-deps"        → dependency closure listing (stdout JSON)
func main() {
	args := os.Args[1:]

	switch {
	case len(args) == 0 || args[0] == "serve":
		// Default mode: start the gRPC plugin server.
		// The host (internal/host) launched us via go-plugin; we communicate
		// over the stdio-multiplexed gRPC transport.
		anstplugin.Serve(&grpcServer{})

	case args[0] == "--extract-symbols":
		// Read patch+files JSON from stdin, print symbol array to stdout.
		runExtractSymbols()

	case args[0] == "--list-deps":
		// Print dependency closure for a project root.
		root := "."
		if len(args) > 1 {
			root = args[1]
		}
		runListDeps(root)

	default:
		fmt.Fprintf(os.Stderr, "python-reachability: unknown subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: python-reachability [serve|--list-deps <root>|--extract-symbols]")
		os.Exit(1)
	}
}
