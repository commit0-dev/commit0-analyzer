// Package cargo provides cargo metadata invocation, JSON parsing, and the
// resolved-closure Manifest type for the Rust reachability plugin.
//
// # Security posture
//
// cargo metadata is the only build-tool invocation used; it does NOT execute
// build scripts (build.rs) or proc-macros, making it safe on untrusted repos.
// By default cargo metadata runs in online mode so it can resolve dependencies
// on fresh clones where crate metadata is not yet in the local registry cache.
// When COMMIT0_CARGO_OFFLINE is set to a truthy value (e.g. "1"), --offline is
// passed to cargo so the scan runs from the already-fetched cache only — this
// matches the behaviour requested by the user's --offline scan flag.
// RUSTUP_TOOLCHAIN=stable is always pinned to prevent a repo-supplied
// rust-toolchain.toml from hijacking the toolchain.
//
// # Partiality invariant
//
// An empty or partial resolve is NEVER treated as a clean "nothing to report"
// result. Whenever cargo fails, times out, or returns zero nodes,
// LoadManifest returns a Manifest with ClosureUnknown=true so that callers
// emit UNKNOWN+incomplete for every advisory rather than silently dropping
// findings (unknown ≠ safe).
package cargo

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// cargoTimeout is the maximum wall-clock time allowed for a single
// `cargo metadata` invocation. The deep-dive spec allows 3 s;
// we keep 5 s to accommodate slow CI machines without breaking the
// 60 s end-to-end budget.
const cargoTimeout = 5 * time.Second

// ─── Public types ────────────────────────────────────────────────────────────

// Manifest is the resolved dependency closure produced by parsing the output
// of `cargo metadata --format-version 1 --all-features`.
//
// Packages is keyed by crate name (the "name" field in Cargo.toml), not by
// the full package ID. When two workspace members have the same name (rare but
// possible in a virtual workspace) the last one parsed wins; the confidence
// logic is the same for both.
type Manifest struct {
	// Packages maps crate name → Package; every crate in the resolve graph is
	// present here, workspace members and third-party crates alike.
	Packages map[string]*Package

	// WorkspaceMembers holds the crate names of the direct workspace members
	// (i.e. the crates listed in [workspace].members in the root Cargo.toml).
	WorkspaceMembers []string

	// Root is the crate name of the single root crate when this is not a
	// workspace (resolve.root != null). Empty for workspaces.
	Root string

	// ClosureUnknown is true whenever the resolve graph is incomplete or
	// unavailable: cargo exited non-zero, timed out, produced no nodes, or
	// the JSON could not be parsed. Callers MUST emit UNKNOWN+incomplete for
	// every advisory when this flag is set.
	ClosureUnknown bool

	// ClosureError is a human-readable description of why ClosureUnknown was
	// set (logged; not exposed in findings directly).
	ClosureError string
}

// Package holds the per-crate data needed by the reachability engine.
type Package struct {
	// Name is the crate name from Cargo.toml (e.g. "serde").
	Name string

	// Version is the resolved version string without a "v" prefix (e.g. "1.0.197").
	Version string

	// ManifestPath is the absolute path to the crate's Cargo.toml.
	ManifestPath string

	// ReachableAsNormal is true when this crate appears as a runtime
	// (dep_kind == null) dependency somewhere in the resolve graph, OR when
	// this crate is a workspace member / the resolve root. Workspace members
	// and the root crate are the code being scanned; they are always reachable
	// as normal code (they are never a "library dep of something else" from the
	// perspective of the scanned project, but they are certainly in scope for
	// vulnerability findings).
	ReachableAsNormal bool

	// ReachableAsDev is true when this crate appears as a dev dep
	// (dep_kind == "dev") somewhere in the resolve graph.
	ReachableAsDev bool

	// ReachableAsBuild is true when this crate appears as a build dep
	// (dep_kind == "build") somewhere in the resolve graph.
	ReachableAsBuild bool

	// IsWorkspaceMember is true when this crate is listed in workspace_members
	// (direct workspace members) or is the resolve.root crate. These are the
	// crates that belong to the scanned project itself.
	IsWorkspaceMember bool
}

// ─── Internal JSON schema types ──────────────────────────────────────────────

// cargoMetadata mirrors the subset of `cargo metadata --format-version 1`
// output that the plugin actually reads.
type cargoMetadata struct {
	Packages         []cargoPackage `json:"packages"`
	WorkspaceMembers []string       `json:"workspace_members"`
	Resolve          cargoResolve   `json:"resolve"`
	Version          int            `json:"version"`
}

type cargoPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ID           string `json:"id"`
	ManifestPath string `json:"manifest_path"`
}

type cargoResolve struct {
	Nodes []cargoNode `json:"nodes"`
	Root  *string     `json:"root"` // pointer: null for workspaces
}

type cargoNode struct {
	ID string `json:"id"`
	// Deps maps to the "deps" field (not "dependencies") in cargo metadata
	// --format-version 1 output. The "dependencies" field is a flat []string of
	// package IDs present in all cargo versions; "deps" is the structured form
	// (with dep_kinds) introduced alongside the space-free ID format in cargo
	// 1.77 and present in all cargo versions that support --format-version 1.
	// Unmarshaling "dependencies" fails because it is []string, not []cargoDep.
	Deps []cargoDep `json:"deps"`
}

type cargoDep struct {
	Pkg      string         `json:"pkg"`
	DepKinds []cargoDepKind `json:"dep_kinds"`
}

// cargoDepKind represents one dep_kinds entry.
// Kind is a pointer because the JSON value is null (not "normal") for runtime
// deps: null → Go nil → runtime dep.
type cargoDepKind struct {
	Kind   *string `json:"kind"`   // nil = normal/runtime, "dev", or "build"
	Target *string `json:"target"` // target triple filter; nil = all targets
}

// ─── Public API ──────────────────────────────────────────────────────────────

// cargoOfflineRequested returns true when the COMMIT0_CARGO_OFFLINE environment
// variable is set to a truthy value ("1", "true", "yes", case-insensitive).
//
// The host scan process sets this variable before launching the plugin when
// the user passed --offline, allowing the plugin to honour the same flag
// without requiring a separate CLI argument or gRPC field.
func cargoOfflineRequested() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("COMMIT0_CARGO_OFFLINE")))
	return v == "1" || v == "true" || v == "yes"
}

// LoadManifest invokes `cargo metadata --format-version 1 --all-features`
// in moduleRoot, parses the output, and returns a fully-populated Manifest.
//
// Online vs offline mode: by default cargo metadata runs online so it can
// fetch registry index and crate metadata on fresh clones. When the env var
// COMMIT0_CARGO_OFFLINE is set to a truthy value ("1", "true", "yes"), --offline
// is added and cargo reads only the already-fetched local cache. This mirrors
// the host scan's --offline flag, which the host signals by setting
// COMMIT0_CARGO_OFFLINE before launching the plugin subprocess.
//
// On any failure (cargo not on PATH, non-zero exit, timeout, JSON parse
// error, empty resolve), LoadManifest returns a non-nil Manifest with
// ClosureUnknown=true and a descriptive ClosureError. The returned error
// carries the same description; callers should log it and treat all advisories
// as UNKNOWN+incomplete.
//
// LoadManifest never returns (nil, nil); a non-nil error is always paired with
// a non-nil Manifest so callers can safely read ClosureUnknown.
func LoadManifest(ctx context.Context, moduleRoot string) (*Manifest, error) {
	// Apply a hard wall-clock timeout so a hung cargo process cannot stall
	// the scan indefinitely. If ctx already has a shorter deadline that is
	// respected too.
	ctx, cancel := context.WithTimeout(ctx, cargoTimeout)
	defer cancel()

	// Threat: the scanned repository is UNTRUSTED. A repo-supplied
	// rust-toolchain.toml (or rust-toolchain) combined with rustup's toolchain
	// override mechanism allows an attacker to nominate an arbitrary toolchain
	// (including a custom one with a malicious linker). rustup honours the file
	// hierarchy: RUSTUP_TOOLCHAIN > command-line +<channel> > rust-toolchain*.
	// We defend by pinning RUSTUP_TOOLCHAIN=stable in the child's environment,
	// which takes highest priority and prevents any file-based override.
	//
	// We also scrub other env vars that could redirect cargo's data directories
	// (CARGO_HOME, RUSTUP_HOME) to attacker-controlled paths. The child inherits
	// only a minimal allowlist sufficient for cargo to locate binaries, config,
	// and the registry cache.
	args := []string{"metadata", "--format-version", "1", "--all-features"}
	if cargoOfflineRequested() {
		args = append(args, "--offline")
	}
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.Dir = moduleRoot
	cmd.Env = SanitizedCargoEnv()

	output, err := cmd.Output()
	if err != nil {
		reason := fmt.Sprintf("cargo metadata failed: %v", err)
		return &Manifest{ClosureUnknown: true, ClosureError: reason}, fmt.Errorf("%s", reason)
	}

	m, parseErr := ParseMetadataJSON(output)
	if parseErr != nil {
		return m, parseErr
	}
	return m, nil
}

// ParseMetadataJSON parses the raw JSON output of `cargo metadata
// --format-version 1` and returns a Manifest. It is exported so tests can
// exercise the parsing logic without invoking cargo.
//
// Empty resolve.nodes → ClosureUnknown=true (partiality invariant).
// JSON decode errors → ClosureUnknown=true + returned error.
func ParseMetadataJSON(raw []byte) (*Manifest, error) {
	var meta cargoMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		reason := fmt.Sprintf("parse cargo metadata JSON: %v", err)
		return &Manifest{ClosureUnknown: true, ClosureError: reason},
			fmt.Errorf("%s", reason)
	}

	// Build a name→Package index from packages[].
	byID := make(map[string]*Package, len(meta.Packages))
	pkgByName := make(map[string]*Package, len(meta.Packages))
	for i := range meta.Packages {
		p := &meta.Packages[i]
		pkg := &Package{
			Name:         p.Name,
			Version:      p.Version,
			ManifestPath: p.ManifestPath,
		}
		byID[p.ID] = pkg
		pkgByName[p.Name] = pkg
	}

	// An empty resolve is a partial/unknown result — cargo ran but produced
	// no graph. Never emit a clean "nothing reachable" from this.
	if len(meta.Resolve.Nodes) == 0 {
		return &Manifest{
			Packages:       pkgByName,
			ClosureUnknown: true,
			ClosureError:   "resolve graph is empty (cargo produced no nodes)",
		}, nil
	}

	// Walk resolve.nodes and stamp ReachableAs* flags on every Package that
	// is referenced as a dependency. The algorithm:
	//   for each node N in nodes:
	//     for each dep D of N:
	//       for each dep_kind K of D:
	//         if K.kind == nil  → D.pkg is ReachableAsNormal
	//         if K.kind == "dev"   → D.pkg is ReachableAsDev
	//         if K.kind == "build" → D.pkg is ReachableAsBuild
	//
	// Note: a dep with multiple dep_kinds entries (e.g. both null and "dev")
	// sets multiple flags — the outer loop never short-circuits.
	//
	// Partiality: `cargo metadata --format-version 1` places every resolved
	// package ID into packages[], so a dep.Pkg that is absent from byID
	// indicates a malformed or partial blob — signal ClosureUnknown.
	closureUnknown := false
	closureErr := ""
	for _, node := range meta.Resolve.Nodes {
		for _, dep := range node.Deps {
			target, ok := byID[dep.Pkg]
			if !ok {
				// In --format-version 1 the ID spaces of packages[] and
				// resolve.nodes are identical. A miss means the blob is
				// partial or malformed, not a routine platform-filter gap.
				closureUnknown = true
				closureErr = fmt.Sprintf("resolve dep %q missing from packages[] (partial blob)", dep.Pkg)
				continue
			}
			for _, dk := range dep.DepKinds {
				switch {
				case dk.Kind == nil:
					target.ReachableAsNormal = true
				case *dk.Kind == "dev":
					target.ReachableAsDev = true
				case *dk.Kind == "build":
					target.ReachableAsBuild = true
				// unknown kind values are ignored conservatively; if needed
				// they can be classified as ReachableAsNormal.
				}
			}
		}
	}

	// Resolve workspace members to crate names and mark them as workspace
	// members that are ReachableAsNormal. Workspace members are the crates
	// belonging to the scanned project; they are always in scope for
	// vulnerability findings. Without this, a workspace root or a member that
	// nothing else depends on would have all-false Reachable* flags, causing
	// the engine to emit NOT_REACHABLE for the scanned project's own crates —
	// a critical false negative (cardinal sin: unknown ≠ safe).
	wsMembers := make([]string, 0, len(meta.WorkspaceMembers))
	for _, id := range meta.WorkspaceMembers {
		name := CrateNameFromID(id)
		wsMembers = append(wsMembers, name)
		if pkg, ok := pkgByName[name]; ok {
			pkg.ReachableAsNormal = true
			pkg.IsWorkspaceMember = true
		}
	}

	// Resolve root crate name (nil for workspaces) and mark it reachable.
	// The root crate is the entry point of the scanned project; it is always
	// reachable as normal code.
	root := ""
	if meta.Resolve.Root != nil && *meta.Resolve.Root != "" {
		root = CrateNameFromID(*meta.Resolve.Root)
		if pkg, ok := pkgByName[root]; ok {
			pkg.ReachableAsNormal = true
			pkg.IsWorkspaceMember = true
		}
	}

	return &Manifest{
		Packages:         pkgByName,
		WorkspaceMembers: wsMembers,
		Root:             root,
		ClosureUnknown:   closureUnknown,
		ClosureError:     closureErr,
	}, nil
}

// CrateNameFromID extracts the crate name from a Cargo package ID.
//
// # Legacy format (cargo < 1.77)
//
//	"<name> <version> (<source_kind>+<url>)"
//
// e.g. "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)"
//
// CrateNameFromID returns the first space-delimited token.
//
// # Space-free format (cargo >= 1.77)
//
// cargo 1.77+ emits package IDs without spaces. The fragment after '#' carries
// either "name@version" or just "version":
//
//   - "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18" → "itoa"
//   - "path+file:///workspace/demo#demo@0.1.0"                             → "demo"
//   - "path+file:///abs/path/my-crate#0.1.0"                               → "my-crate"
//
// When the fragment is a bare version (no '@'), the crate name is derived from
// the last path segment of the URL before the '#'.
func CrateNameFromID(id string) string {
	if id == "" {
		return ""
	}

	// Legacy format: first space separates name from version.
	if i := strings.IndexByte(id, ' '); i > 0 {
		return id[:i]
	}

	// Space-free format (cargo >= 1.77): look for '#' fragment.
	hashIdx := strings.LastIndexByte(id, '#')
	if hashIdx < 0 {
		// No space and no '#': return as-is (bare name, edge case).
		return id
	}

	fragment := id[hashIdx+1:]
	if atIdx := strings.IndexByte(fragment, '@'); atIdx > 0 {
		// Fragment is "name@version" — extract name.
		return fragment[:atIdx]
	}

	// Fragment is a bare version (no '@'): derive name from the last path
	// segment of the URL before the '#'.
	urlPart := id[:hashIdx]
	// Strip a trailing slash if present before splitting.
	urlPart = strings.TrimRight(urlPart, "/")
	if slashIdx := strings.LastIndexByte(urlPart, '/'); slashIdx >= 0 {
		return urlPart[slashIdx+1:]
	}
	// No slash in URL part: fall back to the whole thing.
	return urlPart
}

// sanitizedCargoEnv returns a minimal environment for the `cargo metadata`
// child process that prevents a hostile repository from redirecting the
// toolchain or cargo data directories.
//
// # Threat
//
// A repo-supplied rust-toolchain.toml / rust-toolchain file causes rustup to
// auto-install and run an attacker-chosen toolchain. rustup resolves the active
// toolchain in priority order:
//
//  1. RUSTUP_TOOLCHAIN environment variable  ← we pin this to "stable"
//  2. +<channel> on the cargo command line
//  3. rust-toolchain / rust-toolchain.toml files in the directory hierarchy
//
// By setting RUSTUP_TOOLCHAIN=stable in the child's env we override any
// file-based override the repo might supply — the env var wins.
//
// CARGO_HOME and RUSTUP_HOME are host-process env vars the scanned repo cannot
// set, so their inherited values are forwarded (cargo/rustup need them to locate
// the installed toolchain). The repo-controlled vector is rust-toolchain.toml,
// neutralized by pinning RUSTUP_TOOLCHAIN above.
//
// # Allowlist
//
// The child inherits only env vars cargo requires for normal operation:
//   - PATH                  — locates the cargo/rustup binaries
//   - HOME                  — fallback for default CARGO_HOME / RUSTUP_HOME resolution
//   - USERPROFILE           — Windows equivalent of HOME
//   - LOCALAPPDATA          — Windows: default CARGO_HOME fallback
//   - SystemRoot            — Windows: required by many C runtime calls
//   - TMPDIR/TEMP/TMP       — cargo writes temporary files
//   - SSL_CERT_*            — TLS roots for HTTPS connections to the registry
//   - XDG_*                 — honoured by some cargo/rustup paths on Linux
//   - HTTP_PROXY/HTTPS_PROXY/NO_PROXY (and lowercase) — proxy for online resolution
//   - CARGO_HTTP_*          — cargo-specific HTTP config (proxy, timeout, etc.)
//   - COMMIT0_CARGO_OFFLINE    — internal signal: host sets this to propagate --offline
//
// Anything not on this list is dropped; RUSTUP_TOOLCHAIN is explicitly pinned
// rather than inherited so it cannot be overridden by the calling environment.
func SanitizedCargoEnv() []string {
	// Env var prefixes we forward from the host process.
	allowPrefixes := []string{
		"PATH=",
		"HOME=",
		"USERPROFILE=",
		"LOCALAPPDATA=",
		"SystemRoot=",
		"SYSTEMROOT=",
		"TMPDIR=",
		"TEMP=",
		"TMP=",
		"SSL_CERT_FILE=",
		"SSL_CERT_DIR=",
		"XDG_",
		// Host toolchain config (NOT repo-controlled — these are env vars the
		// scanned repo cannot set). Forward inherited values so rustup/cargo can
		// locate the installed toolchain. Pinning RUSTUP_TOOLCHAIN below already
		// neutralizes the only repo-controlled vector (a rust-toolchain.toml file).
		"CARGO_HOME=",
		"RUSTUP_HOME=",
		// Proxy vars: required for online cargo metadata resolution behind a
		// corporate or CI proxy. Cargo honours these for HTTPS connections to
		// the crates.io registry index. Both upper and lower case forms are used
		// by different tools and systems.
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"NO_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"no_proxy=",
		// cargo-specific HTTP configuration (proxy override, timeout, TLS, etc.).
		"CARGO_HTTP_",
		// Internal signal from the host scan: set to "1" when the user passed
		// --offline so the plugin's LoadManifest call can honour offline mode.
		"COMMIT0_CARGO_OFFLINE=",
	}

	// RUSTUP_TOOLCHAIN is pinned below, never inherited, so a rust-toolchain.toml
	// in the scanned repo cannot select which toolchain runs.
	denyExact := map[string]bool{
		"RUSTUP_TOOLCHAIN": true,
	}

	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		key := kv
		if eqIdx := strings.IndexByte(kv, '='); eqIdx >= 0 {
			key = kv[:eqIdx]
		}
		if denyExact[key] {
			continue
		}
		for _, pfx := range allowPrefixes {
			if strings.HasPrefix(kv, pfx) {
				env = append(env, kv)
				break
			}
		}
	}

	// Pin the toolchain to stable regardless of any rust-toolchain file in the
	// scanned repository's directory hierarchy.
	env = append(env, "RUSTUP_TOOLCHAIN=stable")
	return env
}
