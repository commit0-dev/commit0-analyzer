package cli

import (
	"fmt"
)

// ResolvedDep is a single dependency from a Lane-A lockfile parse.
// It carries the minimum information needed for an OSV advisory query and
// dep-type segmentation (the dev_only gate).
type ResolvedDep struct {
	// Name is the ecosystem-specific package name (e.g. "org.springframework:spring-core").
	Name string
	// Version is the resolved version string from the lockfile.
	Version string
	// DepType is the dependency classification from the lockfile:
	// "runtime", "dev", "test", "optional", or "" (unknown, treated as runtime by the gate).
	// Dep-type segmentation is only possible when the lockfile explicitly records it;
	// if the format does not encode dep-type, tag all deps as "" (not as "runtime") so
	// the caller can log that segmentation was unavailable rather than silently assuming runtime.
	DepType string
}

// LaneAAdapter describes a Lane-A (lockfile-only) ecosystem.
//
// Lane-A ecosystems do not require a reachability plugin. The host parses the
// lockfile statically to obtain the resolved dependency closure, then queries
// OSV advisories for each dependency. The maximum confidence for Lane-A findings
// is PACKAGE_REACHABLE (the vulnerable package is present in the closure);
// SYMBOL_REACHABLE is not possible because OSV advisory records carry no
// method/function-level data for these ecosystems.
//
// Security invariants:
//   - ParseLockfile MUST parse only the lockfile (or other static declarative
//     artifacts). It MUST NOT evaluate the build manifest (Gemfile, mix.exs,
//     Package.swift, conanfile.py, build.gradle[.kts] are executable code —
//     running them on an untrusted repo is arbitrary code execution).
//   - ParseLockfile MUST NOT run a build tool or its repo wrapper (mvn, gradle,
//     ./mvnw, ./gradlew, dotnet restore, bundle install, mix deps.get, etc.)
//     unless the tool is sandboxed (network-denied, dropped privileges, fixed-path
//     toolchain). If a tool must run and cannot be sandboxed, return complete=false.
type LaneAAdapter struct {
	// Ecosystem is the OSV ecosystem name (e.g. "Maven", "NuGet", "Packagist").
	// This value is passed to OSVBundleSource.Refresh and used as the Package.Ecosystem
	// when querying advisories.
	Ecosystem string

	// Language is the --language flag value for this ecosystem (e.g. "java").
	// It must match the value accepted by resolveLanguage and appear in its
	// error message so users can select this ecosystem explicitly.
	Language string

	// DetectFiles is a list of filenames; if ANY exists in the module root, this
	// ecosystem is considered present. Detection is zero-config: the adapter runs
	// automatically when `commit0-analyzer scan <path>` is invoked (no --language flag needed).
	// At least one entry must be a lockfile (not only an executable manifest) to
	// avoid the ACE risk of detecting a manifest-only project and then running the
	// build tool to resolve deps.
	DetectFiles []string

	// ParseLockfile parses the lockfile(s) at root and returns the resolved dep closure.
	//
	// Contract:
	//   - complete=true: closure is the fully-resolved transitive dep closure; the
	//     caller proceeds to query OSV for each dep. An empty closure with complete=true
	//     is valid (project has no dependencies).
	//   - complete=false: the closure could not be resolved (missing lockfile, parse
	//     error, or the resolver requires running a build tool). The caller MUST set
	//     incomplete=true and skip the OSV query for this ecosystem. NEVER return
	//     a partial closure with complete=false — that would produce false
	//     NOT_REACHABLE for the missing portion.
	//   - err non-nil implies complete=false. Return both for caller convenience
	//     (the caller checks complete first, then logs err if non-nil).
	ParseLockfile func(root string) (closure []ResolvedDep, complete bool, err error)

	// NormalizeName optionally transforms a package name from the lockfile before
	// it is passed to the OSV advisory query. This allows adapter-specific
	// normalization (e.g. case folding for case-insensitive registries).
	//
	// If nil, the name is used as-is (identity). Adapter authors MUST set this
	// only when the OSV index for the ecosystem uses a different canonical form
	// than the lockfile. Maven coordinates are case-sensitive and are preserved
	// in OSV records; do NOT set NormalizeName for Maven adapters. PyPI names
	// are case-insensitive; a future PyPI adapter would set NormalizeName to
	// strings.ToLower (or a PEP-503-compliant normalizer).
	NormalizeName func(name string) string
}

// laneARegistry is the global adapter registry. Adapters are appended at
// package init time by init() in this file (and potentially future adapter
// files in this package). Access is not synchronized; all writes happen during
// init, all reads happen during scan (after init completes).
var laneARegistry []LaneAAdapter

// laneALanguageKnown reports whether lang is handled by the switch statements
// in setLaneAFlag, clearLaneAFlag, and laneAAdapterActive. It works by probing
// setLaneAFlag: if the language is known, some ecosystems field will be set.
// Used by RegisterLaneAAdapter to catch silent-no-op registration at init time.
func laneALanguageKnown(lang string) bool {
	var probe ecosystems
	setLaneAFlag(&probe, lang)
	return probe != (ecosystems{})
}

// RegisterLaneAAdapter appends an adapter to the global registry.
// Must be called only from init() functions (before any concurrent use).
//
// Panics if the adapter's Language is not handled by setLaneAFlag /
// laneAAdapterActive. This catches the "silent no-op" trap: an adapter whose
// Language lacks a switch case would be detected (DetectFiles match) but never
// run, with no warning to the operator. The panic surfaces the gap at process
// start rather than silently dropping coverage.
func RegisterLaneAAdapter(a LaneAAdapter) {
	if !laneALanguageKnown(a.Language) {
		panic(fmt.Sprintf(
			"RegisterLaneAAdapter: language %q is not handled by setLaneAFlag / laneAAdapterActive; "+
				"add a case for %q in all three switch statements in ecosystem_registry.go "+
				"before registering this adapter",
			a.Language, a.Language))
	}
	laneARegistry = append(laneARegistry, a)
}

// LaneAAdapters returns a snapshot of the registered Lane-A adapters.
// The returned slice is a copy; modifications do not affect the registry.
func LaneAAdapters() []LaneAAdapter {
	out := make([]LaneAAdapter, len(laneARegistry))
	copy(out, laneARegistry)
	return out
}

// laneAAdapterActive reports whether a Lane-A adapter should run in the current
// scan given the ecosystem detection result. The switch maps adapter Language
// values to the corresponding bool field in the ecosystems struct.
//
// Coupling note: this function and setLaneAFlag / clearLaneAFlag below are the
// only places that couple adapter Language strings to ecosystems struct fields.
// When a new Lane-A ecosystem is added that needs an ecosystems bit, add a case
// in all three functions and a new bool field in ecosystems.
func laneAAdapterActive(lang string, eco ecosystems) bool {
	switch lang {
	case "java":
		return eco.hasJava
	case "dotnet":
		return eco.hasDotnet
	case "php":
		return eco.hasPhp
	case "ruby":
		return eco.hasRuby
	case "elixir":
		return eco.hasElixir
	case "dart":
		return eco.hasDart
	case "swift":
		return eco.hasSwift
	default:
		return false
	}
}

// setLaneAFlag sets the ecosystems flag corresponding to the given adapter Language.
// Called from detectEcosystems to apply registry-driven detection results to the
// ecosystems struct without hardcoding detect-file names in detectEcosystems.
func setLaneAFlag(e *ecosystems, lang string) {
	switch lang {
	case "java":
		e.hasJava = true
	case "dotnet":
		e.hasDotnet = true
	case "php":
		e.hasPhp = true
	case "ruby":
		e.hasRuby = true
	case "elixir":
		e.hasElixir = true
	case "dart":
		e.hasDart = true
	case "swift":
		e.hasSwift = true
	}
}

// clearLaneAFlag clears the ecosystems flag corresponding to the given adapter Language.
// Called in runScan after the Lane-A registry loop has handled an adapter, so that
// warnUnsupportedEcosystems does not emit a duplicate warning for the same ecosystem.
func clearLaneAFlag(e *ecosystems, lang string) {
	switch lang {
	case "java":
		e.hasJava = false
	case "dotnet":
		e.hasDotnet = false
	case "php":
		e.hasPhp = false
	case "ruby":
		e.hasRuby = false
	case "elixir":
		e.hasElixir = false
	case "dart":
		e.hasDart = false
	case "swift":
		e.hasSwift = false
	}
}

// mergeDepType updates depTypeByAdvID for the given advisory ID.
//
// Conservative semantics (must be used by ALL resolve paths: Python, Lane-A, etc.):
//   - "runtime" wins over any other type; once set to "runtime" it cannot be downgraded.
//   - An empty depType is treated as "runtime" (unknown dep-type must NOT default to
//     "dev" — that would cause the dev_only gate to suppress a runtime-reachable vuln,
//     a false-clean pass violating the "unknown ≠ safe" invariant).
//   - A non-runtime type is stored only when no prior entry exists for this advisory.
//     Subsequent non-runtime types do not overwrite the first (keeps deterministic output).
//
// The dep_type field populated here drives the dev_only policy gate. Any deviation
// from this function's semantics is a security-relevant correctness bug.
func mergeDepType(depTypeByAdvID map[string]string, advID, depType string) {
	existing, ok := depTypeByAdvID[advID]
	if ok && existing == "runtime" {
		return // already runtime; cannot be downgraded
	}
	dt := depType
	if dt == "" {
		dt = "runtime" // conservative: unknown dep-type defaults to runtime
	}
	if dt == "runtime" {
		depTypeByAdvID[advID] = "runtime"
	} else if !ok {
		// First non-runtime dep for this advisory; record it.
		depTypeByAdvID[advID] = dt
	}
	// dt != "runtime" && ok (e.g. a second "test" dep after an initial "dev"):
	// keep the initial value; do not overwrite with a possibly-different non-runtime type.
}

// Java (JVM) Lane-A adapter registration has moved to ecosystem_maven.go.
// That file registers the real gradle.lockfile-static parser; there is no
// longer a Phase-0 stub here. Removing the stub ensures the scan loop sees
// only one Java adapter and can reach complete=true for gradle.lockfile
// projects (the stub's complete=false previously forced incomplete=true even
// when the real adapter succeeded).
