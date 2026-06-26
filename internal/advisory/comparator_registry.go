package advisory

import (
	"strings"
	"sync"
)

// ComparatorFunc is the signature for an ecosystem-specific version range
// comparator. It receives the query version (canonical form, may carry a "v"
// prefix depending on the ecosystem) and a single VersionRange, and returns a
// tri-state verdict.
//
// Contract:
//   - Parse errors MUST return VersionUndecidable, never VersionNotAffected.
//     An undecidable verdict propagates upward as a synthetic UNKNOWN finding
//     with incomplete=true — it is never silently dropped.
//   - The function MUST be safe to call concurrently from multiple goroutines.
type ComparatorFunc func(version string, r VersionRange) VersionVerdict

var (
	comparatorMu       sync.RWMutex
	comparatorRegistry = map[string]ComparatorFunc{}
)

// RegisterComparator registers a version-range comparator for the given
// ecosystem. It is intended to be called from package-level init() functions
// so that each language can register its comparator in its own file without
// editing a shared switch.
//
// Registering the same ecosystem twice panics — this is a programming error
// that must be caught at startup, not silently overwritten.
func RegisterComparator(ecosystem string, fn ComparatorFunc) {
	comparatorMu.Lock()
	defer comparatorMu.Unlock()
	if _, exists := comparatorRegistry[ecosystem]; exists {
		panic("advisory: comparator already registered for ecosystem " + ecosystem)
	}
	comparatorRegistry[ecosystem] = fn
}

// lookupComparator returns the registered comparator for ecosystem, or nil when
// no comparator has been registered. The caller is responsible for treating nil
// as an unroutable (undecidable) ecosystem.
func lookupComparator(ecosystem string) ComparatorFunc {
	comparatorMu.RLock()
	defer comparatorMu.RUnlock()
	return comparatorRegistry[ecosystem]
}

// init registers all built-in comparators. New ecosystems add their comparator
// in their own file's init() — they must NOT edit this block.
func init() {
	// Go: standard Go module semver (requires "v"-prefixed canonical form).
	RegisterComparator(EcosystemGo, versionInRangeV)

	// npm: node-semver semantics (bare versions, no "v" prefix required).
	RegisterComparator(EcosystemNPM, npmVersionInRangeV)

	// crates.io: Cargo SemVer. The call path applies canonical() which adds a
	// leading "v"; strip it here because cargoVersionInRangeV expects bare
	// versions (e.g. "1.2.3" not "v1.2.3").
	RegisterComparator(EcosystemCratesIO, func(version string, r VersionRange) VersionVerdict {
		return cargoVersionInRangeV(strings.TrimPrefix(version, "v"), r)
	})

	// PyPI: PEP 440 semantics (ECOSYSTEM type in OSV, not SEMVER).
	RegisterComparator(EcosystemPyPI, pep440VersionInRangeV)
}
