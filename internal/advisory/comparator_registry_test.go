package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestComparatorRegistry_BuiltInEcosystemsRegistered verifies that all four
// built-in ecosystem comparators are present after package init().
func TestComparatorRegistry_BuiltInEcosystemsRegistered(t *testing.T) {
	t.Parallel()

	for _, eco := range []string{EcosystemGo, EcosystemNPM, EcosystemCratesIO, EcosystemPyPI} {
		assert.NotNilf(t, lookupComparator(eco),
			"built-in ecosystem %q must have a registered comparator", eco)
	}
}

// TestComparatorRegistry_UnknownEcosystemReturnsNil verifies that an ecosystem
// with no registered comparator returns nil from lookupComparator.
func TestComparatorRegistry_UnknownEcosystemReturnsNil(t *testing.T) {
	t.Parallel()

	assert.Nil(t, lookupComparator("NoSuchEcosystem"))
}

// TestComparatorRegistry_RegisterDuplicatePanics verifies that registering the
// same ecosystem twice panics — it is a programming error, not a runtime one.
func TestComparatorRegistry_RegisterDuplicatePanics(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		RegisterComparator(EcosystemGo, versionInRangeV)
	}, "registering a duplicate ecosystem comparator must panic")
}

// TestComparatorRegistry_UnregisteredEcosystemIsUndecidable verifies that
// AffectsVersionV on an unregistered ecosystem returns VersionUndecidable and
// never VersionNotAffected. An unregistered ecosystem must not silently drop
// advisories — that would be a false negative.
func TestComparatorRegistry_UnregisteredEcosystemIsUndecidable(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     "UnregisteredEcosystem",
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("1.5.0"),
		"unregistered ecosystem must return VersionUndecidable, never VersionNotAffected")
}

// TestComparatorRegistry_RouteGo verifies the registry routes EcosystemGo
// through Go semver (versionInRangeV), which requires "v"-prefixed versions.
func TestComparatorRegistry_RouteGo(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemGo,
		VersionRanges: []VersionRange{{Introduced: "v1.0.0", Fixed: "v2.0.0"}},
	}
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("v1.5.0"),
		"Go v1.5.0 inside [v1.0.0, v2.0.0) must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("v2.0.0"),
		"Go v2.0.0 == fixed (exclusive upper bound) must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("v0.9.0"),
		"Go v0.9.0 < introduced v1.0.0 must be NotAffected")
}

// TestComparatorRegistry_RouteNPM verifies the registry routes EcosystemNPM
// through npm/node-semver semantics.
func TestComparatorRegistry_RouteNPM(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemNPM,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("1.5.0"),
		"npm 1.5.0 inside [1.0.0, 2.0.0) must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.0.0"),
		"npm 2.0.0 == fixed (exclusive) must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("0.9.0"),
		"npm 0.9.0 < introduced 1.0.0 must be NotAffected")
}

// TestComparatorRegistry_RouteCratesIO verifies the registry routes
// EcosystemCratesIO through Cargo SemVer, stripping the "v" prefix that
// canonical() adds before calling cargoVersionInRangeV.
func TestComparatorRegistry_RouteCratesIO(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemCratesIO,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	// canonical() adds "v"; the registry wrapper must strip it for Cargo.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV(canonical("1.5.0")),
		"crates.io 1.5.0 inside [1.0.0, 2.0.0) must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("2.0.0")),
		"crates.io 2.0.0 == fixed (exclusive) must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV(canonical("0.9.0")),
		"crates.io 0.9.0 < introduced 1.0.0 must be NotAffected")
}

// TestComparatorRegistry_RoutePyPI verifies the registry routes EcosystemPyPI
// through PEP 440 semantics.
func TestComparatorRegistry_RoutePyPI(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemPyPI,
		VersionRanges: []VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("1.5.0"),
		"PyPI 1.5.0 inside [1.0.0, 2.0.0) must be Affected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.0.0"),
		"PyPI 2.0.0 == fixed (exclusive) must be NotAffected")
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("0.9.0"),
		"PyPI 0.9.0 < introduced 1.0.0 must be NotAffected")
}

// TestComparatorRegistry_GoUndecidableOnBadVersion verifies that an
// unparseable version propagates as VersionUndecidable through the registry
// path (not silently not-affected).
func TestComparatorRegistry_GoUndecidableOnBadVersion(t *testing.T) {
	t.Parallel()

	adv := &Advisory{
		Ecosystem:     EcosystemGo,
		VersionRanges: []VersionRange{{Introduced: "v1.0.0", Fixed: "v2.0.0"}},
	}
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("notaversion"),
		"unparseable Go version must propagate as VersionUndecidable via the registry")
}
