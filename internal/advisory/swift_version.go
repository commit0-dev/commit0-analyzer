package advisory

import "strings"

// swiftVersionInRangeV is the tri-state comparator for SwiftURL (Swift Package
// Manager) package versions registered under EcosystemSwiftURL.
//
// SwiftPM enforces SemVer 2.0 strictly — the same semantics as Cargo/Hex.
// This function strips any leading "v" prefix that canonical() may have added
// upstream, then delegates to the shared SemVer-2 base (cargoVersionInRangeV).
//
// Build metadata is NOT ordered (same as Hex, NOT like semver 2.0 §10 which
// says build metadata SHOULD be ignored for precedence). cargoVersionInRangeV
// already drops build metadata before comparison via golang.org/x/mod/semver,
// which follows SemVer 2.0 §10 (build metadata has no precedence), so this is
// correct.
//
// Returns:
//   - VersionAffected    — version falls within the range.
//   - VersionNotAffected — version is provably outside the range.
//   - VersionUndecidable — the query version or a range bound is not valid
//     SemVer 2.0.  Parse errors are NEVER silently treated as NotAffected;
//     callers MUST emit a synthetic UNKNOWN finding with incomplete=true.
//
// Range semantics (OSV schema):
//   - Introduced is an inclusive lower bound; empty means "since the beginning".
//   - Fixed is an exclusive upper bound; empty means "no fix yet".
//   - LastAffected is an inclusive upper bound; at most one of Fixed/LastAffected
//     is set per range.
//
// Prerelease ordering follows SemVer §11.1: a prerelease of a given
// major.minor.patch sorts BEFORE the release (1.0.0-rc.1 < 1.0.0).
func swiftVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// SwiftPM versions never carry a "v" prefix in Package.resolved. Strip it in
	// case the upstream pipeline ran canonical() (which adds "v") before calling here.
	return cargoVersionInRangeV(strings.TrimPrefix(version, "v"), r)
}

// init registers the SwiftURL ecosystem comparator into the shared registry.
// SwiftURL uses SemVer 2.0 identical to Cargo/Hex, so swiftVersionInRangeV is
// a thin wrapper — no bespoke parsing is required.
func init() {
	RegisterComparator(EcosystemSwiftURL, swiftVersionInRangeV)
}
