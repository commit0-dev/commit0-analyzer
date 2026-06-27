package advisory

import "strings"

// hexVersionInRangeV is the tri-state comparator for Hex (Elixir/Erlang) package
// versions registered under EcosystemHex.
//
// Hex enforces SemVer 2.0 strictly — the same semantics as Cargo (crates.io).
// This function strips any leading "v" prefix that canonical() may have added
// upstream, then delegates to the shared SemVer-2 base (cargoVersionInRangeV).
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
func hexVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// Hex registry versions never carry a "v" prefix.  Strip it in case the
	// upstream pipeline ran canonical() (which adds "v") before calling here.
	return cargoVersionInRangeV(strings.TrimPrefix(version, "v"), r)
}

// init registers the Hex ecosystem comparator into the shared registry.
// Hex uses SemVer 2.0 identical to Cargo, so hexVersionInRangeV is a thin
// wrapper — no bespoke parsing is required.
func init() {
	RegisterComparator(EcosystemHex, hexVersionInRangeV)
}
