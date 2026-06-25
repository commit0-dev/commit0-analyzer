package advisory

import (
	"strings"

	"golang.org/x/mod/semver"
)

// cargoVersionInRangeV is the tri-state comparator for crates.io (Cargo) versions.
//
// Cargo uses canonical SemVer 2.0.0 without the "v" prefix required by
// golang.org/x/mod/semver.  This function normalises both the query version and
// every range bound before comparison, and rejects any string that carries a
// leading "v" as malformed input (Cargo versions never do).
//
// Returns:
//   - VersionAffected      — version falls within the range.
//   - VersionNotAffected   — version is provably outside the range.
//   - VersionUndecidable   — the query version or a range bound cannot be parsed
//     as valid SemVer; callers MUST treat this as "possibly affected" and set
//     incomplete=true.  A parse error is NEVER silently treated as NotAffected.
//
// Range semantics:
//   - Introduced is an inclusive lower bound; empty means "since the beginning".
//   - Fixed is an exclusive upper bound; empty means "no fix yet" (open upper end).
//   - LastAffected is an inclusive upper bound; at most one of Fixed/LastAffected
//     is set per range (same semantics as the OSV schema).
func cargoVersionInRangeV(version string, r VersionRange) VersionVerdict {
	// Validate and normalise the query version.
	qv, ok := parseCargoVersion(version)
	if !ok {
		return VersionUndecidable
	}

	// Lower bound: Introduced is inclusive.
	if r.Introduced != "" {
		iv := cargoCanonical(r.Introduced)
		if !semver.IsValid(iv) {
			return VersionUndecidable
		}
		if semver.Compare(qv, iv) < 0 {
			return VersionNotAffected // version < introduced
		}
	}

	// Upper bound: Fixed is exclusive, LastAffected is inclusive.
	if r.Fixed != "" {
		fv := cargoCanonical(r.Fixed)
		if !semver.IsValid(fv) {
			return VersionUndecidable
		}
		if semver.Compare(qv, fv) >= 0 {
			return VersionNotAffected // version >= fixed
		}
	} else if r.LastAffected != "" {
		lv := cargoCanonical(r.LastAffected)
		if !semver.IsValid(lv) {
			return VersionUndecidable
		}
		if semver.Compare(qv, lv) > 0 {
			return VersionNotAffected // version > last_affected
		}
	}

	return VersionAffected
}

// parseCargoVersion validates and normalises a bare Cargo version string (no "v"
// prefix) into the "vX.Y.Z[-pre][+build]" form required by golang.org/x/mod/semver.
//
// A Cargo version must:
//   - Not start with "v" (Go convention; Cargo never uses it).
//   - Have at least three dot-separated numeric components in the core (major.minor.patch).
//   - Pass semver.IsValid after the "v" prefix is prepended.
//
// Returns the canonical string and true on success, or ("", false) on any failure.
// Returning false always maps to VersionUndecidable — never NotAffected.
func parseCargoVersion(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	// Cargo versions must not carry a "v" prefix.
	if v[0] == 'v' || v[0] == 'V' {
		return "", false
	}
	// Validate that the core has at least three parts (major.minor.patch).
	// Strip optional pre-release and build metadata before counting dots.
	core := v
	if idx := strings.IndexByte(core, '-'); idx >= 0 {
		core = core[:idx]
	}
	if idx := strings.IndexByte(core, '+'); idx >= 0 {
		core = core[:idx]
	}
	if strings.Count(core, ".") < 2 {
		// Fewer than two dots means fewer than three parts — not valid SemVer.
		return "", false
	}
	canonical := "v" + v
	if !semver.IsValid(canonical) {
		return "", false
	}
	return canonical, true
}

// cargoCanonical normalises a crates.io range bound (no "v" prefix) to the "v"-
// prefixed form required by golang.org/x/mod/semver.  It does NOT validate the
// result; callers must check semver.IsValid on the returned string.
func cargoCanonical(v string) string {
	return "v" + v
}
