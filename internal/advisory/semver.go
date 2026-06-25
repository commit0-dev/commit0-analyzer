package advisory

import "golang.org/x/mod/semver"

// versionInRange reports whether version falls within the SEMVER range r.
//
// The range is half-open: [Introduced, Fixed).
//   - An empty Introduced means "since the beginning" (treated as v0.0.0-0, the
//     lowest possible pre-release, so that v0.0.0 and any pre-release are included).
//   - An empty Fixed means "no fix released yet" (unbounded upper end).
//
// version must be a canonical "vX.Y.Z" string as returned by go list -json or
// go.sum. Non-canonical strings (missing "v" prefix, pseudo-versions that do not
// parse) cause versionInRange to return false conservatively — the caller should
// surface this as unknown confidence, not as safe.
func versionInRange(version string, r VersionRange) bool {
	if !semver.IsValid(version) {
		return false
	}

	// Check lower bound (Introduced is inclusive).
	if r.Introduced != "" {
		introduced := canonical(r.Introduced)
		if !semver.IsValid(introduced) {
			return false
		}
		if semver.Compare(version, introduced) < 0 {
			return false // version < introduced
		}
	}

	// Check upper bound: Fixed is exclusive, LastAffected is inclusive.
	if r.Fixed != "" {
		fixed := canonical(r.Fixed)
		if !semver.IsValid(fixed) {
			return false
		}
		if semver.Compare(version, fixed) >= 0 {
			return false // version >= fixed
		}
	} else if r.LastAffected != "" {
		lastAffected := canonical(r.LastAffected)
		if !semver.IsValid(lastAffected) {
			return false
		}
		if semver.Compare(version, lastAffected) > 0 {
			return false // version > last_affected
		}
	}

	return true
}

// canonical ensures a version string has the required "v" prefix that
// golang.org/x/mod/semver expects. OSV ranges often omit it.
func canonical(v string) string {
	if len(v) > 0 && v[0] != 'v' {
		return "v" + v
	}
	return v
}
