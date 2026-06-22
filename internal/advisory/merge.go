package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ─── SourcesIncompleteError ───────────────────────────────────────────────────

// SourcesIncompleteError is returned by MultiSource.Query when one or more
// sources fail. It is NOT a fatal error: the caller (CLI scan loop) should:
//  1. Print a warning for each failed source to stderr.
//  2. Mark the scan incomplete (drives exit 3 via policy.EvalFlags.Incomplete).
//  3. Continue gating on whatever advisories the succeeding sources returned.
//
// "unknown ≠ safe": a partial result is never silently treated as a clean pass.
type SourcesIncompleteError struct {
	// FailedSources lists the name of every source that returned a non-nil error.
	FailedSources []string
	// Errors holds the per-source errors in the same order as FailedSources.
	Errors []error
}

func (e *SourcesIncompleteError) Error() string {
	var parts []string
	for i, name := range e.FailedSources {
		parts = append(parts, fmt.Sprintf("%s: %v", name, e.Errors[i]))
	}
	return "advisory: one or more sources failed: " + strings.Join(parts, "; ")
}

// ─── NamedSource ─────────────────────────────────────────────────────────────

// NamedSource pairs a Source implementation with a human-readable name used in
// log/warning messages and SourcesIncompleteError.FailedSources.
type NamedSource struct {
	Name string
	S    Source
}

// ─── MultiSource ─────────────────────────────────────────────────────────────

// MultiSource composes N advisory sources behind a single Source interface.
// It fans out Query calls to each source sequentially, collects per-source
// results, and merges them by alias-equivalence.
//
// Failure semantics ("unknown ≠ safe"):
//   - A single source error does NOT abort the query. The error is recorded
//     and the other sources' results are still merged and returned.
//   - When at least one source fails, the returned error is a
//     *SourcesIncompleteError listing the failed source names. The caller must
//     use this to warn and mark the scan incomplete.
//   - If ALL sources fail, an empty slice is returned alongside the error.
//
// Concurrency: Query is safe to call from multiple goroutines; each call
// executes its fan-out sequentially within the call.
type MultiSource struct {
	sources []NamedSource
}

// NewMultiSource returns a MultiSource that queries the given named sources in
// the order they are provided.
func NewMultiSource(sources ...NamedSource) *MultiSource {
	return &MultiSource{sources: sources}
}

// Query implements Source. It fans out to each registered source, collects all
// advisories, merges by alias-equivalence, and returns a *SourcesIncompleteError
// if any source failed. Callers must check for *SourcesIncompleteError via
// errors.As and treat it as a warning (not a fatal abort).
func (ms *MultiSource) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	var (
		allAdvs       []Advisory
		failedNames   []string
		failedErrors  []error
	)

	for _, ns := range ms.sources {
		advs, err := ns.S.Query(ctx, pkg, version)
		if err != nil {
			failedNames = append(failedNames, ns.Name)
			failedErrors = append(failedErrors, err)
			// Do not abort: collect failures and continue querying remaining sources.
			continue
		}
		allAdvs = append(allAdvs, advs...)
	}

	merged := mergeAdvisories(allAdvs)

	if len(failedNames) > 0 {
		return merged, &SourcesIncompleteError{
			FailedSources: failedNames,
			Errors:        failedErrors,
		}
	}
	return merged, nil
}

// ─── Merge / dedup ────────────────────────────────────────────────────────────

// mergeAdvisories deduplicates a flat slice of advisories by alias-equivalence
// and returns a stable, deterministically-ordered result.
//
// Dedup algorithm (pairwise, sufficient for small N per package):
//  1. Build an identity set for each advisory: {ID} ∪ Aliases.
//  2. Walk advisories left-to-right; for each one, find the first existing group
//     whose identity set intersects with the current advisory's identity set.
//  3. If a match is found, merge the current advisory into that group.
//  4. Otherwise, start a new group.
//
// Within a group, the representative is chosen by:
//   - SymbolLevel=true > SymbolLevel=false (symbol-level preferred).
//   - Tie-break: wider version-range (lower Introduced); empty Introduced wins.
//   - Final tie-break: lexicographically smaller ID (stable, deterministic).
//
// After grouping, union Sources and Aliases from all members of the group into
// the representative. Stable-sort the result by ID.
func mergeAdvisories(advs []Advisory) []Advisory {
	if len(advs) == 0 {
		return nil
	}

	// groups holds merged representatives; groupIDs holds the combined identity
	// sets (used for intersection checks on subsequent advisories).
	groups := make([]Advisory, 0, len(advs))
	groupIDs := make([]map[string]struct{}, 0, len(advs))

	for _, adv := range advs {
		ids := identitySet(adv)

		// Find the first existing group that shares at least one ID with adv.
		matched := -1
		for i, gids := range groupIDs {
			if setsIntersect(ids, gids) {
				matched = i
				break
			}
		}

		if matched == -1 {
			// No existing group matches — start a new one.
			cp := copyAdvisory(adv)
			groups = append(groups, cp)
			groupIDs = append(groupIDs, ids)
		} else {
			// Merge adv into the existing group.
			rep := mergeInto(groups[matched], adv)
			groups[matched] = rep
			// Expand the group's identity set with all new IDs from adv.
			for id := range ids {
				groupIDs[matched][id] = struct{}{}
			}
		}
	}

	// Stable-sort by ID for deterministic output.
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].ID < groups[j].ID
	})

	return groups
}

// identitySet returns {adv.ID} ∪ adv.Aliases as a set.
func identitySet(adv Advisory) map[string]struct{} {
	set := make(map[string]struct{}, 1+len(adv.Aliases))
	set[adv.ID] = struct{}{}
	for _, a := range adv.Aliases {
		set[a] = struct{}{}
	}
	return set
}

// setsIntersect returns true when a and b share at least one key.
func setsIntersect(a, b map[string]struct{}) bool {
	// Iterate the smaller set for efficiency.
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// mergeInto merges src into dst and returns the updated representative.
// The representative is the "better" advisory per the preference rules:
//   1. SymbolLevel=true wins over false.
//   2. Among equal symbol-level, wider version range wins (empty Introduced = widest).
//   3. Lexicographically smaller ID as final tie-break.
//
// Sources and Aliases are always unioned into the winner regardless of which is
// chosen as representative.
func mergeInto(dst, src Advisory) Advisory {
	// Determine the representative (the one whose fields we keep).
	rep, other := chooseRepresentative(dst, src)

	// Union Sources: collect unique entries from both.
	rep.Sources = unionStrings(rep.Sources, other.Sources)

	// Union Aliases: include all alias strings from both advisories, plus the
	// other advisory's own ID (since it was alias-equivalent to rep).
	aliasSet := make(map[string]struct{}, len(rep.Aliases)+len(other.Aliases)+1)
	for _, a := range rep.Aliases {
		aliasSet[a] = struct{}{}
	}
	// The other advisory's ID becomes an alias of the representative.
	aliasSet[other.ID] = struct{}{}
	for _, a := range other.Aliases {
		aliasSet[a] = struct{}{}
	}
	// Remove rep's own ID from its alias list to avoid self-reference.
	delete(aliasSet, rep.ID)

	rep.Aliases = sortedKeys(aliasSet)

	return rep
}

// chooseRepresentative picks the "better" of two advisories as the merge
// representative. The preference order is:
//  1. SymbolLevel=true over false.
//  2. Among equal symbol-level: earlier (empty or smaller) Introduced in the
//     first VersionRange — an empty Introduced means "since the beginning",
//     which is the widest possible range.
//  3. Lexicographically smaller ID as final stable tie-break.
func chooseRepresentative(a, b Advisory) (rep, other Advisory) {
	// Prefer symbol-level.
	if a.SymbolLevel && !b.SymbolLevel {
		return a, b
	}
	if b.SymbolLevel && !a.SymbolLevel {
		return b, a
	}

	// Same symbol-level tier: prefer wider version range (lower Introduced value;
	// empty string sorts before any version string, i.e. "widest").
	aIntro := firstIntroduced(a)
	bIntro := firstIntroduced(b)
	if aIntro < bIntro {
		// a has an earlier (or empty) Introduced → wider range.
		return a, b
	}
	if bIntro < aIntro {
		return b, a
	}

	// Final tie-break: lexicographically smaller ID wins.
	if a.ID <= b.ID {
		return a, b
	}
	return b, a
}

// firstIntroduced returns the Introduced field of the first VersionRange, or ""
// when there are no ranges (empty = unbounded lower = widest).
func firstIntroduced(adv Advisory) string {
	if len(adv.VersionRanges) == 0 {
		return ""
	}
	return adv.VersionRanges[0].Introduced
}

// copyAdvisory returns a shallow copy of adv with independent slice fields so
// that group mutations do not alias the original slice.
func copyAdvisory(adv Advisory) Advisory {
	cp := adv
	if adv.Aliases != nil {
		cp.Aliases = append([]string(nil), adv.Aliases...)
	}
	if adv.Sources != nil {
		cp.Sources = append([]string(nil), adv.Sources...)
	}
	if adv.VersionRanges != nil {
		cp.VersionRanges = append([]VersionRange(nil), adv.VersionRanges...)
	}
	if adv.Symbols != nil {
		cp.Symbols = append([]Symbol(nil), adv.Symbols...)
	}
	return cp
}

// unionStrings returns a sorted, deduplicated slice containing all elements
// from both a and b.
func unionStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		set[s] = struct{}{}
	}
	return sortedKeys(set)
}

// sortedKeys returns the keys of set as a sorted slice.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
