package advisory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
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
	// Trust is the source's trust tier, consulted only as a tie-break in
	// chooseRepresentative AFTER the symbol-level and range-width rules. A higher
	// value wins. The zero value ("unset") expresses no preference, preserving the
	// pre-trust representative choice (the lexicographic-ID tie-break). Trust never
	// changes WHICH advisory groups exist — only which member copy represents a
	// group — so adding a more-trusted source can never drop coverage.
	Trust int
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
		allAdvs      []Advisory
		failedNames  []string
		failedErrors []error
		staleWarns   []*StalenessWarningError
	)

	// trust maps each configured source name to its trust tier so mergeAdvisories
	// can break representative ties deterministically. Built from every configured
	// source (not only the ones that succeeded) so trust ordering is stable.
	trust := make(map[string]int, len(ms.sources))
	for _, ns := range ms.sources {
		if ns.Trust > trust[ns.Name] {
			trust[ns.Name] = ns.Trust
		}
	}

	for _, ns := range ms.sources {
		advs, err := ns.S.Query(ctx, pkg, version)
		if err != nil {
			// A StalenessWarningError is NOT a source failure: it carries usable
			// (if old) advisories. Merge them and record the warning rather than
			// dropping them — a stale snapshot must still surface its known
			// vulnerabilities (warned), never silently stop reporting them or force
			// a false incomplete. unknown ≠ safe cuts both ways: losing coverage
			// because data is old is as wrong as passing a clean on a failed query.
			var stale *StalenessWarningError
			if errors.As(err, &stale) {
				allAdvs = append(allAdvs, stale.Advisories...)
				staleWarns = append(staleWarns, stale)
				continue
			}
			failedNames = append(failedNames, ns.Name)
			failedErrors = append(failedErrors, err)
			// Do not abort: collect failures and continue querying remaining sources.
			continue
		}
		allAdvs = append(allAdvs, advs...)
	}

	merged := mergeAdvisoriesTrust(allAdvs, trust)

	// Error precedence: a real source failure (→ incomplete → exit 3) outranks a
	// staleness warning (warn-only). Either way the advisories already merged above
	// are returned, so coverage is never dropped.
	if len(failedNames) > 0 {
		return merged, &SourcesIncompleteError{
			FailedSources: failedNames,
			Errors:        failedErrors,
		}
	}
	if len(staleWarns) > 0 {
		return merged, combineStaleWarnings(staleWarns, merged)
	}
	return merged, nil
}

// combineStaleWarnings folds one or more per-source staleness warnings into a
// single *StalenessWarningError wrapping the full merged advisory set. The result
// is warn-only: callers surface Warning and keep Advisories without marking the
// scan incomplete. Output is deterministic (messages sorted) and the widest
// (largest) reported age is retained for reporting.
func combineStaleWarnings(warns []*StalenessWarningError, merged []Advisory) *StalenessWarningError {
	msgs := make([]string, 0, len(warns))
	var maxAge, threshold time.Duration
	for _, w := range warns {
		msgs = append(msgs, w.Warning)
		if w.Age > maxAge {
			maxAge = w.Age
		}
		if w.Threshold > threshold {
			threshold = w.Threshold
		}
	}
	sort.Strings(msgs)
	return &StalenessWarningError{
		Warning:    strings.Join(msgs, "; "),
		Age:        maxAge,
		Threshold:  threshold,
		Advisories: merged,
	}
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
//
// mergeAdvisories is the trust-agnostic entry point (trust unset → identical
// behavior to before trust tiers existed). MultiSource.Query uses
// mergeAdvisoriesTrust to thread source trust into the representative tie-break.
func mergeAdvisories(advs []Advisory) []Advisory {
	return mergeAdvisoriesTrust(advs, nil)
}

// mergeAdvisoriesTrust is mergeAdvisories with a source-name→trust map used as a
// representative tie-break AFTER the symbol-level and range-width rules. A nil or
// empty map reproduces the pre-trust behavior exactly.
//
// Each alias-merged group is collapsed by resolveGroup (conflict.go), which picks
// the representative and folds conflicting facts (severity/range/withdrawn) across
// every member toward the fail-safe outcome while recording provenance.
func mergeAdvisoriesTrust(advs []Advisory, trust map[string]int) []Advisory {
	if len(advs) == 0 {
		return nil
	}

	// members holds the raw advisories grouped by alias-equivalence; groupIDs
	// holds the combined identity sets used for intersection checks.
	members := make([][]Advisory, 0, len(advs))
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
			members = append(members, []Advisory{adv})
			groupIDs = append(groupIDs, ids)
		} else {
			members[matched] = append(members[matched], adv)
			// Expand the group's identity set with all new IDs from adv.
			for id := range ids {
				groupIDs[matched][id] = struct{}{}
			}
		}
	}

	// Collapse each group into a single resolved advisory.
	groups := make([]Advisory, 0, len(members))
	for _, grp := range members {
		groups = append(groups, resolveGroup(grp, trust))
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

// chooseRepresentative picks the "better" of two advisories as the merge
// representative. The preference order is:
//  1. SymbolLevel=true over false.
//  2. Among equal symbol-level: earlier (empty or smaller) Introduced in the
//     first VersionRange — an empty Introduced means "since the beginning",
//     which is the widest possible range.
//  3. Higher source trust tier (per the trust map; symbol-curated > GHSA > OSV).
//     Trust is consulted ONLY when the rules above tie, and a nil/equal trust
//     map leaves the choice to the final ID tie-break (no behavior change).
//  4. Lexicographically smaller ID as final stable tie-break.
func chooseRepresentative(a, b Advisory, trust map[string]int) (rep, other Advisory) {
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

	// Trust tie-break: prefer the advisory from the more-trusted source. Unset or
	// equal trust falls through to the deterministic ID tie-break below.
	aTrust := advisoryTrust(a, trust)
	bTrust := advisoryTrust(b, trust)
	if aTrust > bTrust {
		return a, b
	}
	if bTrust > aTrust {
		return b, a
	}

	// Final tie-break: lexicographically smaller ID wins.
	if a.ID <= b.ID {
		return a, b
	}
	return b, a
}

// advisoryTrust returns the highest trust tier among the advisory's contributing
// sources per the trust map. A nil map or unknown sources yield 0 ("unset").
func advisoryTrust(adv Advisory, trust map[string]int) int {
	best := 0
	for _, s := range adv.Sources {
		if t, ok := trust[s]; ok && t > best {
			best = t
		}
	}
	return best
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
