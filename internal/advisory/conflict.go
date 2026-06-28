package advisory

import (
	"sort"
	"strings"
	"time"
)

// Cross-source conflict resolution and provenance/freshness reporting.
//
// When the same vulnerability is reported by more than one source (alias-merged
// into a single group by merge.go), the sources can disagree on facts: severity,
// affected version ranges, fix versions, or whether the advisory was withdrawn.
// Resolution here is governed by a single rule: every conflict resolves toward
// MORE coverage and HIGHER severity (fail-safe). The losing facts are recorded in
// SourceMeta and exposed through provenance/conflict strings — never discarded.
//
// resolveGroup is the single entry point invoked by mergeAdvisoriesTrust for each
// alias-merged group. It selects the representative (the P3 symbol-level >
// range-width > trust > id rule), unions identity (aliases/sources), then folds
// the conflicting facts across every member.

// resolveGroup collapses every member of an alias-merged group into a single
// resolved Advisory. members is non-empty; trust is the optional source-trust map
// used only for representative tie-breaks.
func resolveGroup(members []Advisory, trust map[string]int) Advisory {
	// Representative selection: fold chooseRepresentative across members,
	// preserving the exact pre-conflict-resolution choice (symbol-level >
	// range-width > trust > lexicographic id).
	rep := copyAdvisory(members[0])
	for _, m := range members[1:] {
		winner, _ := chooseRepresentative(rep, m, trust)
		rep = copyAdvisory(winner)
	}

	// Union identity across ALL members so no alias/source is lost regardless of
	// which member became the representative.
	rep.Aliases = unionAliases(rep.ID, members)
	rep.Sources = unionMemberSources(members)

	// Resolve conflicting facts (fail-safe) and record provenance.
	rep.Severity = highestSeverity(members)
	rep.VersionRanges = unionVersionRanges(rep, members)
	rep.Withdrawn = resolveWithdrawn(members)
	rep.Incomplete = rep.Incomplete || anyIncomplete(members)
	rep.UndecidableRanges = rep.UndecidableRanges || anyUndecidableRanges(members)
	rep.SourceMeta = buildSourceMeta(members)

	return rep
}

// unionAliases returns the union of every member's ID and Aliases, excluding the
// representative's own ID (which is not an alias of itself). Sorted + deduped.
func unionAliases(repID string, members []Advisory) []string {
	set := make(map[string]struct{})
	for _, m := range members {
		set[m.ID] = struct{}{}
		for _, a := range m.Aliases {
			set[a] = struct{}{}
		}
	}
	delete(set, repID)
	if len(set) == 0 {
		return nil
	}
	return sortedKeys(set)
}

// unionMemberSources returns the sorted, deduplicated union of every member's
// Sources slice.
func unionMemberSources(members []Advisory) []string {
	set := make(map[string]struct{})
	for _, m := range members {
		for _, s := range m.Sources {
			set[s] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sortedKeys(set)
}

// highestSeverity returns the maximum severity across all members. A source that
// reports a higher severity always wins (fail-safe) — a disagreement never
// silently downgrades to the lower value.
func highestSeverity(members []Advisory) Severity {
	best := SeverityUnspecified
	for _, m := range members {
		if m.Severity > best {
			best = m.Severity
		}
	}
	return best
}

// unionVersionRanges returns the union of every member's affected ranges (broader
// coverage = fail-safe). The representative's ranges are kept first in their
// original order (so a single-source group is byte-identical to before conflict
// resolution existed); additional unique ranges from other members are appended
// in a deterministic sort order.
func unionVersionRanges(rep Advisory, members []Advisory) []VersionRange {
	seen := make(map[VersionRange]struct{}, len(rep.VersionRanges))
	out := make([]VersionRange, 0, len(rep.VersionRanges))
	for _, r := range rep.VersionRanges {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}

	var extra []VersionRange
	for _, m := range members {
		for _, r := range m.VersionRanges {
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			extra = append(extra, r)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return lessVersionRange(extra[i], extra[j]) })

	if len(out) == 0 && len(extra) == 0 {
		return nil
	}
	return append(out, extra...)
}

// lessVersionRange orders VersionRanges by Introduced, then Fixed, then
// LastAffected for deterministic output.
func lessVersionRange(a, b VersionRange) bool {
	if a.Introduced != b.Introduced {
		return a.Introduced < b.Introduced
	}
	if a.Fixed != b.Fixed {
		return a.Fixed < b.Fixed
	}
	return a.LastAffected < b.LastAffected
}

// lowestFixedVersion returns the earliest (lexicographically smallest non-empty)
// Fixed version across the advisory's ranges — the earliest known fix, used for
// remediation advice. Returns "" when no range carries a fix.
func lowestFixedVersion(adv Advisory) string {
	best := ""
	for _, r := range adv.VersionRanges {
		if r.Fixed == "" {
			continue
		}
		if best == "" || r.Fixed < best {
			best = r.Fixed
		}
	}
	return best
}

// resolveWithdrawn applies the unanimous-withdrawal rule: the advisory is
// withdrawn ONLY when every contributing member withdrew it. A single live
// (non-withdrawn) member keeps the advisory surfaced — a CVE retracted by one DB
// but live in another must never be silenced. When unanimous, the earliest
// withdrawal timestamp is kept (deterministic).
func resolveWithdrawn(members []Advisory) string {
	earliest := ""
	for _, m := range members {
		if m.Withdrawn == "" {
			// At least one source still considers this a real vulnerability.
			return ""
		}
		if earliest == "" || m.Withdrawn < earliest {
			earliest = m.Withdrawn
		}
	}
	return earliest
}

// anyIncomplete reports whether any member was marked Incomplete (an undecidable
// version comparison in any source makes the union undecidable — unknown ≠ safe).
func anyIncomplete(members []Advisory) bool {
	for _, m := range members {
		if m.Incomplete {
			return true
		}
	}
	return false
}

// anyUndecidableRanges reports whether any member carried undecidable ranges.
func anyUndecidableRanges(members []Advisory) bool {
	for _, m := range members {
		if m.UndecidableRanges {
			return true
		}
	}
	return false
}

// buildSourceMeta records one SourceContribution per contributing source so
// conflict and provenance reporting can describe what each source said without
// re-querying it. Pre-existing structured contributions on members (e.g. set by
// the NVD enricher) are preserved. On a per-source collision the highest severity
// wins (fail-safe) and empty fields are backfilled. The result is sorted by
// source name for deterministic output.
func buildSourceMeta(members []Advisory) []SourceContribution {
	byName := make(map[string]SourceContribution)
	add := func(c SourceContribution) {
		if c.Name == "" {
			return
		}
		prev, ok := byName[c.Name]
		if !ok {
			byName[c.Name] = c
			return
		}
		if c.Severity > prev.Severity {
			prev.Severity = c.Severity
		}
		if prev.Vector == "" {
			prev.Vector = c.Vector
		}
		if prev.FetchedAt == "" {
			prev.FetchedAt = c.FetchedAt
		}
		if prev.SnapshotAge == "" {
			prev.SnapshotAge = c.SnapshotAge
		}
		byName[c.Name] = prev
	}

	for _, m := range members {
		vector := primaryVector(m.CVSS)
		for _, src := range m.Sources {
			add(SourceContribution{
				Name:        src,
				Severity:    m.Severity,
				Vector:      vector,
				SnapshotAge: m.SnapshotAge,
			})
		}
		for _, c := range m.SourceMeta {
			add(c)
		}
	}

	if len(byName) == 0 {
		return nil
	}
	out := make([]SourceContribution, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ─── Property-string renderers (consumed by the wiring/render phase) ───────────

// severityLabel returns the canonical uppercase severity label, the inverse of
// textSeverityToSeverity. Used to render conflict/provenance strings.
func severityLabel(s Severity) string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// severityConflictString renders the per-source severity spread (e.g.
// "ghsa:HIGH,osv.dev:MEDIUM") when sources actually disagree. Returns "" when
// there are fewer than two sources or every source reported the same severity —
// there is nothing to surface in those cases.
func severityConflictString(meta []SourceContribution) string {
	if len(meta) < 2 {
		return ""
	}
	distinct := make(map[Severity]struct{})
	parts := make([]string, 0, len(meta))
	for _, c := range meta {
		distinct[c.Severity] = struct{}{}
		parts = append(parts, c.Name+":"+severityLabel(c.Severity))
	}
	if len(distinct) < 2 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// provenanceString renders a compact, deterministic per-source summary
// ("name SEVERITY vector"), sorted, for the provenance property. It is a pure
// function of meta so the output is reproducible byte-for-byte.
//
// Freshness (snapshot age) is intentionally excluded: it is wall-clock-relative
// and would make the rendered output differ between two otherwise-identical runs,
// breaking the byte-identical-SARIF invariant. Staleness is surfaced separately
// via the stale_source property, whose membership is a stable threshold decision.
func provenanceString(meta []SourceContribution) string {
	if len(meta) == 0 {
		return ""
	}
	parts := make([]string, 0, len(meta))
	for _, c := range meta {
		p := c.Name + " " + severityLabel(c.Severity)
		if c.Vector != "" {
			p += " " + c.Vector
		}
		parts = append(parts, p)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// staleSourceString renders the sorted, comma-joined stale-source list for the
// stale_source property. Returns "" when nothing is stale.
func staleSourceString(stale []string) string {
	if len(stale) == 0 {
		return ""
	}
	cp := append([]string(nil), stale...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// ProvenanceString renders the deterministic per-source provenance summary for a
// merged advisory's source metadata. It is the exported entry point used by the
// CLI wiring/render layer to surface the audit trail without recomputing it.
func ProvenanceString(meta []SourceContribution) string { return provenanceString(meta) }

// SeverityConflictString renders the per-source severity spread when sources
// actually disagree, and "" otherwise. Exported for the CLI wiring/render layer.
func SeverityConflictString(meta []SourceContribution) string {
	return severityConflictString(meta)
}

// StaleSourceString renders the sorted, comma-joined stale-source list, and ""
// when nothing is stale. Exported for the CLI wiring/render layer.
func StaleSourceString(stale []string) string { return staleSourceString(stale) }

// ─── Freshness SLA ─────────────────────────────────────────────────────────────

// FreshnessSLA defines source-freshness thresholds. A source older than Soft is
// reported stale (warn + stale_source tag). A source older than Hard marks the
// result incomplete ONLY when HardIncomplete is set — the default is warn-only so
// stale data never produces a surprise exit-3.
type FreshnessSLA struct {
	// Soft is the age past which a source is reported stale (warn-only).
	Soft time.Duration
	// Hard is the age past which a source contributes but is incomplete-eligible.
	Hard time.Duration
	// HardIncomplete enables the Hard threshold to mark the result incomplete.
	// Default false → warn-only.
	HardIncomplete bool
}

// Evaluate reports which sources are stale (older than Soft) and whether any
// source past Hard should mark the result incomplete (only when HardIncomplete).
// A source whose age cannot be determined is skipped here (its missing freshness
// is surfaced by the caller, not turned into a false staleness claim).
func (f FreshnessSLA) Evaluate(meta []SourceContribution, now time.Time) (stale []string, incomplete bool) {
	seen := make(map[string]struct{})
	for _, c := range meta {
		age, ok := sourceAge(c, now)
		if !ok {
			continue
		}
		if f.Soft > 0 && age > f.Soft {
			if _, dup := seen[c.Name]; !dup {
				seen[c.Name] = struct{}{}
				stale = append(stale, c.Name)
			}
		}
		if f.HardIncomplete && f.Hard > 0 && age > f.Hard {
			incomplete = true
		}
	}
	sort.Strings(stale)
	return stale, incomplete
}

// sourceAge returns the age of a source contribution, preferring the RFC3339
// FetchedAt timestamp (age = now - fetchedAt) and falling back to the
// human-readable SnapshotAge duration (e.g. "72h"). The bool is false when
// neither is parseable.
func sourceAge(c SourceContribution, now time.Time) (time.Duration, bool) {
	if c.FetchedAt != "" {
		if t, err := time.Parse(time.RFC3339, c.FetchedAt); err == nil {
			return now.Sub(t), true
		}
	}
	if c.SnapshotAge != "" {
		if d, err := time.ParseDuration(c.SnapshotAge); err == nil {
			return d, true
		}
	}
	return 0, false
}
