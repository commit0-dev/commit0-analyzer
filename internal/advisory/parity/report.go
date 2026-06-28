package parity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Report is the full machine-readable harness output: every comparison plus the
// empirically-asserted non-negotiables. It is deterministic — comparisons are
// stable-sorted by (corpus, comparator) and every contained slice is sorted — so
// two runs on the same inputs marshal byte-identically.
type Report struct {
	// GeneratedFrom is a stable description of the corpus/commit0-analyzer version under test.
	GeneratedFrom string `json:"generated_from"`
	// SkippedComparators lists comparators absent from PATH, with the reason. The
	// harness records skips so a missing tool is never silently read as "parity".
	SkippedComparators []SkipNote `json:"skipped_comparators,omitempty"`
	// Comparisons are the per-corpus, per-comparator classified results.
	Comparisons []ComparisonResult `json:"comparisons"`
	// CoverageGains records, per corpus entry, the measured advisory-coverage
	// delta of the full source set over the 2-source baseline (Go-DB + OSV). It is
	// the empirical answer to "what does the extra source add?", never asserted.
	CoverageGains []CoverageGain `json:"coverage_gains,omitempty"`
	// Assertions records the empirical non-negotiable checks and their outcomes.
	Assertions []Assertion `json:"assertions"`
}

// CoverageGain is the measured advisory-coverage delta for one corpus entry
// between a 2-source baseline and the full source set. NewFindings is the count
// of advisories the full set surfaced that the baseline did not — the honest
// coverage-gain number. Zero is a legitimate, reportable result (e.g. when the
// extra source's offline data is already aggregated by the baseline).
type CoverageGain struct {
	Corpus          string   `json:"corpus"`
	BaselineSources string   `json:"baseline_sources"`
	FullSources     string   `json:"full_sources"`
	BaselineCount   int      `json:"baseline_count"`
	FullCount       int      `json:"full_count"`
	NewFindings     int      `json:"new_findings"`
	NewIDs          []string `json:"new_ids,omitempty"`
}

// ComputeCoverageGain measures the advisory-coverage delta of the full source
// set over the baseline for one corpus entry. A full-set finding "counts as new"
// only when no baseline finding refers to the same vulnerability on the same
// package (sameVuln). The result is deterministic: NewIDs is stable-sorted.
func ComputeCoverageGain(corpus, baselineSources, fullSources string, baseline, full []Finding) CoverageGain {
	cg := CoverageGain{
		Corpus:          corpus,
		BaselineSources: baselineSources,
		FullSources:     fullSources,
		BaselineCount:   len(baseline),
		FullCount:       len(full),
	}
	for _, f := range full {
		matched := false
		for _, b := range baseline {
			if sameVuln(f, b) {
				matched = true
				break
			}
		}
		if !matched {
			cg.NewIDs = append(cg.NewIDs, f.VulnID)
		}
	}
	sort.Strings(cg.NewIDs)
	cg.NewFindings = len(cg.NewIDs)
	return cg
}

// SkipNote records a comparator that was not run and why.
type SkipNote struct {
	Comparator string `json:"comparator"`
	Reason     string `json:"reason"`
}

// Assertion is one empirically-checked non-negotiable invariant.
type Assertion struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Sort orders the report's contents deterministically. Call it before rendering
// or marshalling so output is byte-stable across runs.
func (r *Report) Sort() {
	sort.SliceStable(r.SkippedComparators, func(i, j int) bool {
		return r.SkippedComparators[i].Comparator < r.SkippedComparators[j].Comparator
	})
	sort.SliceStable(r.Comparisons, func(i, j int) bool {
		if r.Comparisons[i].Corpus != r.Comparisons[j].Corpus {
			return r.Comparisons[i].Corpus < r.Comparisons[j].Corpus
		}
		return r.Comparisons[i].Comparator < r.Comparisons[j].Comparator
	})
	for i := range r.Comparisons {
		sortDeltas(r.Comparisons[i].Deltas)
	}
	sort.SliceStable(r.CoverageGains, func(i, j int) bool {
		return r.CoverageGains[i].Corpus < r.CoverageGains[j].Corpus
	})
	for i := range r.CoverageGains {
		sort.Strings(r.CoverageGains[i].NewIDs)
	}
	sort.SliceStable(r.Assertions, func(i, j int) bool {
		return r.Assertions[i].Name < r.Assertions[j].Name
	})
}

// ToJSON renders the report as deterministic, indented JSON.
func (r *Report) ToJSON() ([]byte, error) {
	r.Sort()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal parity report: %w", err)
	}
	return b, nil
}

// ToMarkdown renders the human-facing report deterministically. The summary
// table is the headline (FP/FN per comparator); the assertions section records
// the empirical non-negotiables; misses are listed explicitly because a false
// negative is the soundness-critical signal the harness exists to surface.
func (r *Report) ToMarkdown() string {
	r.Sort()
	var b strings.Builder
	b.WriteString("# Advisory parity report\n\n")
	if r.GeneratedFrom != "" {
		fmt.Fprintf(&b, "Generated from: %s\n\n", r.GeneratedFrom)
	}

	b.WriteString("## Coverage summary\n\n")
	b.WriteString("| Corpus | Comparator | Shared | Sound suppression | Unknown surfaced | Misses (FN) | commit0-analyzer-unique |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, c := range r.Comparisons {
		s := Summarize(c)
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %d |\n",
			c.Corpus, c.Comparator, s.Shared, s.SuppressedSound, s.UnknownSurfaced, s.FalseNegatives, s.AnstUnique)
	}
	b.WriteString("\n")

	// Misses are the soundness-critical deltas: list every one with its reason.
	b.WriteString("## False negatives (misses)\n\n")
	wroteMiss := false
	for _, c := range r.Comparisons {
		for _, d := range c.Deltas {
			if d.Kind != DeltaMiss {
				continue
			}
			fmt.Fprintf(&b, "- `%s` %s (%s found, commit0-analyzer missed): %s\n", d.VulnID, d.Package, c.Comparator, d.Reason)
			wroteMiss = true
		}
	}
	if !wroteMiss {
		b.WriteString("None — commit0-analyzer carried a record for every comparator finding.\n")
	}
	b.WriteString("\n")

	if len(r.CoverageGains) > 0 {
		b.WriteString("## Coverage gain over the 2-source baseline\n\n")
		b.WriteString("Measured advisory-coverage delta of the full source set over the Go-DB + OSV baseline.\n\n")
		b.WriteString("| Corpus | Baseline | Full | Baseline findings | Full findings | New findings |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, g := range r.CoverageGains {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d |\n",
				g.Corpus, g.BaselineSources, g.FullSources, g.BaselineCount, g.FullCount, g.NewFindings)
		}
		b.WriteString("\n")
	}

	if len(r.SkippedComparators) > 0 {
		b.WriteString("## Skipped comparators\n\n")
		for _, s := range r.SkippedComparators {
			fmt.Fprintf(&b, "- %s: %s\n", s.Comparator, s.Reason)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Empirical non-negotiables\n\n")
	for _, a := range r.Assertions {
		status := "FAIL"
		if a.Passed {
			status = "PASS"
		}
		fmt.Fprintf(&b, "- [%s] %s: %s\n", status, a.Name, a.Detail)
	}

	return b.String()
}
