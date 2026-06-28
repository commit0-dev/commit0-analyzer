package parity

import (
	"bytes"
	"sort"
)

// DeltaKind classifies the relationship between a commit0-analyzer result and a comparator
// result for one vulnerability. The set is closed and ordered for deterministic
// reporting.
type DeltaKind string

const (
	// DeltaShared: both commit0-analyzer and the comparator reported the vulnerability and
	// commit0-analyzer reported it as reachable/affected (not suppressed, not unknown).
	DeltaShared DeltaKind = "shared"
	// DeltaSuppressedSound: the comparator flagged it and commit0-analyzer carries the same
	// advisory with a proven NOT_REACHABLE verdict — a correct reachability
	// suppression, commit0-analyzer's differentiator, NOT a miss.
	DeltaSuppressedSound DeltaKind = "suppressed-sound"
	// DeltaUnknownSurfaced: the comparator flagged it and commit0-analyzer surfaced it but
	// could not decide reachability (UNKNOWN/incomplete). Not a clean miss —
	// unknown ≠ safe means commit0-analyzer still reports it for the user/gate.
	DeltaUnknownSurfaced DeltaKind = "unknown-surfaced"
	// DeltaMiss: the comparator flagged it and commit0-analyzer has no record at all — a
	// genuine false negative.
	DeltaMiss DeltaKind = "miss"
	// DeltaCommit0Unique: commit0-analyzer reported it and the comparator did not — broader
	// coverage or a candidate false positive; flagged for human review, never
	// auto-counted as a confirmed FP.
	DeltaCommit0Unique DeltaKind = "commit0-analyzer-unique"
)

// Delta is one classified relationship between commit0-analyzer and a comparator for a
// single vulnerability on a single package.
type Delta struct {
	Kind       DeltaKind `json:"kind"`
	VulnID     string    `json:"vuln_id"`
	Package    string    `json:"package"`
	Comparator string    `json:"comparator"`
	// Reason is a short, deterministic human explanation of the classification.
	Reason string `json:"reason"`
}

// ComparisonResult is the full classified comparison of commit0-analyzer against one
// comparator on one corpus entry.
type ComparisonResult struct {
	Comparator      string  `json:"comparator"`
	Corpus          string  `json:"corpus"`
	Commit0Count       int     `json:"commit0_count"`
	ComparatorCount int     `json:"comparator_count"`
	Deltas          []Delta `json:"deltas"`
}

// Compare classifies commit0-analyzer's findings against one comparator's findings for a
// single corpus entry. The result is deterministic: deltas are stable-sorted by
// (kind, vuln id, package). The classification never launders a miss into a
// suppression — only a proven NOT_REACHABLE commit0-analyzer record yields DeltaSuppressedSound.
func Compare(corpus, comparator string, commit0Analyzer, other []Finding) ComparisonResult {
	res := ComparisonResult{
		Comparator:      comparator,
		Corpus:          corpus,
		Commit0Count:       len(commit0Analyzer),
		ComparatorCount: len(other),
	}

	// Track which commit0-analyzer findings were matched by some comparator finding so the
	// remainder can be reported as commit0-analyzer-unique.
	matchedCommit0 := make([]bool, len(commit0Analyzer))

	for _, c := range other {
		kind, reason, commit0Idx := classifyAgainstCommit0(c, commit0Analyzer)
		if commit0Idx >= 0 {
			matchedCommit0[commit0Idx] = true
		}
		res.Deltas = append(res.Deltas, Delta{
			Kind:       kind,
			VulnID:     c.VulnID,
			Package:    c.Package,
			Comparator: comparator,
			Reason:     reason,
		})
	}

	for i, a := range commit0Analyzer {
		if matchedCommit0[i] {
			continue
		}
		res.Deltas = append(res.Deltas, Delta{
			Kind:       DeltaCommit0Unique,
			VulnID:     a.VulnID,
			Package:    a.Package,
			Comparator: comparator,
			Reason:     "commit0-analyzer reported; " + comparator + " did not (broader coverage or candidate FP — needs review)",
		})
	}

	sortDeltas(res.Deltas)
	return res
}

// classifyAgainstCommit0 classifies one comparator finding against commit0-analyzer's full
// finding set. It returns the delta kind, a reason, and the index of the matching
// commit0-analyzer finding (or -1 when none matched). The order of checks encodes the
// cardinal rule: a comparator-only finding is a suppression ONLY when commit0-analyzer proved
// NOT_REACHABLE; an undecided commit0-analyzer record is "surfaced", and no commit0-analyzer record is a
// miss.
func classifyAgainstCommit0(c Finding, commit0Analyzer []Finding) (DeltaKind, string, int) {
	for i, a := range commit0Analyzer {
		if !sameVuln(a, c) {
			continue
		}
		switch {
		case a.isNotReachable() && !a.Incomplete:
			// Mirrors vex.MapStatus: only a COMPLETE, proven NOT_REACHABLE verdict
			// is a sound suppression. A NOT_REACHABLE verdict from an incomplete
			// analysis cannot prove unreachability, so it is surfaced (next case),
			// never laundered into a suppression — the harness must not be less
			// conservative than the product's own VEX guard.
			return DeltaSuppressedSound, "commit0-analyzer proved NOT_REACHABLE (sound reachability suppression)", i
		case a.Incomplete || a.Reachability == reachUnknown:
			return DeltaUnknownSurfaced, "commit0-analyzer surfaced as UNKNOWN/incomplete (reported, not dropped)", i
		case a.isReachable():
			return DeltaShared, "both tools flagged; commit0-analyzer reachable", i
		default:
			// commit0-analyzer carries the record but with no reachability verdict — still
			// surfaced, never silently safe.
			return DeltaUnknownSurfaced, "commit0-analyzer surfaced without a reachability verdict", i
		}
	}
	return DeltaMiss, "comparator flagged; commit0-analyzer has no record (genuine false negative)", -1
}

// sortDeltas orders deltas deterministically by kind, then vuln id, then package.
func sortDeltas(ds []Delta) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Kind != ds[j].Kind {
			return ds[i].Kind < ds[j].Kind
		}
		if ds[i].VulnID != ds[j].VulnID {
			return ds[i].VulnID < ds[j].VulnID
		}
		return ds[i].Package < ds[j].Package
	})
}

// Summary aggregates delta counts for a comparison. FalseNegatives is the
// soundness-critical number: comparator findings commit0-analyzer missed entirely.
type Summary struct {
	Shared          int `json:"shared"`
	SuppressedSound int `json:"suppressed_sound"`
	UnknownSurfaced int `json:"unknown_surfaced"`
	FalseNegatives  int `json:"false_negatives"`
	Commit0Unique      int `json:"commit0_unique"`
}

// Summarize counts each delta kind in a comparison result.
func Summarize(res ComparisonResult) Summary {
	var s Summary
	for _, d := range res.Deltas {
		switch d.Kind {
		case DeltaShared:
			s.Shared++
		case DeltaSuppressedSound:
			s.SuppressedSound++
		case DeltaUnknownSurfaced:
			s.UnknownSurfaced++
		case DeltaMiss:
			s.FalseNegatives++
		case DeltaCommit0Unique:
			s.Commit0Unique++
		}
	}
	return s
}

// FailClosed reports whether an exit code is fail-closed for a scan that hit an
// injected source/enricher failure: such a scan must NEVER exit 0 (clean). Exit
// 3 (incomplete) or 1 (gate failure) are both acceptable fail-closed outcomes;
// exit 0 is the forbidden "silent clean" the non-negotiables prohibit.
func FailClosed(exitCode int) bool {
	return exitCode != 0
}

// Deterministic reports whether two scan outputs are byte-identical, the
// reproducibility guarantee the harness asserts on every corpus entry.
func Deterministic(run1, run2 []byte) bool {
	return bytes.Equal(run1, run2)
}
