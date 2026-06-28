package parity

import (
	"bytes"
	"sort"
)

// DeltaKind classifies the relationship between an anst result and a comparator
// result for one vulnerability. The set is closed and ordered for deterministic
// reporting.
type DeltaKind string

const (
	// DeltaShared: both anst and the comparator reported the vulnerability and
	// anst reported it as reachable/affected (not suppressed, not unknown).
	DeltaShared DeltaKind = "shared"
	// DeltaSuppressedSound: the comparator flagged it and anst carries the same
	// advisory with a proven NOT_REACHABLE verdict — a correct reachability
	// suppression, anst's differentiator, NOT a miss.
	DeltaSuppressedSound DeltaKind = "suppressed-sound"
	// DeltaUnknownSurfaced: the comparator flagged it and anst surfaced it but
	// could not decide reachability (UNKNOWN/incomplete). Not a clean miss —
	// unknown ≠ safe means anst still reports it for the user/gate.
	DeltaUnknownSurfaced DeltaKind = "unknown-surfaced"
	// DeltaMiss: the comparator flagged it and anst has no record at all — a
	// genuine false negative.
	DeltaMiss DeltaKind = "miss"
	// DeltaAnstUnique: anst reported it and the comparator did not — broader
	// coverage or a candidate false positive; flagged for human review, never
	// auto-counted as a confirmed FP.
	DeltaAnstUnique DeltaKind = "anst-unique"
)

// Delta is one classified relationship between anst and a comparator for a
// single vulnerability on a single package.
type Delta struct {
	Kind       DeltaKind `json:"kind"`
	VulnID     string    `json:"vuln_id"`
	Package    string    `json:"package"`
	Comparator string    `json:"comparator"`
	// Reason is a short, deterministic human explanation of the classification.
	Reason string `json:"reason"`
}

// ComparisonResult is the full classified comparison of anst against one
// comparator on one corpus entry.
type ComparisonResult struct {
	Comparator      string  `json:"comparator"`
	Corpus          string  `json:"corpus"`
	AnstCount       int     `json:"anst_count"`
	ComparatorCount int     `json:"comparator_count"`
	Deltas          []Delta `json:"deltas"`
}

// Compare classifies anst's findings against one comparator's findings for a
// single corpus entry. The result is deterministic: deltas are stable-sorted by
// (kind, vuln id, package). The classification never launders a miss into a
// suppression — only a proven NOT_REACHABLE anst record yields DeltaSuppressedSound.
func Compare(corpus, comparator string, anst, other []Finding) ComparisonResult {
	res := ComparisonResult{
		Comparator:      comparator,
		Corpus:          corpus,
		AnstCount:       len(anst),
		ComparatorCount: len(other),
	}

	// Track which anst findings were matched by some comparator finding so the
	// remainder can be reported as anst-unique.
	matchedAnst := make([]bool, len(anst))

	for _, c := range other {
		kind, reason, anstIdx := classifyAgainstAnst(c, anst)
		if anstIdx >= 0 {
			matchedAnst[anstIdx] = true
		}
		res.Deltas = append(res.Deltas, Delta{
			Kind:       kind,
			VulnID:     c.VulnID,
			Package:    c.Package,
			Comparator: comparator,
			Reason:     reason,
		})
	}

	for i, a := range anst {
		if matchedAnst[i] {
			continue
		}
		res.Deltas = append(res.Deltas, Delta{
			Kind:       DeltaAnstUnique,
			VulnID:     a.VulnID,
			Package:    a.Package,
			Comparator: comparator,
			Reason:     "anst reported; " + comparator + " did not (broader coverage or candidate FP — needs review)",
		})
	}

	sortDeltas(res.Deltas)
	return res
}

// classifyAgainstAnst classifies one comparator finding against anst's full
// finding set. It returns the delta kind, a reason, and the index of the matching
// anst finding (or -1 when none matched). The order of checks encodes the
// cardinal rule: a comparator-only finding is a suppression ONLY when anst proved
// NOT_REACHABLE; an undecided anst record is "surfaced", and no anst record is a
// miss.
func classifyAgainstAnst(c Finding, anst []Finding) (DeltaKind, string, int) {
	for i, a := range anst {
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
			return DeltaSuppressedSound, "anst proved NOT_REACHABLE (sound reachability suppression)", i
		case a.Incomplete || a.Reachability == reachUnknown:
			return DeltaUnknownSurfaced, "anst surfaced as UNKNOWN/incomplete (reported, not dropped)", i
		case a.isReachable():
			return DeltaShared, "both tools flagged; anst reachable", i
		default:
			// anst carries the record but with no reachability verdict — still
			// surfaced, never silently safe.
			return DeltaUnknownSurfaced, "anst surfaced without a reachability verdict", i
		}
	}
	return DeltaMiss, "comparator flagged; anst has no record (genuine false negative)", -1
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
// soundness-critical number: comparator findings anst missed entirely.
type Summary struct {
	Shared          int `json:"shared"`
	SuppressedSound int `json:"suppressed_sound"`
	UnknownSurfaced int `json:"unknown_surfaced"`
	FalseNegatives  int `json:"false_negatives"`
	AnstUnique      int `json:"anst_unique"`
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
		case DeltaAnstUnique:
			s.AnstUnique++
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
