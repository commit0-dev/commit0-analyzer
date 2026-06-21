// Package corpus provides the reachability corpus harness and precision/recall
// metrics for anst-analyzer. It runs the analyzer over labeled fixture modules,
// computes TP/FP/FN counts, and optionally compares against a recorded govulncheck
// baseline (never a live run — the baseline is pinned to avoid drift).
package corpus

import anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"

// Label is the expected reachability result for a corpus case.
type Label int

const (
	// LabelReachable expects CONFIDENCE_SYMBOL_REACHABLE or CONFIDENCE_PACKAGE_REACHABLE.
	LabelReachable Label = iota
	// LabelNotReachable expects CONFIDENCE_NOT_REACHABLE.
	LabelNotReachable
	// LabelUnknown expects CONFIDENCE_UNKNOWN (e.g. reflection, build-tag mismatch,
	// load failure). Never suppressed — unknown ≠ safe.
	LabelUnknown
)

// Outcome is the evaluation result of a single corpus case.
type Outcome int

const (
	// OutcomeTP is a true positive: expected reachable, got reachable.
	OutcomeTP Outcome = iota
	// OutcomeFP is a false positive: expected not-reachable, got reachable.
	OutcomeFP
	// OutcomeFN is a false negative: expected reachable, got not-reachable.
	OutcomeFN
	// OutcomeTN is a true negative: expected not-reachable, got not-reachable.
	OutcomeTN
	// OutcomeUnknown is the outcome when the expected label is LabelUnknown.
	// The engine must produce CONFIDENCE_UNKNOWN; any other result is a violation.
	OutcomeUnknown
	// OutcomeUnknownViolation means LabelUnknown was expected but the engine
	// produced a definitive result (NOT_REACHABLE is the worst case — it implies
	// safe when the engine could not actually determine reachability).
	OutcomeUnknownViolation
)

// CaseResult captures the per-case evaluation output.
type CaseResult struct {
	// CaseName is the corpus case identifier (e.g. "reachable-cve").
	CaseName string
	// AdvisoryID is the advisory evaluated.
	AdvisoryID string
	// Expected is the labeled expected outcome.
	Expected Label
	// Got is the confidence the engine produced.
	Got anstv1.Confidence
	// Outcome is the evaluation result.
	Outcome Outcome
}

// Metrics aggregates precision, recall, and FP-suppression across corpus cases.
type Metrics struct {
	// TP, FP, FN, TN are raw counts across all cases.
	TP int
	FP int
	FN int
	TN int
	// UnknownCorrect counts cases where LabelUnknown yielded CONFIDENCE_UNKNOWN (good).
	UnknownCorrect int
	// UnknownViolations counts cases where LabelUnknown did NOT yield CONFIDENCE_UNKNOWN.
	// A NOT_REACHABLE result on an expected-UNKNOWN case is the most dangerous violation.
	UnknownViolations int
	// Cases holds all per-case results.
	Cases []CaseResult
	// GovulncheckVersion is the pinned govulncheck version used for the baseline.
	// Empty when no baseline comparison was performed.
	GovulncheckVersion string
	// DBDigest is the digest of the advisory snapshot used for both the analyzer
	// and the govulncheck baseline (they must use the same data).
	DBDigest string
}

// Precision returns TP / (TP + FP). Returns 1.0 when both are zero (vacuously precise).
func (m *Metrics) Precision() float64 {
	denom := m.TP + m.FP
	if denom == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(denom)
}

// Recall returns TP / (TP + FN). Returns 1.0 when both are zero (vacuously complete).
func (m *Metrics) Recall() float64 {
	denom := m.TP + m.FN
	if denom == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(denom)
}

// FPSuppressionRate returns the fraction of NOT_REACHABLE results among all
// expected-not-reachable cases: TN / (TN + FP). Higher is better (more FPs suppressed).
func (m *Metrics) FPSuppressionRate() float64 {
	denom := m.TN + m.FP
	if denom == 0 {
		return 1.0
	}
	return float64(m.TN) / float64(denom)
}

// Evaluate computes the Outcome for a single case and updates m.
// expected is the label, got is the confidence the engine produced.
func (m *Metrics) Evaluate(caseName, advisoryID string, expected Label, got anstv1.Confidence) CaseResult {
	var outcome Outcome
	switch expected {
	case LabelReachable:
		if isReachable(got) {
			outcome = OutcomeTP
			m.TP++
		} else if got == anstv1.Confidence_CONFIDENCE_UNKNOWN {
			// UNKNOWN is conservative — not a false negative (could still be reachable).
			// We do not count it as FN; it sits outside the precision/recall pair.
			outcome = OutcomeUnknown
			m.UnknownCorrect++
		} else {
			// NOT_REACHABLE when we expected reachable → false negative.
			outcome = OutcomeFN
			m.FN++
		}
	case LabelNotReachable:
		if got == anstv1.Confidence_CONFIDENCE_NOT_REACHABLE {
			outcome = OutcomeTN
			m.TN++
		} else if isReachable(got) {
			outcome = OutcomeFP
			m.FP++
		} else {
			// UNKNOWN on a not-reachable case is conservative, not a FP.
			outcome = OutcomeUnknown
			m.UnknownCorrect++
		}
	case LabelUnknown:
		if got == anstv1.Confidence_CONFIDENCE_UNKNOWN {
			outcome = OutcomeUnknown
			m.UnknownCorrect++
		} else {
			// Any definitive result when the engine should have said UNKNOWN is a violation.
			// NOT_REACHABLE is especially dangerous (implies safe when we cannot confirm).
			outcome = OutcomeUnknownViolation
			m.UnknownViolations++
		}
	}

	r := CaseResult{
		CaseName:   caseName,
		AdvisoryID: advisoryID,
		Expected:   expected,
		Got:        got,
		Outcome:    outcome,
	}
	m.Cases = append(m.Cases, r)
	return r
}

// isReachable reports whether a confidence level indicates the symbol/package is reachable.
func isReachable(c anstv1.Confidence) bool {
	return c == anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE ||
		c == anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE
}
