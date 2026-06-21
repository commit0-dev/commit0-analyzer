package corpus_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ducthinh993/anst-analyzer/internal/corpus"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// TestMetrics_PrecisionRecall verifies precision/recall computation on a seeded
// TP/FP/FN set. The numbers are hand-verified:
//
//	TP=2  FP=1  FN=1  TN=1
//	precision = 2/(2+1) = 0.666…
//	recall    = 2/(2+1) = 0.666…
func TestMetrics_PrecisionRecall(t *testing.T) {
	m := &corpus.Metrics{}

	// TP: expected reachable, got SYMBOL_REACHABLE.
	m.Evaluate("case-tp-1", "CORPUS-CVE-001", corpus.LabelReachable, anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE)
	m.Evaluate("case-tp-2", "CORPUS-CVE-001", corpus.LabelReachable, anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE)

	// FP: expected not-reachable, got SYMBOL_REACHABLE.
	m.Evaluate("case-fp-1", "CORPUS-CVE-001", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE)

	// FN: expected reachable, got NOT_REACHABLE.
	m.Evaluate("case-fn-1", "CORPUS-CVE-001", corpus.LabelReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)

	// TN: expected not-reachable, got NOT_REACHABLE.
	m.Evaluate("case-tn-1", "CORPUS-CVE-001", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)

	assert.Equal(t, 2, m.TP, "TP count")
	assert.Equal(t, 1, m.FP, "FP count")
	assert.Equal(t, 1, m.FN, "FN count")
	assert.Equal(t, 1, m.TN, "TN count")

	assert.InDelta(t, 2.0/3.0, m.Precision(), 1e-9, "precision = TP/(TP+FP)")
	assert.InDelta(t, 2.0/3.0, m.Recall(), 1e-9, "recall = TP/(TP+FN)")
}

// TestMetrics_FPSuppressionRate verifies FP-suppression rate = TN/(TN+FP).
func TestMetrics_FPSuppressionRate(t *testing.T) {
	m := &corpus.Metrics{}

	// 3 TN, 1 FP → suppression rate = 3/4 = 0.75.
	m.Evaluate("tn-1", "ADV", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)
	m.Evaluate("tn-2", "ADV", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)
	m.Evaluate("tn-3", "ADV", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)
	m.Evaluate("fp-1", "ADV", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE)

	assert.InDelta(t, 0.75, m.FPSuppressionRate(), 1e-9, "FP suppression rate = TN/(TN+FP)")
}

// TestMetrics_VacuousPrecisionRecall verifies that zero TP+FP → precision=1.0
// and zero TP+FN → recall=1.0 (no cases = vacuously true, not divide-by-zero).
func TestMetrics_VacuousPrecisionRecall(t *testing.T) {
	m := &corpus.Metrics{}
	assert.Equal(t, 1.0, m.Precision(), "empty metrics: precision must be 1.0")
	assert.Equal(t, 1.0, m.Recall(), "empty metrics: recall must be 1.0")
	assert.Equal(t, 1.0, m.FPSuppressionRate(), "empty metrics: FP suppression must be 1.0")
}

// TestMetrics_UnknownLabel verifies the LabelUnknown path:
//   - CONFIDENCE_UNKNOWN → OutcomeUnknown (correct, not a TP/FN).
//   - CONFIDENCE_NOT_REACHABLE → OutcomeUnknownViolation (dangerous — implies safe).
//   - CONFIDENCE_SYMBOL_REACHABLE → OutcomeUnknownViolation.
func TestMetrics_UnknownLabel(t *testing.T) {
	t.Run("unknown_got_unknown", func(t *testing.T) {
		m := &corpus.Metrics{}
		r := m.Evaluate("uk-1", "ADV", corpus.LabelUnknown, anstv1.Confidence_CONFIDENCE_UNKNOWN)
		assert.Equal(t, corpus.OutcomeUnknown, r.Outcome)
		assert.Equal(t, 1, m.UnknownCorrect)
		assert.Equal(t, 0, m.UnknownViolations)
		// Unknown cases must not be counted as TP/FP/FN/TN.
		assert.Equal(t, 0, m.TP+m.FP+m.FN+m.TN)
	})

	t.Run("unknown_got_not_reachable_is_violation", func(t *testing.T) {
		m := &corpus.Metrics{}
		r := m.Evaluate("uk-2", "ADV", corpus.LabelUnknown, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)
		assert.Equal(t, corpus.OutcomeUnknownViolation, r.Outcome,
			"NOT_REACHABLE on a LabelUnknown case is a violation (implies safe when we can't confirm)")
		assert.Equal(t, 1, m.UnknownViolations)
	})

	t.Run("unknown_got_reachable_is_violation", func(t *testing.T) {
		m := &corpus.Metrics{}
		r := m.Evaluate("uk-3", "ADV", corpus.LabelUnknown, anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE)
		assert.Equal(t, corpus.OutcomeUnknownViolation, r.Outcome,
			"definitive SYMBOL_REACHABLE on a LabelUnknown case is a violation")
		assert.Equal(t, 1, m.UnknownViolations)
	})
}

// TestMetrics_UnknownOnReachableCase verifies that CONFIDENCE_UNKNOWN on a
// LabelReachable case is treated conservatively (not FN) — the engine is
// being cautious, which is correct under "unknown ≠ safe".
func TestMetrics_UnknownOnReachableCase(t *testing.T) {
	m := &corpus.Metrics{}
	r := m.Evaluate("reachable-got-unknown", "ADV", corpus.LabelReachable, anstv1.Confidence_CONFIDENCE_UNKNOWN)
	assert.Equal(t, corpus.OutcomeUnknown, r.Outcome,
		"UNKNOWN on LabelReachable is conservative, not a FN")
	assert.Equal(t, 0, m.FN, "should not count as FN — engine was cautious")
	assert.Equal(t, 1, m.UnknownCorrect)
}

// TestMetrics_Cases verifies that every Evaluate call appends to Cases.
func TestMetrics_Cases(t *testing.T) {
	m := &corpus.Metrics{}
	m.Evaluate("c1", "A1", corpus.LabelReachable, anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE)
	m.Evaluate("c2", "A2", corpus.LabelNotReachable, anstv1.Confidence_CONFIDENCE_NOT_REACHABLE)
	assert.Len(t, m.Cases, 2)
	assert.Equal(t, "c1", m.Cases[0].CaseName)
	assert.Equal(t, "c2", m.Cases[1].CaseName)
}
