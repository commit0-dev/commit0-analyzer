package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"

	"github.com/ducthinh993/anst-analyzer/internal/policy"
)

// makeHighFinding returns a SYMBOL_REACHABLE HIGH finding for test use.
func makeHighFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-0001", Url: "https://pkg.go.dev/vuln/GO-2024-0001"},
		Module:     "golang.org/x/net",
		Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Path: &anstv1.ReachabilityPath{
			Steps: []*anstv1.CallStep{
				{Location: &anstv1.Location{File: "cmd/main.go", Line: 1, Column: 1}, Symbol: "main.main"},
			},
		},
	}
}

// makeNotReachableFinding returns the same advisory but NOT_REACHABLE.
func makeNotReachableFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-0001", Url: "https://pkg.go.dev/vuln/GO-2024-0001"},
		Module:     "golang.org/x/net",
		Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
	}
}

// makePackageReachableFinding returns a PACKAGE_REACHABLE HIGH finding.
func makePackageReachableFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-0005"},
		Module:     "github.com/example/pkg",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
	}
}

// makeUnknownFinding returns an UNKNOWN HIGH finding.
func makeUnknownFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-0006"},
		Module:     "github.com/example/reflect",
		Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
	}
}

// TestPolicy_ThresholdHigh_ReachableHighFailing verifies that a threshold of "high"
// with a SYMBOL_REACHABLE HIGH finding produces exit code 1 (gate failure).
func TestPolicy_ThresholdHigh_ReachableHighFailing(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
	}
	findings := []*anstv1.Finding{makeHighFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitGateFailure, code,
		"SYMBOL_REACHABLE HIGH above threshold must produce exit code 1")
}

// TestPolicy_ThresholdHigh_NotReachable_ReachableOnly_Pass verifies that a
// NOT_REACHABLE HIGH finding under reachable-only gating exits 0 (pass).
func TestPolicy_ThresholdHigh_NotReachable_ReachableOnly_Pass(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: true,
	}
	findings := []*anstv1.Finding{makeNotReachableFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitPass, code,
		"NOT_REACHABLE finding under reachable-only must exit 0")
}

// TestPolicy_ReachableOnly_PackageReachable_Fails validates Red Team #15c:
// PACKAGE_REACHABLE is gate-eligible under reachable-only (not proven safe).
func TestPolicy_ReachableOnly_PackageReachable_Fails(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: true,
	}
	findings := []*anstv1.Finding{makePackageReachableFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitGateFailure, code,
		"PACKAGE_REACHABLE HIGH under reachable-only must exit non-zero (Red Team #15c)")
}

// TestPolicy_ReachableOnly_Unknown_Fails validates Red Team #15c:
// UNKNOWN is gate-eligible under reachable-only (not proven safe).
func TestPolicy_ReachableOnly_Unknown_Fails(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: true,
	}
	findings := []*anstv1.Finding{makeUnknownFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitGateFailure, code,
		"UNKNOWN HIGH under reachable-only must exit non-zero (Red Team #15c): unknown ≠ safe")
}

// TestPolicy_ReachableOnly_OnlyNotReachableExcludable verifies that only
// NOT_REACHABLE is excluded from gate under reachable-only; the three other tiers
// all gate.
func TestPolicy_ReachableOnly_OnlyNotReachableExcludable(t *testing.T) {
	cases := []struct {
		name       string
		confidence anstv1.Confidence
		wantCode   int
	}{
		{"symbol_reachable", anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE, policy.ExitGateFailure},
		{"package_reachable", anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, policy.ExitGateFailure},
		{"unknown", anstv1.Confidence_CONFIDENCE_UNKNOWN, policy.ExitGateFailure},
		{"not_reachable", anstv1.Confidence_CONFIDENCE_NOT_REACHABLE, policy.ExitPass},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := &policy.Policy{
				FailOn:       "high",
				ReachableOnly: true,
			}
			f := &anstv1.Finding{
				Advisory:   &anstv1.AdvisoryRef{Id: "GO-TEST-0001"},
				Module:     "example.com/mod",
				Confidence: tc.confidence,
				Severity:   anstv1.Severity_SEVERITY_HIGH,
			}
			code := p.Evaluate([]*anstv1.Finding{f})
			assert.Equal(t, tc.wantCode, code,
				"%s: unexpected exit code", tc.name)
		})
	}
}

// TestPolicy_ThresholdCritical_HighDoesNotFail verifies that a threshold of "critical"
// does not fail on a HIGH finding.
func TestPolicy_ThresholdCritical_HighDoesNotFail(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "critical",
		ReachableOnly: false,
	}
	findings := []*anstv1.Finding{makeHighFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitPass, code,
		"HIGH finding below critical threshold must exit 0")
}

// TestPolicy_BelowThreshold_LowFindings verifies low findings do not trigger high threshold.
func TestPolicy_BelowThreshold_LowFindings(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
	}
	f := &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-TEST-0002"},
		Module:     "example.com/mod",
		Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_LOW,
	}
	code := p.Evaluate([]*anstv1.Finding{f})
	assert.Equal(t, policy.ExitPass, code,
		"LOW finding below high threshold must exit 0")
}

// TestPolicy_LoadYAML verifies that a policy can be loaded from a YAML byte slice.
func TestPolicy_LoadYAML(t *testing.T) {
	yaml := []byte(`
fail-on: high
reachable-only: true
ignores: []
`)
	p, err := policy.LoadPolicy(yaml)
	require.NoError(t, err)
	assert.Equal(t, "high", p.FailOn)
	assert.True(t, p.ReachableOnly)
}

// TestPolicy_LoadYAML_Defaults verifies that missing fields use safe defaults.
func TestPolicy_LoadYAML_Defaults(t *testing.T) {
	yaml := []byte(`fail-on: critical`)
	p, err := policy.LoadPolicy(yaml)
	require.NoError(t, err)
	assert.Equal(t, "critical", p.FailOn)
	assert.False(t, p.ReachableOnly, "reachable-only must default to false")
}

// TestPolicy_IncompleteScan_NeverExitsZero verifies that when the incomplete flag is
// set, the policy gate must exit non-zero (operational error / fail-closed).
func TestPolicy_IncompleteScan_NeverExitsZero(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
	}
	// Even with zero findings, incomplete must not exit 0.
	code := p.EvaluateWithFlags([]*anstv1.Finding{}, policy.EvalFlags{Incomplete: true})
	assert.NotEqual(t, policy.ExitPass, code,
		"incomplete scan must never exit 0 (fail closed)")
	assert.Equal(t, policy.ExitOperationalError, code,
		"incomplete scan must exit 3 (operational error)")
}

// TestPolicy_IncompleteScan_GatingFinding_ExitsGateFailure verifies the exit-code
// precedence: a confirmed gate-failing finding exits 1 even when the scan is
// incomplete — a reachable gating vulnerability is the strongest signal and must
// not be masked by incompleteness. An incomplete scan with no gate-failing finding
// still exits 3.
func TestPolicy_IncompleteScan_GatingFinding_ExitsGateFailure(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: false,
	}
	// A PACKAGE_REACHABLE HIGH finding fails the gate; incomplete must not mask it.
	code := p.EvaluateWithFlags(
		[]*anstv1.Finding{makePackageReachableFinding()},
		policy.EvalFlags{Incomplete: true},
	)
	assert.Equal(t, policy.ExitGateFailure, code,
		"a gate-failing finding must exit 1 even when the scan is incomplete")

	// With no gate-failing finding, incomplete still exits 3.
	code = p.EvaluateWithFlags(nil, policy.EvalFlags{Incomplete: true})
	assert.Equal(t, policy.ExitOperationalError, code,
		"incomplete scan with no gate-failing finding must exit 3")
}

// TestPolicy_EvaluateWithIgnores verifies that ignored findings (by exact tuple)
// are excluded from the gate count, but rendered as suppressed (not absent).
// The SARIF rendering of suppressed findings is tested in sarif_test.go.
func TestPolicy_EvaluateWithIgnores(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
		Ignores: []policy.IgnoreEntry{
			{
				AdvisoryID: "GO-2024-0001",
				Module:     "golang.org/x/net",
				Reason:     "confirmed unexploitable in this deployment",
				ExpiresAt:  time.Now().Add(24 * time.Hour), // future
			},
		},
	}
	findings := []*anstv1.Finding{makeHighFinding()}

	code := p.Evaluate(findings)
	assert.Equal(t, policy.ExitPass, code,
		"an exactly-matched, non-expired ignore must suppress the finding from gate count")
}

// makeCriticalSymbolReachableFinding returns a SYMBOL_REACHABLE CRITICAL finding
// for use in elevated-ignore gate tests.
func makeCriticalSymbolReachableFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-CRIT", Url: "https://pkg.go.dev/vuln/GO-2024-CRIT"},
		Module:     "golang.org/x/net",
		Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_CRITICAL,
		Path: &anstv1.ReachabilityPath{
			Steps: []*anstv1.CallStep{
				{Location: &anstv1.Location{File: "cmd/main.go", Line: 1, Column: 1}, Symbol: "main.main"},
			},
		},
	}
}

// TestPolicy_NonElevatedIgnore_CriticalSymbolReachable_DoesNotSuppress is the
// gate-level regression test for Red Team #15d: a plain (non-elevated) ignore
// entry MUST NOT silently suppress a SYMBOL_REACHABLE CRITICAL finding.
// Previously, ValidateAgainstFinding was defined but never called by isIgnored,
// meaning any ignore entry could suppress a proven-reachable critical vuln.
func TestPolicy_NonElevatedIgnore_CriticalSymbolReachable_DoesNotSuppress(t *testing.T) {
	nonElevatedIgnore := policy.IgnoreEntry{
		AdvisoryID:     "GO-2024-CRIT",
		Module:         "golang.org/x/net",
		Reason:         "attempt to suppress without elevated flag",
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		ElevatedIgnore: false, // deliberately not set
	}

	p := &policy.Policy{
		FailOn:        "critical",
		ReachableOnly: false,
		Ignores:       []policy.IgnoreEntry{nonElevatedIgnore},
	}

	f := makeCriticalSymbolReachableFinding()
	code := p.Evaluate([]*anstv1.Finding{f})

	// The non-elevated ignore must be refused: the finding must still gate (Red Team #15d).
	assert.Equal(t, policy.ExitGateFailure, code,
		"non-elevated ignore of SYMBOL_REACHABLE CRITICAL must NOT suppress the finding (Red Team #15d)")
}

// TestPolicy_ElevatedIgnore_CriticalSymbolReachable_Suppresses verifies that
// when ElevatedIgnore=true is explicitly set, the SYMBOL_REACHABLE CRITICAL
// finding IS suppressed and the gate passes.
func TestPolicy_ElevatedIgnore_CriticalSymbolReachable_Suppresses(t *testing.T) {
	elevatedIgnore := policy.IgnoreEntry{
		AdvisoryID:     "GO-2024-CRIT",
		Module:         "golang.org/x/net",
		Reason:         "risk accepted by security team — ticket SEC-42",
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		ElevatedIgnore: true, // correctly elevated
	}

	p := &policy.Policy{
		FailOn:        "critical",
		ReachableOnly: false,
		Ignores:       []policy.IgnoreEntry{elevatedIgnore},
	}

	f := makeCriticalSymbolReachableFinding()
	code := p.Evaluate([]*anstv1.Finding{f})

	assert.Equal(t, policy.ExitPass, code,
		"elevated ignore of SYMBOL_REACHABLE CRITICAL must suppress the finding (Red Team #15d)")
}

// TestPolicy_DevOnly_NeverGates verifies the runtime-vs-dev gate split: a finding
// tagged properties["dev_only"]="true" is reported but never triggers a gate failure,
// regardless of confidence or severity. Dev-only dependencies are not in the runtime
// execution path; they are surfaced for audit, not for CI failure.
func TestPolicy_DevOnly_NeverGates(t *testing.T) {
	makeCriticalDevOnly := func() *anstv1.Finding {
		return &anstv1.Finding{
			Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-DEV"},
			Module:     "example.com/devtool",
			Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			Severity:   anstv1.Severity_SEVERITY_CRITICAL,
			Properties: map[string]string{"dev_only": "true"},
		}
	}

	t.Run("dev_only_passes_reachable_only_false", func(t *testing.T) {
		p := &policy.Policy{FailOn: "critical", ReachableOnly: false}
		code := p.EvaluateWithFlags([]*anstv1.Finding{makeCriticalDevOnly()}, policy.EvalFlags{})
		assert.Equal(t, policy.ExitPass, code,
			"dev_only CRITICAL SYMBOL_REACHABLE must not gate (ReachableOnly=false)")
	})

	t.Run("dev_only_passes_reachable_only_true", func(t *testing.T) {
		p := &policy.Policy{FailOn: "critical", ReachableOnly: true}
		code := p.EvaluateWithFlags([]*anstv1.Finding{makeCriticalDevOnly()}, policy.EvalFlags{})
		assert.Equal(t, policy.ExitPass, code,
			"dev_only CRITICAL SYMBOL_REACHABLE must not gate (ReachableOnly=true)")
	})

	t.Run("non_dev_only_still_gates", func(t *testing.T) {
		// Prove the only difference is the dev_only property: without it, same finding gates.
		f := &anstv1.Finding{
			Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-DEV"},
			Module:     "example.com/devtool",
			Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			Severity:   anstv1.Severity_SEVERITY_CRITICAL,
			// No Properties / dev_only not set.
		}
		p := &policy.Policy{FailOn: "critical", ReachableOnly: false}
		code := p.EvaluateWithFlags([]*anstv1.Finding{f}, policy.EvalFlags{})
		assert.Equal(t, policy.ExitGateFailure, code,
			"identical finding WITHOUT dev_only must still gate (proves tag is the only differentiator)")
	})
}

// TestPolicy_NonElevatedIgnore_NonCritical_StillSuppresses is a regression test
// verifying that the elevated-ignore guard only applies to SYMBOL_REACHABLE CRITICAL
// findings. Non-critical or non-SYMBOL_REACHABLE findings must still be suppressible
// by a plain (non-elevated) ignore entry.
func TestPolicy_NonElevatedIgnore_NonCritical_StillSuppresses(t *testing.T) {
	cases := []struct {
		name       string
		confidence anstv1.Confidence
		severity   anstv1.Severity
	}{
		{
			name:       "symbol_reachable_high",
			confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			severity:   anstv1.Severity_SEVERITY_HIGH,
		},
		{
			name:       "package_reachable_critical",
			confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			severity:   anstv1.Severity_SEVERITY_CRITICAL,
		},
		{
			name:       "unknown_critical",
			confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			severity:   anstv1.Severity_SEVERITY_CRITICAL,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := &anstv1.Finding{
				Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-REG"},
				Module:     "example.com/mod",
				Confidence: tc.confidence,
				Severity:   tc.severity,
			}

			nonElevated := policy.IgnoreEntry{
				AdvisoryID:     "GO-2024-REG",
				Module:         "example.com/mod",
				Reason:         "risk accepted — non-critical or non-symbol-reachable",
				ExpiresAt:      time.Now().Add(24 * time.Hour),
				ElevatedIgnore: false,
			}

			p := &policy.Policy{
				FailOn:        "high",
				ReachableOnly: false,
				Ignores:       []policy.IgnoreEntry{nonElevated},
			}

			code := p.Evaluate([]*anstv1.Finding{f})
			assert.Equal(t, policy.ExitPass, code,
				"%s: non-elevated ignore must suppress non-(SYMBOL_REACHABLE+CRITICAL) finding", tc.name)
		})
	}
}

// makeLowFinding returns a PACKAGE_REACHABLE LOW finding with optional risk
// properties, used to exercise the opt-in additive gate predicates.
func makeLowFinding(props map[string]string) *anstv1.Finding {
	return &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GO-2024-0009"},
		Module:     "github.com/example/low",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_LOW,
		Properties: props,
	}
}

// TestPolicy_DefaultGateOn_UnchangedByPredicateSupport is the regression guard:
// the default gate-on string with no predicates must produce identical verdicts
// to the pre-change gate for every confidence tier.
func TestPolicy_DefaultGateOn_UnchangedByPredicateSupport(t *testing.T) {
	p, err := policy.LoadPolicy([]byte("fail-on: high\n"))
	require.NoError(t, err)
	require.Empty(t, p.GatePredicates, "default policy must carry no gate predicates")

	cases := []struct {
		name string
		f    *anstv1.Finding
		want int
	}{
		{"symbol_high", makeHighFinding(), policy.ExitGateFailure},
		{"package_high", makePackageReachableFinding(), policy.ExitGateFailure},
		{"unknown_high", makeUnknownFinding(), policy.ExitGateFailure},
		{"not_reachable_high", makeNotReachableFinding(), policy.ExitPass},
		{"package_low", makeLowFinding(nil), policy.ExitPass},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, p.Evaluate([]*anstv1.Finding{tc.f}), tc.name)
	}
}

// TestPolicy_GateOnKEV verifies the kev predicate gates a sub-threshold finding
// only when its advisory is KEV-listed, and never gates a NOT_REACHABLE finding.
func TestPolicy_GateOnKEV(t *testing.T) {
	p, err := policy.LoadPolicy([]byte("fail-on: high\ngate-on: reachable+unknown,kev\n"))
	require.NoError(t, err)

	// LOW finding, KEV-listed → gates via the predicate (severity alone would not).
	kevLow := makeLowFinding(map[string]string{"kev": "true"})
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*anstv1.Finding{kevLow}),
		"KEV-listed reachable finding must gate even below the severity threshold")

	// LOW finding, not KEV → predicate does not fire, severity below threshold → pass.
	plainLow := makeLowFinding(map[string]string{"kev": "false"})
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*anstv1.Finding{plainLow}),
		"non-KEV sub-threshold finding must not gate")

	// NOT_REACHABLE must never gate even when KEV-listed (eligibility preserved).
	nr := makeNotReachableFinding()
	nr.Properties = map[string]string{"kev": "true"}
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*anstv1.Finding{nr}),
		"NOT_REACHABLE must never gate, even KEV-listed")
}

// TestPolicy_GateOnEPSS verifies the epss>=X predicate gates by EPSS probability.
func TestPolicy_GateOnEPSS(t *testing.T) {
	p, err := policy.LoadPolicy([]byte("fail-on: critical\ngate-on: reachable+unknown,epss>=0.5\n"))
	require.NoError(t, err)

	high := makeLowFinding(map[string]string{"epss": "0.70"})
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*anstv1.Finding{high}),
		"EPSS 0.70 ≥ 0.5 must gate")

	low := makeLowFinding(map[string]string{"epss": "0.30"})
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*anstv1.Finding{low}),
		"EPSS 0.30 < 0.5 must not gate")

	// Missing EPSS data: predicate cannot fire; sub-critical severity → pass.
	none := makeLowFinding(nil)
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*anstv1.Finding{none}),
		"missing EPSS data must not gate via the epss predicate")
}

// TestPolicy_GateOnRisk verifies the risk>=Y predicate gates by fused risk score.
func TestPolicy_GateOnRisk(t *testing.T) {
	p, err := policy.LoadPolicy([]byte("fail-on: critical\ngate-on: reachable+unknown,risk>=70\n"))
	require.NoError(t, err)

	high := makeLowFinding(map[string]string{"risk_score": "80.0"})
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*anstv1.Finding{high}),
		"risk 80 ≥ 70 must gate")

	low := makeLowFinding(map[string]string{"risk_score": "50.0"})
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*anstv1.Finding{low}),
		"risk 50 < 70 must not gate")
}

// TestPolicy_Predicates_AddNeverRemove verifies that adding a predicate never
// removes a finding the base severity gate would already catch.
func TestPolicy_Predicates_AddNeverRemove(t *testing.T) {
	p, err := policy.LoadPolicy([]byte("fail-on: high\ngate-on: reachable+unknown,kev\n"))
	require.NoError(t, err)

	// A HIGH finding with no KEV signal must still gate via the base severity path.
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*anstv1.Finding{makeHighFinding()}),
		"base severity gate must still fire when a predicate is configured")
}

// TestPolicy_GateOn_InvalidPredicate verifies a malformed predicate is a load
// error so a typo never silently disables gating.
func TestPolicy_GateOn_InvalidPredicate(t *testing.T) {
	_, err := policy.LoadPolicy([]byte("fail-on: high\ngate-on: reachable+unknown,epss>0.5\n"))
	assert.Error(t, err, "epss>0.5 (wrong comparator) must be rejected")

	_, err = policy.LoadPolicy([]byte("fail-on: high\ngate-on: bogus\n"))
	assert.Error(t, err, "unknown gate-on token must be rejected")

	_, err = policy.LoadPolicy([]byte("fail-on: high\ngate-on: reachable,all\n"))
	assert.Error(t, err, "two confidence tiers must be rejected")
}
