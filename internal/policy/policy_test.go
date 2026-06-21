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
