package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"

	"github.com/ducthinh993/anst-analyzer/internal/policy"
)

// ── JS Finding helpers ────────────────────────────────────────────────────────

// makeJSPackageReachable returns a PACKAGE_REACHABLE HIGH JS finding.
func makeJSPackageReachable() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id: "GHSA-h9rv-jmmf-4pgx",
		},
		Module:     "serialize-javascript",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
		},
		Language: "js",
		Pillar:   "sca",
	}
}

// makeJSNotReachable returns a NOT_REACHABLE HIGH JS finding.
func makeJSNotReachable() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id: "GHSA-lodash-not-imported",
		},
		Module:     "lodash",
		Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{"language": "js"},
		Language:   "js",
		Pillar:     "sca",
	}
}

// makeJSUnknown returns an UNKNOWN HIGH JS finding (dynamic-require path).
func makeJSUnknown() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id: "GHSA-dyn-require-001",
		},
		Module:     "some-package",
		Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{"language": "js"},
		Language:   "js",
		Pillar:     "sca",
	}
}

// makeJSPhantomReachable returns a PACKAGE_REACHABLE CRITICAL JS finding for a
// phantom (undeclared) dependency.
func makeJSPhantomReachable() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id: "GHSA-phantom-dep-001",
		},
		Module:     "hoisted-phantom",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_CRITICAL,
		Properties: map[string]string{
			"language": "js",
			"phantom":  "true",
		},
		Language: "js",
		Pillar:   "sca",
	}
}

// ── JS policy gate tests ──────────────────────────────────────────────────────

// TestPolicy_JS_PackageReachable_TripsGate verifies that a PACKAGE_REACHABLE
// HIGH JS finding triggers exit code 1 under a "high" threshold.
func TestPolicy_JS_PackageReachable_TripsGate(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: false,
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSPackageReachable()})
	assert.Equal(t, policy.ExitGateFailure, code,
		"PACKAGE_REACHABLE HIGH JS finding must trip the gate (exit 1)")
}

// TestPolicy_JS_NotReachable_ReachableOnly_DoesNotTrip verifies that a
// NOT_REACHABLE JS finding is excluded by reachable-only gating (exit 0).
func TestPolicy_JS_NotReachable_ReachableOnly_DoesNotTrip(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: true,
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSNotReachable()})
	assert.Equal(t, policy.ExitPass, code,
		"NOT_REACHABLE JS finding must pass under reachable-only gate (exit 0)")
}

// TestPolicy_JS_UNKNOWN_IsGateEligible verifies the "unknown ≠ safe" invariant
// for JS: an UNKNOWN JS finding is gate-eligible under reachable-only and trips
// exit code 1 for a HIGH finding.
func TestPolicy_JS_UNKNOWN_IsGateEligible(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: true,
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSUnknown()})
	assert.Equal(t, policy.ExitGateFailure, code,
		"UNKNOWN JS finding must be gate-eligible under reachable-only (unknown ≠ safe)")
}

// TestPolicy_JS_UNKNOWN_IsGateEligible_WithoutReachableOnly verifies that
// UNKNOWN JS findings also gate when reachable-only is false (all findings gate
// unless below threshold or ignored).
func TestPolicy_JS_UNKNOWN_IsGateEligible_WithoutReachableOnly(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: false,
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSUnknown()})
	assert.Equal(t, policy.ExitGateFailure, code,
		"UNKNOWN JS finding must gate with reachable-only=false")
}

// TestPolicy_JS_PhantomReachable_Gates verifies that a reachable phantom
// (undeclared) dependency finding gates the build (exit 1).
// The "phantom" property signals an undeclared dep; the gate must treat it
// identically to any other PACKAGE_REACHABLE finding.
func TestPolicy_JS_PhantomReachable_Gates(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "critical",
		ReachableOnly: true,
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSPhantomReachable()})
	assert.Equal(t, policy.ExitGateFailure, code,
		"reachable phantom-dep CRITICAL JS finding must gate the build (exit 1)")
}

// TestPolicy_JS_PhantomReachable_Gates_ReachableOnly verifies that a phantom
// PACKAGE_REACHABLE finding gates even with reachable-only=true (it is not
// NOT_REACHABLE — it IS reachable, just from an undeclared dep).
func TestPolicy_JS_PhantomReachable_Gates_ReachableOnly(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: true,
	}

	// Use a HIGH severity phantom to match the "high" threshold.
	phantomHigh := &anstv1.Finding{
		Advisory:   &anstv1.AdvisoryRef{Id: "GHSA-phantom-high-001"},
		Module:     "hoisted-phantom-high",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{"language": "js", "phantom": "true"},
		Language:   "js",
		Pillar:     "sca",
	}

	code := p.Evaluate([]*anstv1.Finding{phantomHigh})
	assert.Equal(t, policy.ExitGateFailure, code,
		"phantom PACKAGE_REACHABLE HIGH JS finding must gate under reachable-only (exit 1)")
}

// TestPolicy_JS_IncompleteScan_ExitsThree verifies that when JS scan is marked
// incomplete (e.g. corrupt lockfile, missing OSV npm cache), the gate must exit
// 3 (fail-closed) regardless of findings.
func TestPolicy_JS_IncompleteScan_ExitsThree(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: false,
	}

	// Even when there are zero findings, incomplete must exit 3.
	code := p.EvaluateWithFlags([]*anstv1.Finding{}, policy.EvalFlags{Incomplete: true})
	assert.Equal(t, policy.ExitOperationalError, code,
		"incomplete JS scan must exit 3 (fail-closed), never 0")
}

// TestPolicy_JS_IncompleteScan_WithFindings_ExitsThree verifies that incomplete
// overrides the gate even when there would otherwise be a gate failure (exit 1).
// Incomplete always wins (exit 3).
func TestPolicy_JS_IncompleteScan_WithFindings_ExitsThree(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "high",
		ReachableOnly: false,
	}

	// PACKAGE_REACHABLE HIGH would normally exit 1, but incomplete overrides to 3.
	code := p.EvaluateWithFlags(
		[]*anstv1.Finding{makeJSPackageReachable()},
		policy.EvalFlags{Incomplete: true},
	)
	assert.Equal(t, policy.ExitOperationalError, code,
		"incomplete JS scan with findings must exit 3, not 1")
}

// TestPolicy_JS_BoundedIgnore_SuppressesJSFinding verifies that a bounded ignore
// (advisory-id + module, non-expired) suppresses a JS finding from the gate count.
func TestPolicy_JS_BoundedIgnore_SuppressesJSFinding(t *testing.T) {
	import_time := "2099-01-01"
	p, err := policy.LoadPolicy([]byte(
		"fail-on: high\n" +
			"ignores:\n" +
			"  - advisory-id: GHSA-h9rv-jmmf-4pgx\n" +
			"    module: serialize-javascript\n" +
			"    reason: confirmed not exploitable in this deployment context\n" +
			"    expires-at: " + import_time + "\n",
	))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	code := p.Evaluate([]*anstv1.Finding{makeJSPackageReachable()})
	assert.Equal(t, policy.ExitPass, code,
		"bounded ignore matching advisory-id+module must suppress JS finding from gate")
}

// TestPolicy_JS_SeverityThreshold_BelowThreshold_Passes verifies that a JS
// finding below the configured severity threshold does not trip the gate.
func TestPolicy_JS_SeverityThreshold_BelowThreshold_Passes(t *testing.T) {
	p := &policy.Policy{
		FailOn:        "critical",
		ReachableOnly: false,
	}

	// HIGH finding below critical threshold.
	code := p.Evaluate([]*anstv1.Finding{makeJSPackageReachable()})
	assert.Equal(t, policy.ExitPass, code,
		"HIGH JS finding below critical threshold must not trip the gate")
}

// TestPolicy_JS_MixedFindings_ReachableOnlyGating verifies that in a mixed JS
// result set, only the gate-eligible tiers (PACKAGE_REACHABLE, UNKNOWN, not
// NOT_REACHABLE) cause a gate failure.
func TestPolicy_JS_MixedFindings_ReachableOnlyGating(t *testing.T) {
	// Only NOT_REACHABLE: must pass.
	t.Run("only_not_reachable_passes", func(t *testing.T) {
		p := &policy.Policy{FailOn: "high", ReachableOnly: true}
		code := p.Evaluate([]*anstv1.Finding{makeJSNotReachable()})
		assert.Equal(t, policy.ExitPass, code)
	})

	// NOT_REACHABLE + PACKAGE_REACHABLE: must gate (one eligible finding).
	t.Run("not_reachable_and_package_reachable_gates", func(t *testing.T) {
		p := &policy.Policy{FailOn: "high", ReachableOnly: true}
		code := p.Evaluate([]*anstv1.Finding{
			makeJSNotReachable(),
			makeJSPackageReachable(),
		})
		assert.Equal(t, policy.ExitGateFailure, code,
			"mixed: PACKAGE_REACHABLE must gate even when NOT_REACHABLE is also present")
	})

	// NOT_REACHABLE + UNKNOWN: must gate (UNKNOWN is gate-eligible).
	t.Run("not_reachable_and_unknown_gates", func(t *testing.T) {
		p := &policy.Policy{FailOn: "high", ReachableOnly: true}
		code := p.Evaluate([]*anstv1.Finding{
			makeJSNotReachable(),
			makeJSUnknown(),
		})
		assert.Equal(t, policy.ExitGateFailure, code,
			"mixed: UNKNOWN must gate even when NOT_REACHABLE is also present")
	})
}
