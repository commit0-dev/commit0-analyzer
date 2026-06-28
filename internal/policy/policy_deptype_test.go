package policy_test

// Tests for the confidence-tiered + dep-type gate matrix introduced for Python
// reachability value-prop reframing. Key invariants:
//
//   - runtime + SYMBOL/PACKAGE_REACHABLE → gates (exit 1) under any gate-on.
//   - dev/test/docs/optional-extra + any confidence → does NOT gate by default.
//   - runtime + NOT_REACHABLE → never gates (only suppressible tier).
//   - runtime + UNKNOWN → gates under default (reachable+unknown) gate-on.
//   - runtime + UNKNOWN → does NOT gate under --gate-on=reachable.
//   - Go/JS/Rust findings with no dep_type → treated as runtime (conservative).
//   - legacy dev_only=true → always non-gating (unchanged from prior behaviour).

import (
	"testing"

	"github.com/stretchr/testify/assert"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"

	"github.com/commit0-dev/commit0-analyzer/internal/policy"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func makePythonFinding(confidence commit0v1.Confidence, depType string) *commit0v1.Finding {
	props := map[string]string{
		"dep_type": depType,
	}
	return &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "PYPI-TEST-0001"},
		Module:     "requests",
		Confidence: confidence,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: props,
	}
}

func policyWithGateOn(gateOn string) *policy.Policy {
	return &policy.Policy{
		FailOn:        "high",
		ReachableOnly: true,
		GateOn:        gateOn,
	}
}

// ── Matrix: runtime + various confidences ────────────────────────────────────

// TestGate_Runtime_PackageReachable_Gates verifies the core invariant:
// a runtime dep with PACKAGE_REACHABLE confidence must gate under all gate-on values.
func TestGate_Runtime_PackageReachable_Gates(t *testing.T) {
	for _, gateOn := range []string{
		"",                              // default → reachable+unknown
		policy.GateOnReachableAndUnknown,
		policy.GateOnReachable,
		policy.GateOnAll,
	} {
		t.Run("gate-on="+gateOn, func(t *testing.T) {
			p := policyWithGateOn(gateOn)
			f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, "runtime")
			assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
				"runtime+PACKAGE_REACHABLE must gate under gate-on=%q", gateOn)
		})
	}
}

// TestGate_Runtime_SymbolReachable_Gates verifies SYMBOL_REACHABLE runtime gates.
func TestGate_Runtime_SymbolReachable_Gates(t *testing.T) {
	for _, gateOn := range []string{"", policy.GateOnReachableAndUnknown, policy.GateOnReachable, policy.GateOnAll} {
		t.Run("gate-on="+gateOn, func(t *testing.T) {
			p := policyWithGateOn(gateOn)
			f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE, "runtime")
			assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
				"runtime+SYMBOL_REACHABLE must gate under gate-on=%q", gateOn)
		})
	}
}

// TestGate_Runtime_NotReachable_NeverGates verifies that NOT_REACHABLE never gates.
func TestGate_Runtime_NotReachable_NeverGates(t *testing.T) {
	for _, gateOn := range []string{"", policy.GateOnReachableAndUnknown, policy.GateOnReachable, policy.GateOnAll} {
		t.Run("gate-on="+gateOn, func(t *testing.T) {
			p := policyWithGateOn(gateOn)
			f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, "runtime")
			assert.Equal(t, policy.ExitPass, p.Evaluate([]*commit0v1.Finding{f}),
				"runtime+NOT_REACHABLE must never gate (gate-on=%q)", gateOn)
		})
	}
}

// TestGate_Runtime_Unknown_DefaultGates verifies the default sound behaviour:
// UNKNOWN on a runtime dep gates under the default gate-on (reachable+unknown).
func TestGate_Runtime_Unknown_DefaultGates(t *testing.T) {
	// Default gate-on (empty string → reachable+unknown).
	p := &policy.Policy{FailOn: "high", ReachableOnly: true}
	f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_UNKNOWN, "runtime")
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
		"runtime+UNKNOWN must gate under default gate-on (reachable+unknown)")
}

// TestGate_Runtime_Unknown_GateOnReachableAndUnknown_Gates verifies explicit
// reachable+unknown gate-on still gates UNKNOWN runtime findings.
func TestGate_Runtime_Unknown_GateOnReachableAndUnknown_Gates(t *testing.T) {
	p := policyWithGateOn(policy.GateOnReachableAndUnknown)
	f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_UNKNOWN, "runtime")
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
		"runtime+UNKNOWN must gate under gate-on=reachable+unknown")
}

// TestGate_Runtime_Unknown_GateOnReachable_NoGate verifies the hyper-dynamic
// opt-out: under --gate-on=reachable, runtime+UNKNOWN is warn-only, not gating.
func TestGate_Runtime_Unknown_GateOnReachable_NoGate(t *testing.T) {
	p := policyWithGateOn(policy.GateOnReachable)
	f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_UNKNOWN, "runtime")
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*commit0v1.Finding{f}),
		"runtime+UNKNOWN must NOT gate under gate-on=reachable (hyper-dynamic opt-out)")
}

// ── Matrix: non-runtime dep types ────────────────────────────────────────────

// TestGate_NonRuntime_PackageReachable_NoGate verifies that non-runtime deps
// do not trigger gate failures regardless of confidence or gate-on.
func TestGate_NonRuntime_PackageReachable_NoGate(t *testing.T) {
	nonRuntimeTypes := []string{"dev", "test", "docs", "optional-extra"}
	confidences := []commit0v1.Confidence{
		commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		commit0v1.Confidence_CONFIDENCE_UNKNOWN,
	}
	gateOns := []string{"", policy.GateOnReachableAndUnknown, policy.GateOnReachable, policy.GateOnAll}

	for _, dt := range nonRuntimeTypes {
		for _, conf := range confidences {
			for _, gateOn := range gateOns {
				dt, conf, gateOn := dt, conf, gateOn
				name := dt + "_" + conf.String() + "_gate-on=" + gateOn
				t.Run(name, func(t *testing.T) {
					p := policyWithGateOn(gateOn)
					f := makePythonFinding(conf, dt)
					assert.Equal(t, policy.ExitPass, p.Evaluate([]*commit0v1.Finding{f}),
						"non-runtime dep (%s, conf=%s) must NOT gate (gate-on=%q)", dt, conf, gateOn)
				})
			}
		}
	}
}

// TestGate_Dev_PackageReachable_NoFail verifies the primary invariant from the spec:
// dev dep + PACKAGE_REACHABLE → no gate failure (report only).
func TestGate_Dev_PackageReachable_NoFail(t *testing.T) {
	p := &policy.Policy{FailOn: "high", ReachableOnly: true}
	f := makePythonFinding(commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, "dev")
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*commit0v1.Finding{f}),
		"dev+PACKAGE_REACHABLE must NOT gate (dev dep is not in production)")
}

// ── No dep_type (other ecosystems) ───────────────────────────────────────────

// TestGate_NoDeptType_TreatedAsRuntime verifies that findings with no dep_type
// property (Go, JS, Rust) are treated conservatively as runtime and gate normally.
func TestGate_NoDeptType_TreatedAsRuntime(t *testing.T) {
	p := &policy.Policy{FailOn: "high", ReachableOnly: true}
	// No dep_type property set — simulates a Go/JS/Rust finding.
	f := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-TEST-NO-DEPTYPE"},
		Module:     "example.com/lib",
		Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		// Properties intentionally omitted (no dep_type).
	}
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
		"finding with no dep_type must gate (conservative: treat as runtime)")
}

// ── GateOn YAML round-trip ────────────────────────────────────────────────────

// TestPolicy_LoadYAML_GateOn verifies that gate-on is correctly parsed from YAML.
func TestPolicy_LoadYAML_GateOn(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
		wantGO  string
	}{
		{"reachable", "fail-on: high\ngate-on: reachable\n", false, "reachable"},
		{"reachable+unknown", "fail-on: high\ngate-on: reachable+unknown\n", false, "reachable+unknown"},
		{"all", "fail-on: high\ngate-on: all\n", false, "all"},
		{"absent", "fail-on: high\n", false, ""},                                // absent → default (empty)
		{"invalid", "fail-on: high\ngate-on: invalid\n", true, ""},              // bad value → error
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.LoadPolicy([]byte(tc.yaml))
			if tc.wantErr {
				assert.Error(t, err, "invalid gate-on must return error")
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantGO, p.GateOn)
		})
	}
}

// ── Legacy dev_only property still works ─────────────────────────────────────

// TestGate_LegacyDevOnly_NeverGates verifies that the legacy dev_only=true
// property (used by JS/Go) still suppresses findings from the gate, even with
// dep_type unset, matching the pre-dep-type behaviour exactly.
func TestGate_LegacyDevOnly_NeverGates(t *testing.T) {
	p := &policy.Policy{FailOn: "high", ReachableOnly: true}
	f := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "JS-DEV-0001"},
		Module:     "eslint",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_CRITICAL,
		Properties: map[string]string{"dev_only": "true"},
	}
	assert.Equal(t, policy.ExitPass, p.Evaluate([]*commit0v1.Finding{f}),
		"legacy dev_only=true must still suppress gating (backward compatible)")
}

// ── GateOn=all preserves old behaviour for non-Python ecosystems ─────────────

// TestGate_GateOnAll_NoDepType_UNKNOWN_Gates verifies that gate-on=all with no
// dep_type is equivalent to the pre-dep-type "all non-NOT_REACHABLE gate" behaviour.
func TestGate_GateOnAll_NoDepType_UNKNOWN_Gates(t *testing.T) {
	p := &policy.Policy{FailOn: "high", ReachableOnly: false, GateOn: policy.GateOnAll}
	f := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-ALL-0001"},
		Module:     "golang.org/x/net",
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
	}
	assert.Equal(t, policy.ExitGateFailure, p.Evaluate([]*commit0v1.Finding{f}),
		"gate-on=all must gate UNKNOWN (no dep_type) — preserves old behaviour")
}

// ── Ensure Go/JS/Rust gate exit codes are preserved ──────────────────────────

// TestGate_GoFinding_NoDeptType_PreservesExitCodes verifies that Go findings
// (no dep_type property) continue to produce the same exit codes as before this
// feature (regression guard).
func TestGate_GoFinding_NoDeptType_PreservesExitCodes(t *testing.T) {
	cases := []struct {
		name       string
		confidence commit0v1.Confidence
		wantCode   int
	}{
		{"SYMBOL_REACHABLE", commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE, policy.ExitGateFailure},
		{"PACKAGE_REACHABLE", commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, policy.ExitGateFailure},
		{"UNKNOWN", commit0v1.Confidence_CONFIDENCE_UNKNOWN, policy.ExitGateFailure},
		{"NOT_REACHABLE", commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, policy.ExitPass},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := &policy.Policy{FailOn: "high", ReachableOnly: true}
			f := &commit0v1.Finding{
				Advisory:   &commit0v1.AdvisoryRef{Id: "GO-REGRESSION-0001"},
				Module:     "golang.org/x/net",
				Confidence: tc.confidence,
				Severity:   commit0v1.Severity_SEVERITY_HIGH,
				// No Properties / dep_type not set (Go plugin).
			}
			assert.Equal(t, tc.wantCode, p.Evaluate([]*commit0v1.Finding{f}),
				"%s: Go finding (no dep_type) exit code must be unchanged", tc.name)
		})
	}
}
