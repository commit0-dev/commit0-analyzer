// Package policy implements the policy-as-code gate for anst-analyzer.
//
// Responsibilities:
//   - Evaluate a set of findings against a user-supplied policy configuration.
//   - Determine the process exit code: 0 (pass), 1 (policy violation), 3
//     (operational error / incomplete scan — never exits 0 on partial results).
//   - Enforce the suppression invariant: only CONFIDENCE_NOT_REACHABLE findings
//     may be excluded from threshold counts; UNKNOWN findings are always counted.
//   - Handle ignore-list scoping (per advisory ID, module, or path) without
//     silently broadening scope.
//
// Policy tiers (reachable-only gate example):
//   - "reachable-only": threshold applies to SYMBOL_REACHABLE + PACKAGE_REACHABLE
//     + UNKNOWN (any finding that could be reachable); NOT_REACHABLE excluded.
//   - Custom severity thresholds: exit non-zero when HIGH+ count exceeds limit.
//
// Dep-type gating:
//   - Non-runtime dependencies (dev, test, docs, optional-extra) do NOT fail the
//     gate by default: they are not in the production execution path.
//   - The gate-on field controls the confidence floor for gating:
//       "reachable"         → gate only SYMBOL_REACHABLE + PACKAGE_REACHABLE
//       "reachable+unknown" → gate SYMBOL_REACHABLE + PACKAGE_REACHABLE + UNKNOWN (default)
//       "all"               → gate all findings regardless of confidence
//   - NOT_REACHABLE is never gate-eligible regardless of gate-on.
//
// A crashed or incomplete scan MUST exit 3, never 0.
package policy

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	"github.com/ducthinh993/anst-analyzer/pkg/contract"
)

// severityRank maps Severity enum values to comparable integers.
// Higher number = higher severity.
var severityRank = map[anstv1.Severity]int{
	anstv1.Severity_SEVERITY_UNSPECIFIED: 0,
	anstv1.Severity_SEVERITY_LOW:         1,
	anstv1.Severity_SEVERITY_MEDIUM:      2,
	anstv1.Severity_SEVERITY_HIGH:        3,
	anstv1.Severity_SEVERITY_CRITICAL:    4,
}

// parseSeverity converts a threshold string (e.g. "high") to a Severity enum.
func parseSeverity(s string) (anstv1.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return anstv1.Severity_SEVERITY_LOW, nil
	case "medium":
		return anstv1.Severity_SEVERITY_MEDIUM, nil
	case "high":
		return anstv1.Severity_SEVERITY_HIGH, nil
	case "critical":
		return anstv1.Severity_SEVERITY_CRITICAL, nil
	case "":
		return anstv1.Severity_SEVERITY_UNSPECIFIED, nil
	default:
		return anstv1.Severity_SEVERITY_UNSPECIFIED,
			fmt.Errorf("unknown severity threshold %q: must be low|medium|high|critical", s)
	}
}

// EvalFlags carries scan-level metadata that modifies gate behaviour.
type EvalFlags struct {
	// Incomplete signals that the scan did not fully complete (e.g. a plugin
	// crashed, a build target failed, or the host reported an error).
	// An incomplete scan MUST exit ExitOperationalError, never ExitPass.
	Incomplete bool
}

// GateOn constants control which confidence tiers are eligible to trigger a gate
// failure. The value is case-insensitive.
//
//   - GateOnReachable          → gate SYMBOL_REACHABLE + PACKAGE_REACHABLE only.
//     UNKNOWN is treated as warn-only. Useful for hyper-dynamic apps where static
//     analysis cannot resolve all call paths, making UNKNOWN extremely common.
//   - GateOnReachableAndUnknown → gate SYMBOL_REACHABLE + PACKAGE_REACHABLE +
//     UNKNOWN (default). "unknown ≠ safe": a runtime dep with UNKNOWN confidence
//     still gates because we cannot prove it's unreachable.
//   - GateOnAll                → gate all non-NOT_REACHABLE findings regardless of
//     confidence tier. Equivalent to the pre-dep-type behaviour.
const (
	GateOnReachable          = "reachable"
	GateOnReachableAndUnknown = "reachable+unknown"
	GateOnAll                = "all"
)

// nonRuntimeDepTypes is the set of dep_type values that do NOT fail the gate by
// default (they are not in the production execution path).
var nonRuntimeDepTypes = map[string]bool{
	"dev":            true,
	"test":           true,
	"docs":           true,
	"optional-extra": true,
}

// policyYAML is the raw YAML structure for unmarshalling.
type policyYAML struct {
	FailOn        string          `yaml:"fail-on"`
	ReachableOnly bool            `yaml:"reachable-only"`
	GateOn        string          `yaml:"gate-on"`
	Ignores       []ignoreYAML    `yaml:"ignores"`
}

// ignoreYAML is the raw YAML structure for an ignore entry.
type ignoreYAML struct {
	AdvisoryID     string `yaml:"advisory-id"`
	Module         string `yaml:"module"`
	Symbol         string `yaml:"symbol,omitempty"`
	Reason         string `yaml:"reason"`
	ExpiresAt      string `yaml:"expires-at"`
	ElevatedIgnore bool   `yaml:"elevated-ignore,omitempty"`
}

// Policy holds the parsed and validated policy configuration.
type Policy struct {
	// FailOn is the minimum severity that triggers a gate failure (e.g. "high").
	FailOn string
	// ReachableOnly restricts gating to findings that are not proven safe:
	// SYMBOL_REACHABLE, PACKAGE_REACHABLE, and UNKNOWN. Only NOT_REACHABLE
	// is excluded. See Red Team #15c.
	ReachableOnly bool
	// GateOn sets the confidence floor for gating:
	//   "reachable"          → gate SYMBOL_REACHABLE + PACKAGE_REACHABLE only
	//   "reachable+unknown"  → gate SYMBOL_REACHABLE + PACKAGE_REACHABLE + UNKNOWN (default)
	//   "all"                → gate all non-NOT_REACHABLE findings
	// Empty string defaults to GateOnReachableAndUnknown (sound default).
	// NOT_REACHABLE is never gate-eligible regardless of this setting.
	GateOn string
	// Ignores is the list of active ignore entries.
	Ignores []IgnoreEntry
}

// LoadPolicy parses and validates a policy from YAML bytes.
// Returns an error if any ignore entry has an empty reason, a wildcard, or an
// invalid expiry date.
func LoadPolicy(data []byte) (*Policy, error) {
	var raw policyYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("policy: YAML parse error: %w", err)
	}

	// Validate gate-on value if present.
	gateOn := strings.ToLower(strings.TrimSpace(raw.GateOn))
	if gateOn != "" && gateOn != GateOnReachable && gateOn != GateOnReachableAndUnknown && gateOn != GateOnAll {
		return nil, fmt.Errorf("policy: unknown gate-on value %q: must be reachable|reachable+unknown|all", raw.GateOn)
	}

	p := &Policy{
		FailOn:        raw.FailOn,
		ReachableOnly: raw.ReachableOnly,
		GateOn:        gateOn,
	}

	for i, ig := range raw.Ignores {
		entry := IgnoreEntry{
			AdvisoryID:     ig.AdvisoryID,
			Module:         ig.Module,
			Symbol:         ig.Symbol,
			Reason:         ig.Reason,
			ElevatedIgnore: ig.ElevatedIgnore,
		}
		if ig.ExpiresAt != "" {
			t, err := time.Parse("2006-01-02", ig.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("policy: ignore[%d]: invalid expires-at %q: %w", i, ig.ExpiresAt, err)
			}
			// Treat the expiry as end-of-day UTC.
			entry.ExpiresAt = t.Add(24*time.Hour - time.Second)
		}
		if err := entry.Validate(); err != nil {
			return nil, fmt.Errorf("policy: ignore[%d]: %w", i, err)
		}
		p.Ignores = append(p.Ignores, entry)
	}
	return p, nil
}

// effectiveGateOn returns the gate-on tier in effect, defaulting to
// GateOnReachableAndUnknown when GateOn is unset.
func (p *Policy) effectiveGateOn() string {
	if p.GateOn == "" {
		return GateOnReachableAndUnknown
	}
	return p.GateOn
}

// isGateEligible reports whether a finding is eligible to trigger a gate failure
// under the current policy settings.
//
// Confidence tier eligibility (applied to all ecosystems):
//   - NOT_REACHABLE → NEVER eligible (only suppressible tier).
//   - SYMBOL_REACHABLE → always eligible.
//   - PACKAGE_REACHABLE → always eligible.
//   - UNKNOWN → eligible when gate-on is "reachable+unknown" (default) or "all";
//     treated as warn-only under "reachable".
//
// Under ReachableOnly mode the gate-on logic is also applied (they compose).
// ReachableOnly without a gate-on is equivalent to gate-on=reachable+unknown.
//
// Dep-type eligibility (Python; signalled via properties["dep_type"]):
//   - runtime → eligible (in production execution path).
//   - optional-extra, dev, test, docs → NOT eligible by default (not in production).
//   - Missing dep_type is treated as runtime (conservative default).
//
// Legacy exclusion: properties["dev_only"]="true" → never eligible.
// This covers the older JS/Go wire that doesn't use dep_type.
func (p *Policy) isGateEligible(f *anstv1.Finding) bool {
	props := f.GetProperties()

	// Legacy dev-only tag (JS/Go) — always overrides.
	if props["dev_only"] == "true" {
		return false
	}

	// Dep-type exclusion: non-runtime Python deps do not gate by default.
	// properties["dep_type"] is set by the host's stampDepType pass.
	// When absent, we assume runtime (conservative: never hide a real runtime vuln).
	if dt := props["dep_type"]; dt != "" && nonRuntimeDepTypes[dt] {
		return false
	}

	// NOT_REACHABLE is the only confidence tier that may be suppressed.
	if contract.WrapFinding(f).IsSuppressible() {
		return false
	}

	// Without reachable-only and gate-on=all, all remaining findings gate.
	gateOn := p.effectiveGateOn()
	if !p.ReachableOnly && gateOn == GateOnAll {
		return true
	}

	// Apply the confidence floor.
	switch f.GetConfidence() {
	case anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
		// Always gate-eligible (provably reachable or not proven safe).
		return true
	case anstv1.Confidence_CONFIDENCE_UNKNOWN:
		// UNKNOWN gates unless gate-on="reachable" (hyper-dynamic opt-out).
		return gateOn != GateOnReachable
	default:
		// Any other confidence value: gate only when not in reachable-only /
		// reachable+unknown mode (i.e., gate-on=all or no mode restriction).
		return !p.ReachableOnly && gateOn == GateOnAll
	}
}

// isIgnored reports whether f is suppressed by an active (non-expired, matching)
// ignore entry.
func (p *Policy) isIgnored(f *anstv1.Finding) bool {
	for _, ig := range p.Ignores {
		if isActiveIgnore(ig, f) {
			return true
		}
	}
	return false
}

// meetsThreshold reports whether f's severity meets or exceeds the configured
// fail-on threshold.
func (p *Policy) meetsThreshold(f *anstv1.Finding) bool {
	threshold, err := parseSeverity(p.FailOn)
	if err != nil {
		// Unknown threshold: fail closed — treat everything as above threshold.
		return true
	}
	if threshold == anstv1.Severity_SEVERITY_UNSPECIFIED {
		// No threshold configured: nothing triggers a failure.
		return false
	}
	return severityRank[f.GetSeverity()] >= severityRank[threshold]
}

// Evaluate runs the gate against findings using default (complete scan) flags.
// Returns ExitPass, ExitGateFailure, or ExitOperationalError.
func (p *Policy) Evaluate(findings []*anstv1.Finding) int {
	return p.EvaluateWithFlags(findings, EvalFlags{})
}

// EvaluateWithFlags runs the gate with explicit scan-state flags.
// If flags.Incomplete is true, returns ExitOperationalError regardless of findings
// (fail-closed: an incomplete scan must never read as a pass).
func (p *Policy) EvaluateWithFlags(findings []*anstv1.Finding, flags EvalFlags) int {
	if flags.Incomplete {
		return ExitOperationalError
	}

	for _, f := range findings {
		if !p.isGateEligible(f) {
			continue
		}
		if p.isIgnored(f) {
			continue
		}
		if p.meetsThreshold(f) {
			return ExitGateFailure
		}
	}
	return ExitPass
}
