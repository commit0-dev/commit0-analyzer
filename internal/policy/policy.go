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
	"strconv"
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

// Opt-in gate predicate kinds (purely additive risk-prioritization knobs). They
// extend the gate-on string with risk-signal predicates that gate eligible
// findings independently of the severity threshold. Default behaviour (no
// predicates) is unchanged: the existing confidence-tier + severity gate runs as
// before. Predicates only ADD gating — they never exclude a finding the base gate
// would already catch, preserving "unknown ≠ safe".
//
// Grammar (comma-separated tokens after the confidence tier):
//   - "kev"      → gate any finding whose advisory is KEV-listed.
//   - "epss>=X"  → gate any finding whose EPSS probability is ≥ X (0 ≤ X ≤ 1).
//   - "risk>=Y"  → gate any finding whose fused risk score is ≥ Y (0 ≤ Y ≤ 100).
const (
	gatePredicateKEV  = "kev"
	gatePredicateEPSS = "epss"
	gatePredicateRisk = "risk"
)

// gatePredicate is a single opt-in additive gate knob parsed from the gate-on
// string. Threshold is meaningful only for the epss/risk kinds.
type gatePredicate struct {
	kind      string
	threshold float64
}

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
	// GatePredicates are the opt-in, additive risk-signal knobs parsed from the
	// gate-on string (kev, epss>=X, risk>=Y). Empty by default — the gate then
	// behaves exactly as before. They never remove a finding from the base gate.
	GatePredicates []gatePredicate
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

	// Parse gate-on into its confidence tier and any opt-in additive predicates.
	gateOn, preds, gateErr := parseGateOn(raw.GateOn)
	if gateErr != nil {
		return nil, gateErr
	}

	p := &Policy{
		FailOn:         raw.FailOn,
		ReachableOnly:  raw.ReachableOnly,
		GateOn:         gateOn,
		GatePredicates: preds,
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

// parseGateOn splits a raw gate-on string into its confidence tier and any
// opt-in additive predicates. Tokens are comma-separated and case-insensitive:
//   - exactly one tier token (reachable | reachable+unknown | all); optional —
//     when absent the tier defaults to GateOnReachableAndUnknown.
//   - zero or more predicate tokens (kev, epss>=X, risk>=Y).
//
// A backward-compatible call (e.g. "reachable+unknown" or "") yields the same
// tier and no predicates, so the existing gate path and goldens are untouched.
func parseGateOn(raw string) (tier string, preds []gatePredicate, err error) {
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		switch tok {
		case GateOnReachable, GateOnReachableAndUnknown, GateOnAll:
			if tier != "" {
				return "", nil, fmt.Errorf("policy: gate-on %q sets more than one confidence tier", raw)
			}
			tier = tok
			continue
		}
		pred, perr := parseGatePredicate(tok)
		if perr != nil {
			return "", nil, fmt.Errorf("policy: gate-on token %q: %w", tok, perr)
		}
		preds = append(preds, pred)
	}
	return tier, preds, nil
}

// parseGatePredicate parses a single opt-in predicate token: "kev", "epss>=X",
// or "risk>=Y". The comparator is always ">=" (gate when the signal is at or
// above the threshold). Any other shape is an error so a typo never silently
// disables gating.
func parseGatePredicate(tok string) (gatePredicate, error) {
	if tok == gatePredicateKEV {
		return gatePredicate{kind: gatePredicateKEV}, nil
	}
	for _, kind := range []string{gatePredicateEPSS, gatePredicateRisk} {
		prefix := kind + ">="
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(tok[len(prefix):]), 64)
		if err != nil {
			return gatePredicate{}, fmt.Errorf("invalid %s threshold: %w", kind, err)
		}
		return gatePredicate{kind: kind, threshold: v}, nil
	}
	return gatePredicate{}, fmt.Errorf(
		"unknown gate-on token: must be reachable|reachable+unknown|all|kev|epss>=X|risk>=Y")
}

// matchesPredicate reports whether a finding satisfies any opt-in predicate. The
// risk signals are read from the finding's properties (stamped by the risk-fusion
// pass): properties["kev"], properties["epss"], properties["risk_score"]. A
// missing or unparseable signal simply does not match — it never excludes the
// finding from the base gate (additive only; unknown ≠ safe).
func (p *Policy) matchesPredicate(f *anstv1.Finding) bool {
	if len(p.GatePredicates) == 0 {
		return false
	}
	props := f.GetProperties()
	for _, pred := range p.GatePredicates {
		switch pred.kind {
		case gatePredicateKEV:
			if props["kev"] == "true" {
				return true
			}
		case gatePredicateEPSS:
			if v, err := strconv.ParseFloat(props["epss"], 64); err == nil && v >= pred.threshold {
				return true
			}
		case gatePredicateRisk:
			if v, err := strconv.ParseFloat(props["risk_score"], 64); err == nil && v >= pred.threshold {
				return true
			}
		}
	}
	return false
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
//
// Precedence: a confirmed gate-failing finding (gate-eligible, not ignored, and
// meeting the severity threshold) returns ExitGateFailure even when the scan is
// incomplete — a reachable gating vulnerability is the strongest, most actionable
// signal and must not be masked by incompleteness. Only when nothing fails the
// gate does flags.Incomplete take effect, returning ExitOperationalError
// (fail-closed: an incomplete scan with no gate failure must never read as a pass).
// A complete scan with no gate failure returns ExitPass.
func (p *Policy) EvaluateWithFlags(findings []*anstv1.Finding, flags EvalFlags) int {
	for _, f := range findings {
		if !p.isGateEligible(f) {
			continue
		}
		if p.isIgnored(f) {
			continue
		}
		// An eligible, non-ignored finding gates when it meets the severity
		// threshold (existing behaviour) OR matches an opt-in risk predicate
		// (kev / epss>=X / risk>=Y). Predicates only ADD gating; with none
		// configured the verdict is byte-identical to the pre-change gate.
		if p.meetsThreshold(f) || p.matchesPredicate(f) {
			return ExitGateFailure
		}
	}

	if flags.Incomplete {
		return ExitOperationalError
	}
	return ExitPass
}
