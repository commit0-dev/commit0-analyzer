package parity

import "fmt"

// VEX status and risk-tier constants the empirical non-negotiables assert against.
const (
	// vexStatusNotAffected is the only VEX status a proven-unreachable finding may
	// carry (justification vulnerable_code_not_in_execute_path).
	vexStatusNotAffected = "not_affected"
	// riskTierTop is the top fused-risk band (see advisory.riskTier). A KEV-listed
	// reachable finding is hard-boosted into this band.
	riskTierTop = "critical"
)

// VEXForUnreachable is the empirical non-negotiable "a known-unreachable CVE ⇒
// VEX status not_affected". It cross-checks that every COMPLETE, proven
// NOT_REACHABLE commit0-analyzer finding is recorded in the VEX document as not_affected — the
// proof that a reachability suppression flows through to the VEX output rather
// than being silently dropped. statuses maps a normalized vuln identifier to its
// VEX status (from ParseAnstVEX).
//
// Incomplete NOT_REACHABLE verdicts are skipped: they are not sound suppressions
// (commit0-analyzer maps them to under_investigation), so requiring not_affected for them
// would be wrong. When there are no complete NOT_REACHABLE findings, the result is
// an honest pass with a note — there is nothing to cross-check, and the harness
// never fabricates a suppression that did not occur.
func VEXForUnreachable(findings []Finding, statuses map[string]string) (bool, string) {
	checked := 0
	for _, f := range findings {
		if !f.isNotReachable() || f.Incomplete {
			continue
		}
		st, ok := vexStatusForFinding(f, statuses)
		if !ok {
			return false, fmt.Sprintf("%s proven NOT_REACHABLE but absent from the VEX document", f.VulnID)
		}
		if st != vexStatusNotAffected {
			return false, fmt.Sprintf("%s proven NOT_REACHABLE but VEX status = %q (want %q)", f.VulnID, st, vexStatusNotAffected)
		}
		checked++
	}
	if checked == 0 {
		return true, "no complete NOT_REACHABLE findings to cross-check against the VEX document"
	}
	return true, fmt.Sprintf("all %d complete NOT_REACHABLE finding(s) are VEX not_affected", checked)
}

// vexStatusForFinding looks up a finding's VEX status by any of its identifiers.
func vexStatusForFinding(f Finding, statuses map[string]string) (string, bool) {
	for _, id := range f.identifiers() {
		if st, ok := statuses[id]; ok {
			return st, true
		}
	}
	return "", false
}

// KEVTopTier is the empirical non-negotiable "a known-KEV dependency ⇒ KEV flag +
// top risk tier". It asserts the finding identified by id (matched against the
// primary id or any alias) carries the KEV flag and the top fused-risk band. A
// KEV dependency commit0-analyzer never found is a miss (fail), not a pass.
func KEVTopTier(findings []Finding, id string) (bool, string) {
	norm := normalizeID(id)
	for _, f := range findings {
		if !hasIdentifier(f, norm) {
			continue
		}
		if !f.KEV {
			return false, fmt.Sprintf("%s present but the KEV flag is not set", id)
		}
		if f.RiskTier != riskTierTop {
			return false, fmt.Sprintf("%s is KEV-listed but risk tier = %q (want %q)", id, f.RiskTier, riskTierTop)
		}
		return true, fmt.Sprintf("%s: KEV flag set and risk tier = %q", id, f.RiskTier)
	}
	return false, fmt.Sprintf("%s not found in commit0-analyzer findings (KEV dependency missed)", id)
}

// hasIdentifier reports whether a finding carries the given normalized identifier.
func hasIdentifier(f Finding, normID string) bool {
	for _, fid := range f.identifiers() {
		if fid == normID {
			return true
		}
	}
	return false
}
