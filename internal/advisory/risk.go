package advisory

import (
	"fmt"
	"strings"
)

// Reachability tiers used as the second input to Score. They mirror the wire
// Confidence enum but are decoupled from it so the advisory package does not
// depend on the proto: the caller translates a finding's confidence to one of
// these strings.
const (
	// ReachabilitySymbol is a concrete call path to the vulnerable symbol.
	ReachabilitySymbol = "symbol"
	// ReachabilityPackage is a reachable package without symbol-level proof.
	ReachabilityPackage = "package"
	// ReachabilityUnknown is an undecided reachability verdict (unknown ≠ safe).
	ReachabilityUnknown = "unknown"
	// ReachabilityNotReachable is a proven NOT_REACHABLE verdict (the only tier
	// that scores 0 — it is the sole proven-safe state).
	ReachabilityNotReachable = "not_reachable"
)

// Risk-model weighting constants. They are intentionally explicit and documented
// so P8 can tune them from parity data without changing the Score signature.
//
// The model is a transparent, deterministic, pure function:
//
//	severity backbone = CVSS_base × 10 × reachability_multiplier   (0–100)
//	+ EPSS additive term (probability scaled by epssWeight)
//	→ KEV hard-boosts a reachable finding into the top band (kevFloor + headroom)
//	→ a reachability floor guarantees a reachable finding is never demoted to
//	  "ignore" even with no CVSS/EPSS/KEV data (missing enrichment ≠ safe).
const (
	// Reachability multipliers scale the CVSS-derived severity backbone.
	reachMultSymbol  = 1.0
	reachMultPackage = 0.9
	reachMultUnknown = 0.6

	// Reachability floors: a reachable finding never scores below this minimum,
	// even with no enrichment. Missing enrichment must never lower risk to "ignore".
	reachFloorSymbol  = 50.0
	reachFloorPackage = 40.0
	reachFloorUnknown = 25.0

	// epssWeight scales the EPSS probability [0,1] into at most this many points.
	epssWeight = 10.0

	// kevFloor is the minimum score for a KEV-listed reachable finding. KEV
	// (known exploited in the wild) dominates: it hard-boosts into the top band.
	kevFloor = 90.0

	// CVSS base-score proxies (0–10) used only when no scored vector is present.
	// Coarse by design — they never invent vector precision, only a severity band.
	sevProxyCritical = 9.0
	sevProxyHigh     = 7.5
	sevProxyMedium   = 5.0
	sevProxyLow      = 2.0
)

// Score fuses reachability with CVSS, KEV, and EPSS into a deterministic,
// explainable 0–100 risk score. It is a pure function: no clock, no network, no
// map iteration, fully reproducible for golden/SARIF stability.
//
// Invariants:
//   - NOT_REACHABLE → 0 (the only proven-safe state).
//   - KEV dominates: a KEV-listed reachable finding is boosted into the top band.
//   - Monotonic in each input (CVSS, reachability tier, EPSS, KEV).
//   - A reachable finding never falls below its reachability-implied floor; missing
//     enrichment never demotes it to "ignore".
func Score(adv *Advisory, reachabilityTier string) RiskScore {
	if adv == nil {
		return RiskScore{Score: 0, Tier: riskTier(0), Rationale: "no advisory"}
	}

	// A proven NOT_REACHABLE verdict is the sole safe state.
	if reachabilityTier == ReachabilityNotReachable {
		return RiskScore{
			Score:     0,
			Tier:      riskTier(0),
			Rationale: "not-reachable (no call path to vulnerable code)",
		}
	}

	mult, floor := reachParams(reachabilityTier)

	// CVSS backbone: prefer a scored vector, fall back to a coarse severity proxy.
	cvss := cvssBaseScore(adv)
	if cvss == 0 {
		cvss = severityProxyScore(adv.Severity)
	}

	var epssProb float64
	if adv.EPSS != nil {
		epssProb = adv.EPSS.Probability
	}
	kevListed := adv.KEV != nil && adv.KEV.Listed

	var score float64
	if kevListed {
		// KEV dominates: floor into the top band, with reachability scaling the
		// headroom above the floor so symbol > package > unknown ordering holds.
		score = kevFloor + (100.0-kevFloor)*mult
	} else {
		score = cvss * 10.0 * mult
	}
	score += epssProb * epssWeight

	// Reachability floor: never demote a reachable finding to "ignore".
	if score < floor {
		score = floor
	}
	score = clampScore(score)

	return RiskScore{
		Score:     score,
		Tier:      riskTier(score),
		Rationale: buildRationale(reachabilityTier, cvss, epssProb, kevListed),
	}
}

// BestCVSS returns the most authoritative CVSS metric for an advisory: the vector
// with the highest positive base score. When no metric carries a positive score
// (e.g. only an unscored v4.0 vector is present) it still surfaces the first
// vector with score 0 so the vector is never silently dropped. ok is false only
// when the advisory carries no CVSS metric at all.
func BestCVSS(adv *Advisory) (vector string, baseScore float64, ok bool) {
	if adv == nil || len(adv.CVSS) == 0 {
		return "", 0, false
	}
	best := -1.0
	bestVec := ""
	for _, m := range adv.CVSS {
		if m.BaseScore > best {
			best = m.BaseScore
			bestVec = m.Vector
		}
	}
	if best <= 0 {
		// No scored vector: surface the first vector losslessly (score stays 0).
		return adv.CVSS[0].Vector, 0, true
	}
	return bestVec, best, true
}

// cvssBaseScore returns the highest positive CVSS base score, or 0 when none.
func cvssBaseScore(adv *Advisory) float64 {
	_, score, ok := BestCVSS(adv)
	if !ok {
		return 0
	}
	return score
}

// reachParams returns the multiplier and floor for a reachability tier. An empty
// or unrecognised tier is treated as UNKNOWN (conservative: unknown ≠ safe).
func reachParams(tier string) (mult, floor float64) {
	switch tier {
	case ReachabilitySymbol:
		return reachMultSymbol, reachFloorSymbol
	case ReachabilityPackage:
		return reachMultPackage, reachFloorPackage
	default: // ReachabilityUnknown and any unrecognised value
		return reachMultUnknown, reachFloorUnknown
	}
}

// severityProxyScore maps a coarse Severity band to a representative CVSS base
// score for the backbone when no scored vector exists. SeverityUnspecified → 0.
func severityProxyScore(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return sevProxyCritical
	case SeverityHigh:
		return sevProxyHigh
	case SeverityMedium:
		return sevProxyMedium
	case SeverityLow:
		return sevProxyLow
	default:
		return 0
	}
}

// riskTier maps a 0–100 score to a human-readable band.
func riskTier(score float64) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// clampScore bounds a score to [0,100].
func clampScore(s float64) float64 {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

// buildRationale produces a short, deterministic human explanation of the score
// inputs (e.g. "package-reachable + KEV + CVSS 7.0 + EPSS 0.94").
func buildRationale(tier string, cvss, epss float64, kev bool) string {
	parts := []string{reachLabel(tier)}
	if kev {
		parts = append(parts, "KEV")
	}
	if cvss > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", cvss))
	}
	if epss > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", epss))
	}
	return strings.Join(parts, " + ")
}

// reachLabel returns a human label for a reachability tier.
func reachLabel(tier string) string {
	switch tier {
	case ReachabilitySymbol:
		return "symbol-reachable"
	case ReachabilityPackage:
		return "package-reachable"
	case ReachabilityNotReachable:
		return "not-reachable"
	default:
		return "reachability-unknown"
	}
}
