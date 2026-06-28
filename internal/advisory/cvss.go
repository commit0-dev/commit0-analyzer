package advisory

import (
	"fmt"
	"math"
	"strings"
)

// ParseCVSS parses a CVSS v3.0, v3.1, or v4.0 vector string into a CVSSMetric.
//
// For v3.0/3.1 it validates the required base metrics and computes the exact
// base score per the official CVSS v3.x specification (§7.1), reusing the
// established weight tables. For v4.0 it validates the required base metrics and
// captures the vector losslessly, but defers the exact base-score computation:
// the v4.0 scoring algorithm is the MacroVector lookup method, which is tracked
// as a follow-up. A v4.0 metric therefore carries BaseScore=0 ("not yet
// computed"); downstream severity derivation never treats that as a downgrade.
//
// A malformed, unsupported, or incomplete vector returns an error so the caller
// treats the metric as unknown — never as a silent zero/None that could hide a
// Critical (unknown ≠ safe).
func ParseCVSS(vector string) (CVSSMetric, error) {
	v := strings.TrimSpace(vector)
	if v == "" {
		return CVSSMetric{}, fmt.Errorf("advisory: empty CVSS vector")
	}

	switch {
	case strings.HasPrefix(v, "CVSS:3.0/"):
		return parseCVSSv3(v, "3.0")
	case strings.HasPrefix(v, "CVSS:3.1/"):
		return parseCVSSv3(v, "3.1")
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return parseCVSSv4(v)
	default:
		return CVSSMetric{}, fmt.Errorf("advisory: unrecognised or unsupported CVSS vector: %q", vector)
	}
}

// parseCVSSv3 validates and scores a CVSS v3.0/3.1 vector per the official
// specification §7.1 (base-score formula) and §7.4 (Roundup). A vector missing a
// required base metric or carrying an invalid value yields an error.
//
// The weight tables (cvss3AV/AC/PR/UI/CIA) are shared with the existing OSV
// severity path. The Roundup here is the spec-exact ceiling-based function — not
// the round-half-up approximation used by the legacy parseCVSSVectorScore, which
// undershoots boundary cases such as scope-changed XSS (6.1, not 6.0).
func parseCVSSv3(vector, version string) (CVSSMetric, error) {
	metrics := cvssMetricMap(vector)

	av, avOK := cvss3AV(metrics["AV"])
	ac, acOK := cvss3AC(metrics["AC"])
	pr, prOK := cvss3PR(metrics["PR"], metrics["S"])
	ui, uiOK := cvss3UI(metrics["UI"])
	s, sOK := metrics["S"]
	c, cOK := cvss3CIA(metrics["C"])
	i, iOK := cvss3CIA(metrics["I"])
	a, aOK := cvss3CIA(metrics["A"])
	if !avOK || !acOK || !prOK || !uiOK || !sOK || !cOK || !iOK || !aOK || (s != "U" && s != "C") {
		return CVSSMetric{}, fmt.Errorf("advisory: invalid or incomplete CVSS v%s vector: %q", version, vector)
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var isc float64
	if s == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	switch {
	case isc <= 0:
		base = 0
	case s == "U":
		base = cvssRoundup(math.Min(isc+exploitability, 10))
	default:
		base = cvssRoundup(math.Min(1.08*(isc+exploitability), 10))
	}

	return CVSSMetric{
		Version:   version,
		Vector:    vector,
		BaseScore: base,
	}, nil
}

// cvssRoundup implements the CVSS v3.1 Roundup function (§7.4): round up to one
// decimal place. Using integer arithmetic at 1e5 scale avoids float artefacts.
func cvssRoundup(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10.0
}

// parseCVSSv4 validates a CVSS v4.0 vector's required base metrics and captures
// the vector losslessly. The exact v4.0 base score (MacroVector lookup method)
// is deferred, so BaseScore is left 0; the vector is preserved so a later exact
// implementation can compute the score without re-fetching.
func parseCVSSv4(vector string) (CVSSMetric, error) {
	metrics := cvssMetricMap(vector)
	if err := validateCVSSv4(metrics); err != nil {
		return CVSSMetric{}, err
	}
	return CVSSMetric{
		Version:   "4.0",
		Vector:    vector,
		BaseScore: 0, // deferred: see ParseCVSS / CVSSMetric docs
	}, nil
}

// cvssMetricMap splits a CVSS vector ("CVSS:x.y/K1:V1/K2:V2/...") into its
// metric key→value map, ignoring the leading version token.
func cvssMetricMap(vector string) map[string]string {
	out := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			continue // version token
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			continue
		}
		out[kv[0]] = kv[1]
	}
	return out
}

// cvss4BaseMetrics is the set of required CVSS v4.0 base metrics with their
// allowed values. All must be present and valid for a v4.0 base vector.
var cvss4BaseMetrics = map[string]map[string]struct{}{
	"AV": {"N": {}, "A": {}, "L": {}, "P": {}},
	"AC": {"L": {}, "H": {}},
	"AT": {"N": {}, "P": {}},
	"PR": {"N": {}, "L": {}, "H": {}},
	"UI": {"N": {}, "P": {}, "A": {}},
	"VC": {"H": {}, "L": {}, "N": {}},
	"VI": {"H": {}, "L": {}, "N": {}},
	"VA": {"H": {}, "L": {}, "N": {}},
	"SC": {"H": {}, "L": {}, "N": {}},
	"SI": {"H": {}, "L": {}, "N": {}},
	"SA": {"H": {}, "L": {}, "N": {}},
}

// validateCVSSv4 verifies that every required v4.0 base metric is present with an
// allowed value.
func validateCVSSv4(metrics map[string]string) error {
	for key, allowed := range cvss4BaseMetrics {
		val, ok := metrics[key]
		if !ok {
			return fmt.Errorf("advisory: CVSS v4.0 vector missing required metric %q", key)
		}
		if _, valid := allowed[val]; !valid {
			return fmt.Errorf("advisory: CVSS v4.0 metric %q has invalid value %q", key, val)
		}
	}
	return nil
}

// severityFromMetrics derives a Severity from a set of parsed CVSS metrics, with
// deterministic precedence and sound fallbacks.
//
// Precedence (highest first): a scored v4.0 vector, then v3.1, then v3.0. Only a
// metric with a usable (>0) base score participates — so a v4.0 metric whose
// score is deferred (BaseScore=0) is skipped and never downgrades the result.
// When no scored vector is present, it falls back to the bare numeric score,
// then to the textual severity string, matching the pre-existing OSV path.
//
// Returns SeverityUnspecified only when there is genuinely no signal; it never
// fabricates a band, and it never silently lowers a present signal to "safe".
func severityFromMetrics(metrics []CVSSMetric, bareScore float64, textual string) Severity {
	for _, version := range []string{"4.0", "3.1", "3.0"} {
		for _, m := range metrics {
			if m.Version == version && m.BaseScore > 0 {
				return cvssScoreToSeverity(m.BaseScore)
			}
		}
	}
	if bareScore > 0 {
		return cvssScoreToSeverity(bareScore)
	}
	return textSeverityToSeverity(textual)
}
