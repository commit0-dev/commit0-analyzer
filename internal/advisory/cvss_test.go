package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCVSS_V3ExactScores verifies the v3.0/3.1 base-score computation
// against official, well-known example vectors whose base scores are external
// ground truth (published by FIRST), not invented here.
func TestParseCVSS_V3ExactScores(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		vector  string
		version string
		score   float64
	}{
		{
			name:    "v3.1 network RCE 9.8",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "3.1",
			score:   9.8,
		},
		{
			name:    "v3.1 info disclosure 7.5",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			version: "3.1",
			score:   7.5,
		},
		{
			name:    "v3.1 stored XSS scope-changed 6.1",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			version: "3.1",
			score:   6.1,
		},
		{
			name:    "v3.0 network RCE 9.8 (same base formula)",
			vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "3.0",
			score:   9.8,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := ParseCVSS(tc.vector)
			require.NoError(t, err)
			assert.Equal(t, tc.version, m.Version, "version")
			assert.Equal(t, tc.vector, m.Vector, "vector must be captured losslessly")
			assert.InDelta(t, tc.score, m.BaseScore, 0.0001, "base score")
		})
	}
}

// TestParseCVSS_V4CapturesVectorDefersScore verifies that a valid CVSS v4.0
// vector is parsed and captured losslessly, with the base score deliberately
// deferred (0) — the exact v4.0 math is a documented follow-up, but the vector
// is never lost and the call does not fail.
func TestParseCVSS_V4CapturesVectorDefersScore(t *testing.T) {
	t.Parallel()

	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
	m, err := ParseCVSS(vector)
	require.NoError(t, err)
	assert.Equal(t, "4.0", m.Version)
	assert.Equal(t, vector, m.Vector, "v4.0 vector must be captured losslessly")
	assert.Equal(t, 0.0, m.BaseScore, "v4.0 base score is deferred (0 = not yet computed)")
}

// TestParseCVSS_Errors verifies that malformed and unsupported vectors return an
// error so the caller treats the metric as unknown — never as a silent zero/None
// that could hide a Critical.
func TestParseCVSS_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		vector string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"no prefix", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"unsupported version", "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{"v3.1 missing required metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"v3.1 invalid metric value", "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"v4.0 missing required metric", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H"},
		{"v4.0 invalid metric value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:Z/VI:H/VA:H/SC:H/SI:H/SA:H"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseCVSS(tc.vector)
			assert.Error(t, err, "expected error for %q", tc.vector)
		})
	}
}

// TestSeverityFromMetrics_HighestVersionPreferred verifies the deterministic
// tie-break: among scored vectors, the highest version wins (v4.0 > v3.1 > v3.0).
// Because v4.0 scoring is deferred, a v4.0 metric without a base score does not
// win and does not downgrade — the v3.1 score is used instead.
func TestSeverityFromMetrics_HighestVersionPreferred(t *testing.T) {
	t.Parallel()

	// v3.1 (9.8 Critical) and a v4.0 metric whose score is deferred (0).
	metrics := []CVSSMetric{
		{Version: "3.1", Vector: "x", BaseScore: 9.8},
		{Version: "4.0", Vector: "y", BaseScore: 0},
	}
	assert.Equal(t, SeverityCritical, severityFromMetrics(metrics, 0, ""),
		"deferred v4.0 must not downgrade the v3.1 Critical")

	// When a v4.0 score is present (future exact impl), it takes priority.
	metricsWithV4 := []CVSSMetric{
		{Version: "3.1", Vector: "x", BaseScore: 2.0}, // Low
		{Version: "4.0", Vector: "y", BaseScore: 9.5}, // Critical
	}
	assert.Equal(t, SeverityCritical, severityFromMetrics(metricsWithV4, 0, ""),
		"a scored v4.0 metric must take priority over v3.1")

	// v3.0 vs v3.1: prefer v3.1.
	metricsV3 := []CVSSMetric{
		{Version: "3.0", Vector: "x", BaseScore: 2.0}, // Low
		{Version: "3.1", Vector: "y", BaseScore: 7.5}, // High
	}
	assert.Equal(t, SeverityHigh, severityFromMetrics(metricsV3, 0, ""),
		"v3.1 must be preferred over v3.0")
}

// TestSeverityFromMetrics_Fallbacks proves old-path parity: with no usable
// vector, severity falls back to the bare score, then to textual severity,
// exactly as the pre-existing OSV path did.
func TestSeverityFromMetrics_Fallbacks(t *testing.T) {
	t.Parallel()

	// Bare-score-only record.
	assert.Equal(t, SeverityHigh, severityFromMetrics(nil, 7.5, ""),
		"bare score 7.5 → High")
	assert.Equal(t, SeverityCritical, severityFromMetrics(nil, 9.8, ""),
		"bare score 9.8 → Critical")

	// Textual-severity-only record.
	assert.Equal(t, SeverityMedium, severityFromMetrics(nil, 0, "moderate"),
		"textual moderate → Medium")
	assert.Equal(t, SeverityCritical, severityFromMetrics(nil, 0, "CRITICAL"),
		"textual CRITICAL → Critical")

	// Nothing at all → Unspecified (never an invented downgrade).
	assert.Equal(t, SeverityUnspecified, severityFromMetrics(nil, 0, ""),
		"no signal → Unspecified")

	// A deferred-only v4.0 metric (no score) with no other signal → Unspecified,
	// not a fabricated band.
	deferred := []CVSSMetric{{Version: "4.0", Vector: "y", BaseScore: 0}}
	assert.Equal(t, SeverityUnspecified, severityFromMetrics(deferred, 0, ""),
		"deferred v4.0 alone yields no severity (unknown ≠ safe, not downgraded)")
}
