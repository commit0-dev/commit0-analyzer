package render_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"

	"github.com/commit0-dev/commit0-analyzer/internal/render"
)

// TestJSON_StableOutput verifies that repeated calls with the same input produce
// byte-identical JSON (deterministic key order + finding sort).
func TestJSON_StableOutput(t *testing.T) {
	findings := []*commit0v1.Finding{
		symbolReachableFinding3Steps(),
		packageReachableFinding(),
		unknownFinding(),
		notReachableFinding(),
	}

	out1, err := render.ToJSON(findings)
	require.NoError(t, err)
	out2, err := render.ToJSON(findings)
	require.NoError(t, err)

	assert.Equal(t, string(out1), string(out2), "ToJSON must be deterministic across calls")
}

// TestJSON_GoldenFile verifies that the JSON output matches the golden file and
// contains required fields: confidence, source attribution, path.
func TestJSON_GoldenFile(t *testing.T) {
	findings := []*commit0v1.Finding{
		symbolReachableFinding3Steps(),
		packageReachableFinding(),
		unknownFinding(),
		notReachableFinding(),
	}

	out, err := render.ToJSON(findings)
	require.NoError(t, err)

	// Must be valid JSON.
	var parsed interface{}
	require.NoError(t, json.Unmarshal(out, &parsed), "ToJSON must produce valid JSON")

	// Structural checks.
	root, ok := parsed.([]interface{})
	require.True(t, ok, "JSON root must be an array of findings")
	assert.Len(t, root, 4, "all 4 findings must be present")

	// Find the SYMBOL_REACHABLE entry (GO-2024-0001) and verify its structure.
	var symbolEntry map[string]interface{}
	for _, item := range root {
		entry := item.(map[string]interface{})
		if adv, ok := entry["advisory"].(map[string]interface{}); ok {
			if adv["id"] == "GO-2024-0001" {
				symbolEntry = entry
				break
			}
		}
	}
	require.NotNil(t, symbolEntry, "SYMBOL_REACHABLE finding must be present in JSON output")

	// Confidence must be present and meaningful.
	assert.NotEmpty(t, symbolEntry["confidence"], "confidence field must be present")

	// Source attribution: the advisory URL and aliases must be present.
	adv := symbolEntry["advisory"].(map[string]interface{})
	assert.Equal(t, "GO-2024-0001", adv["id"])
	assert.Equal(t, "https://pkg.go.dev/vuln/GO-2024-0001", adv["url"])
	aliases, ok := adv["aliases"].([]interface{})
	require.True(t, ok, "aliases must be present")
	assert.Contains(t, aliases, "CVE-2024-12345")

	// Path must be present for SYMBOL_REACHABLE.
	path, ok := symbolEntry["path"].(map[string]interface{})
	require.True(t, ok, "path must be present for SYMBOL_REACHABLE finding")
	steps, ok := path["steps"].([]interface{})
	require.True(t, ok, "path.steps must be present")
	assert.Len(t, steps, 3, "3 call steps must be present")

	// Properties (goos, algorithm, snapshot_digest) must be present.
	props, ok := symbolEntry["properties"].(map[string]interface{})
	require.True(t, ok, "properties must be present")
	assert.Equal(t, "linux", props["goos"])
	assert.Equal(t, "vta", props["algorithm"])

	// Golden-file check.
	if *updateGolden {
		goldenWrite(t, "json_findings.golden.json", out)
	}
	golden := goldenRead(t, "json_findings.golden.json")
	assert.JSONEq(t, string(golden), string(out), "JSON output must match golden file")
}

// TestJSON_SortOrder verifies findings are sorted deterministically (by advisory ID).
func TestJSON_SortOrder(t *testing.T) {
	// Provide findings in reverse order; output must be sorted by advisory ID.
	findings := []*commit0v1.Finding{
		{
			Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0003"},
			Module:     "example.com/z",
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			Severity:   commit0v1.Severity_SEVERITY_LOW,
		},
		{
			Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
			Module:     "example.com/a",
			Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			Severity:   commit0v1.Severity_SEVERITY_HIGH,
		},
		{
			Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0002"},
			Module:     "example.com/b",
			Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			Severity:   commit0v1.Severity_SEVERITY_MEDIUM,
		},
	}

	out, err := render.ToJSON(findings)
	require.NoError(t, err)

	var parsed []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed, 3)

	ids := make([]string, len(parsed))
	for i, e := range parsed {
		ids[i] = e["advisory"].(map[string]interface{})["id"].(string)
	}
	assert.Equal(t, []string{"GO-2024-0001", "GO-2024-0002", "GO-2024-0003"}, ids,
		"findings must be sorted by advisory ID for deterministic output")
}

// TestJSON_NilInput verifies that a nil or empty input produces a valid empty JSON array.
func TestJSON_NilInput(t *testing.T) {
	out, err := render.ToJSON(nil)
	require.NoError(t, err)
	assert.JSONEq(t, "[]", string(out))
}

// TestJSON_ProvenanceBlockDistinctFromSources locks the contract that the typed
// provenance block exposes the per-source provenance SUMMARY under "summary"
// (name SEVERITY vector), which is a different value from properties["sources"]
// (the comma-joined contributing-source list). Regression guard: the provenance
// summary must never be emitted under a "sources" key (which previously collided
// with the real source list and read as "go-vuln-db UNSPECIFIED").
func TestJSON_ProvenanceBlockDistinctFromSources(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: map[string]string{
				"sources":           "go-vuln-db,osv.dev",
				"provenance":        "go-vuln-db UNSPECIFIED; osv.dev HIGH",
				"severity_conflict": "go-vuln-db:UNSPECIFIED,osv.dev:HIGH",
			},
		},
	}

	out, err := render.ToJSON(findings)
	require.NoError(t, err)

	var parsed []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed, 1)

	props := parsed[0]["properties"].(map[string]interface{})
	assert.Equal(t, "go-vuln-db,osv.dev", props["sources"],
		"properties.sources must remain the comma-joined source list")

	prov, ok := parsed[0]["provenance"].(map[string]interface{})
	require.True(t, ok, "typed provenance block must be present")
	assert.Equal(t, "go-vuln-db UNSPECIFIED; osv.dev HIGH", prov["summary"],
		"provenance summary must be under \"summary\"")
	assert.Equal(t, "go-vuln-db:UNSPECIFIED,osv.dev:HIGH", prov["severity_conflict"])
	_, hasSources := prov["sources"]
	assert.False(t, hasSources,
		"provenance block must NOT carry a \"sources\" key (collides with the real source list)")
}
