package render_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"

	"github.com/commit0-dev/commit0-analyzer/internal/render"
)

// ── JS/TS Finding helpers ─────────────────────────────────────────────────────

// jsPackageReachableFinding returns a PACKAGE_REACHABLE JS finding representing
// the serialize-javascript vulnerability (the Gate G1-JS advisory).
func jsPackageReachableFinding() *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  "GHSA-h9rv-jmmf-4pgx",
			Url: "https://osv.dev/vulnerability/GHSA-h9rv-jmmf-4pgx",
		},
		Module:     "serialize-javascript",
		Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
			"workspace": "default",
		},
		Pillar:   "sca",
		Language: "js",
	}
}

// jsSymbolReachableFinding returns a SYMBOL_REACHABLE JS finding with a
// two-step ReachabilityPath (first-party call → import site).
func jsSymbolReachableFinding() *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  "GHSA-synth-sym-001",
			Url: "https://osv.dev/vulnerability/GHSA-synth-sym-001",
		},
		Module:     "serialize-javascript",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Path: &commit0v1.ReachabilityPath{
			Steps: []*commit0v1.CallStep{
				{
					Location: &commit0v1.Location{File: "src/index.js", Line: 3, Column: 1},
					Symbol:   "run",
				},
				{
					Location: &commit0v1.Location{File: "src/index.js", Line: 5, Column: 10},
					Symbol:   "serialize",
				},
			},
		},
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
			"workspace": "default",
		},
		Pillar:   "sca",
		Language: "js",
	}
}

// jsNotReachableFinding returns a NOT_REACHABLE JS finding for lodash (installed
// but not imported from any entrypoint).
func jsNotReachableFinding() *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  "GHSA-lodash-not-imported",
			Url: "https://osv.dev/vulnerability/GHSA-lodash-not-imported",
		},
		Module:     "lodash",
		Confidence: commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_MEDIUM,
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
			"workspace": "default",
		},
		Pillar:   "sca",
		Language: "js",
	}
}

// jsUnknownFinding returns an UNKNOWN JS finding for a dynamic-require path.
func jsUnknownFinding() *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  "GHSA-dyn-require-001",
			Url: "https://osv.dev/vulnerability/GHSA-dyn-require-001",
		},
		Module:     "some-package",
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
			"workspace": "default",
		},
		Pillar:   "sca",
		Language: "js",
	}
}

// jsPhantomReachableFinding returns a PACKAGE_REACHABLE JS finding for a
// phantom (undeclared) dependency. The phantom property must be rendered.
func jsPhantomReachableFinding() *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  "GHSA-phantom-dep-001",
			Url: "https://osv.dev/vulnerability/GHSA-phantom-dep-001",
		},
		Module:     "hoisted-phantom",
		Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_CRITICAL,
		Properties: map[string]string{
			"algorithm": "conservative-flow",
			"language":  "js",
			"workspace": "default",
			"phantom":   "true",
		},
		Pillar:   "sca",
		Language: "js",
	}
}

// ── SARIF golden tests for JS tiers ──────────────────────────────────────────

// TestSARIF_JS_PackageReachable_NoCodeFlows verifies that a PACKAGE_REACHABLE
// JS finding does not have codeFlows (no concrete call path at MVP).
func TestSARIF_JS_PackageReachable_NoCodeFlows(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := jsPackageReachableFinding()

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1, "PACKAGE_REACHABLE JS finding must appear in results")

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GHSA-h9rv-jmmf-4pgx", result["ruleId"])
	assert.Equal(t, "error", result["level"], "HIGH PACKAGE_REACHABLE must render as error")

	// PACKAGE_REACHABLE has no path steps → no codeFlows.
	_, hasCF := result["codeFlows"]
	assert.False(t, hasCF, "PACKAGE_REACHABLE JS finding must omit codeFlows (no concrete call path)")

	// language property must be "js".
	props := result["properties"].(map[string]interface{})
	assert.Equal(t, "js", props["language"], "JS finding must carry language=js in SARIF properties")
}

// TestSARIF_JS_SymbolReachable_HasCodeFlows verifies that a SYMBOL_REACHABLE JS
// finding produces codeFlows with the call steps.
func TestSARIF_JS_SymbolReachable_HasCodeFlows(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := jsSymbolReachableFinding()

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GHSA-synth-sym-001", result["ruleId"])

	// SYMBOL_REACHABLE with 2 steps → codeFlows with 2 locations.
	codeFlows, hasCF := result["codeFlows"].([]interface{})
	require.True(t, hasCF, "SYMBOL_REACHABLE JS finding must have codeFlows")
	require.Len(t, codeFlows, 1)

	tf := codeFlows[0].(map[string]interface{})["threadFlows"].([]interface{})
	locs := tf[0].(map[string]interface{})["locations"].([]interface{})
	assert.Len(t, locs, 2, "2-step JS path must produce 2 threadFlowLocations")

	// Verify the first step references the JS source file.
	loc0 := locs[0].(map[string]interface{})["location"].(map[string]interface{})
	phys0 := loc0["physicalLocation"].(map[string]interface{})
	assert.Equal(t, "src/index.js",
		phys0["artifactLocation"].(map[string]interface{})["uri"],
		"first step must reference the JS source file")
}

// TestSARIF_JS_NotReachable_Suppressed verifies that a NOT_REACHABLE JS finding
// is rendered as suppressed (auditable, not silently absent).
func TestSARIF_JS_NotReachable_Suppressed(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := jsNotReachableFinding()

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1, "NOT_REACHABLE JS finding must not be silently dropped")

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GHSA-lodash-not-imported", result["ruleId"])
	assert.Equal(t, "note", result["level"], "NOT_REACHABLE must be rendered as note level")

	// Must be suppressed.
	suppressions, hasSup := result["suppressions"].([]interface{})
	require.True(t, hasSup, "NOT_REACHABLE JS finding must have suppressions (auditable, not absent)")
	require.NotEmpty(t, suppressions)
	sup := suppressions[0].(map[string]interface{})
	assert.Equal(t, "external", sup["kind"])
	assert.NotEmpty(t, sup["justification"])

	// No codeFlows for NOT_REACHABLE.
	_, hasCF := result["codeFlows"]
	assert.False(t, hasCF, "NOT_REACHABLE JS finding must omit codeFlows")
}

// TestSARIF_JS_Unknown_SurfacedAsNormalResult verifies that an UNKNOWN JS finding
// is NOT suppressed — it must appear as an ordinary result (unknown ≠ safe).
func TestSARIF_JS_Unknown_SurfacedAsNormalResult(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := jsUnknownFinding()

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1, "UNKNOWN JS finding must appear as a normal result")

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GHSA-dyn-require-001", result["ruleId"])

	// UNKNOWN must NOT be suppressed.
	_, hasSup := result["suppressions"]
	assert.False(t, hasSup, "UNKNOWN JS finding must not have suppressions (unknown ≠ safe)")

	// No codeFlows for UNKNOWN.
	_, hasCF := result["codeFlows"]
	assert.False(t, hasCF, "UNKNOWN JS finding (no path) must omit codeFlows")
}

// TestSARIF_JS_Phantom_RenderedWithPhantomTag verifies that a phantom (undeclared)
// dependency finding carries the phantom property in SARIF properties.
func TestSARIF_JS_Phantom_RenderedWithPhantomTag(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := jsPhantomReachableFinding()

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	result := results[0].(map[string]interface{})
	props := result["properties"].(map[string]interface{})

	// The phantom property must be present.
	assert.Equal(t, "true", props["phantom"],
		"phantom finding must carry phantom=true in SARIF properties")

	// The phantom (undeclared) tag is surfaced as properties["phantom"]="true" in SARIF
	// and JSON output. It is NOT embedded inline in the message text — operators who need
	// it can filter on the property. Inserting it into the human-readable message would
	// require changing the generic renderer; that is a deliberate scope boundary.
	msg := result["message"].(map[string]interface{})["text"].(string)
	assert.Equal(t, "GHSA-phantom-dep-001", result["ruleId"])
	assert.NotEmpty(t, msg, "phantom finding must have a non-empty message")
}

// TestSARIF_JS_MixedTiers_AllFiveTiers verifies a mixed JS document containing
// all five tier cases (PACKAGE_REACHABLE, SYMBOL_REACHABLE, NOT_REACHABLE,
// UNKNOWN, phantom PACKAGE_REACHABLE) against the SARIF schema. Asserts:
//   - Schema valid
//   - All 5 results present (none dropped)
//   - Only SYMBOL_REACHABLE has codeFlows
//   - NOT_REACHABLE is suppressed
//   - UNKNOWN is not suppressed
//   - phantom carries phantom=true property
//   - language=js on all findings
func TestSARIF_JS_MixedTiers_AllFiveTiers(t *testing.T) {
	schema := compileSARIFSchema(t)

	findings := []*commit0v1.Finding{
		jsPackageReachableFinding(),
		jsSymbolReachableFinding(),
		jsNotReachableFinding(),
		jsUnknownFinding(),
		jsPhantomReachableFinding(),
	}

	out, err := render.ToSARIF(findings)
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	assert.Len(t, results, 5, "all 5 JS tier results must be present")

	ruleIDs := make(map[string]map[string]interface{})
	for _, r := range results {
		res := r.(map[string]interface{})
		ruleIDs[res["ruleId"].(string)] = res
	}

	// Verify each tier.
	symRes := ruleIDs["GHSA-synth-sym-001"]
	require.NotNil(t, symRes, "SYMBOL_REACHABLE result must be present")
	_, symHasCF := symRes["codeFlows"]
	assert.True(t, symHasCF, "SYMBOL_REACHABLE must have codeFlows")

	pkgRes := ruleIDs["GHSA-h9rv-jmmf-4pgx"]
	require.NotNil(t, pkgRes, "PACKAGE_REACHABLE result must be present")
	_, pkgHasCF := pkgRes["codeFlows"]
	assert.False(t, pkgHasCF, "PACKAGE_REACHABLE must omit codeFlows")

	notRes := ruleIDs["GHSA-lodash-not-imported"]
	require.NotNil(t, notRes, "NOT_REACHABLE result must be present")
	_, notHasSup := notRes["suppressions"]
	assert.True(t, notHasSup, "NOT_REACHABLE must be suppressed")
	_, notHasCF := notRes["codeFlows"]
	assert.False(t, notHasCF, "NOT_REACHABLE must omit codeFlows")

	unknRes := ruleIDs["GHSA-dyn-require-001"]
	require.NotNil(t, unknRes, "UNKNOWN result must be present")
	_, unknHasSup := unknRes["suppressions"]
	assert.False(t, unknHasSup, "UNKNOWN must not be suppressed")

	phantRes := ruleIDs["GHSA-phantom-dep-001"]
	require.NotNil(t, phantRes, "phantom PACKAGE_REACHABLE result must be present")
	phantProps := phantRes["properties"].(map[string]interface{})
	assert.Equal(t, "true", phantProps["phantom"], "phantom finding must carry phantom property")
	_, phantHasCF := phantRes["codeFlows"]
	assert.False(t, phantHasCF, "phantom PACKAGE_REACHABLE must omit codeFlows")

	// All JS findings must carry language=js in properties.
	for id, res := range ruleIDs {
		props := res["properties"].(map[string]interface{})
		assert.Equal(t, "js", props["language"], "result %s must have language=js", id)
	}
}

// ── JSON golden tests for JS tiers ───────────────────────────────────────────

// TestJSON_JS_AllFiveTiers verifies that all five JS tier findings are correctly
// marshalled to JSON: confidence labels, language, phantom property.
func TestJSON_JS_AllFiveTiers(t *testing.T) {
	findings := []*commit0v1.Finding{
		jsPackageReachableFinding(),
		jsSymbolReachableFinding(),
		jsNotReachableFinding(),
		jsUnknownFinding(),
		jsPhantomReachableFinding(),
	}

	out, err := render.ToJSON(findings)
	require.NoError(t, err)

	var parsed []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed, 5, "all 5 JS tier findings must be present in JSON")

	byID := make(map[string]map[string]interface{})
	for _, e := range parsed {
		id := e["advisory"].(map[string]interface{})["id"].(string)
		byID[id] = e
	}

	// PACKAGE_REACHABLE: no path, language=js.
	pkg := byID["GHSA-h9rv-jmmf-4pgx"]
	require.NotNil(t, pkg)
	assert.Equal(t, "CONFIDENCE_PACKAGE_REACHABLE", pkg["confidence"])
	assert.Equal(t, "js", pkg["language"])
	assert.Nil(t, pkg["path"], "PACKAGE_REACHABLE must have no path in JSON")

	// SYMBOL_REACHABLE: has path with 2 steps.
	sym := byID["GHSA-synth-sym-001"]
	require.NotNil(t, sym)
	assert.Equal(t, "CONFIDENCE_SYMBOL_REACHABLE", sym["confidence"])
	path, ok := sym["path"].(map[string]interface{})
	require.True(t, ok, "SYMBOL_REACHABLE must have a path")
	steps := path["steps"].([]interface{})
	assert.Len(t, steps, 2, "2-step JS symbol path must produce 2 JSON steps")

	// NOT_REACHABLE: no path, confidence label correct.
	notR := byID["GHSA-lodash-not-imported"]
	require.NotNil(t, notR)
	assert.Equal(t, "CONFIDENCE_NOT_REACHABLE", notR["confidence"])
	assert.Nil(t, notR["path"])

	// UNKNOWN: no path, confidence label correct.
	unkn := byID["GHSA-dyn-require-001"]
	require.NotNil(t, unkn)
	assert.Equal(t, "CONFIDENCE_UNKNOWN", unkn["confidence"])
	assert.Nil(t, unkn["path"])

	// Phantom: phantom property must be present.
	phantom := byID["GHSA-phantom-dep-001"]
	require.NotNil(t, phantom)
	props := phantom["properties"].(map[string]interface{})
	assert.Equal(t, "true", props["phantom"], "phantom finding must carry phantom=true in JSON properties")
}

// ── Table render tests for JS tiers ──────────────────────────────────────────

// TestTable_JS_AllFiveTiers verifies that all five JS tier findings appear in
// the table output with correct confidence labels and language attribution.
func TestTable_JS_AllFiveTiers(t *testing.T) {
	findings := []*commit0v1.Finding{
		jsPackageReachableFinding(),
		jsSymbolReachableFinding(),
		jsNotReachableFinding(),
		jsUnknownFinding(),
		jsPhantomReachableFinding(),
	}

	out := render.ToTable(findings)
	tableStr := string(out)

	// All five advisory IDs must appear.
	assert.Contains(t, tableStr, "GHSA-h9rv-jmmf", "PACKAGE_REACHABLE JS finding must appear in table")
	assert.Contains(t, tableStr, "GHSA-synth-sym", "SYMBOL_REACHABLE JS finding must appear in table")
	assert.Contains(t, tableStr, "GHSA-lodash", "NOT_REACHABLE JS finding must appear in table")
	assert.Contains(t, tableStr, "GHSA-dyn-req", "UNKNOWN JS finding must appear in table")
	assert.Contains(t, tableStr, "GHSA-phantom", "phantom JS finding must appear in table")

	// All confidence labels must appear.
	assert.Contains(t, tableStr, "PKG_REACHABLE", "PACKAGE_REACHABLE confidence must appear")
	assert.Contains(t, tableStr, "SYM_REACHABLE", "SYMBOL_REACHABLE confidence must appear")
	assert.Contains(t, tableStr, "NOT_REACHABLE", "NOT_REACHABLE confidence must appear")
	assert.Contains(t, tableStr, "UNKNOWN", "UNKNOWN confidence must appear")

	// SYMBOL_REACHABLE finding must have its call path printed below the row.
	assert.Contains(t, tableStr, "src/index.js", "SYMBOL_REACHABLE JS call path must reference source file")

	// Table must have a header.
	assert.Contains(t, tableStr, "ADVISORY", "table must have header")
}

// TestTable_JS_Deterministic verifies that ToTable produces byte-identical
// output across two calls with the same findings.
func TestTable_JS_Deterministic(t *testing.T) {
	findings := []*commit0v1.Finding{
		jsPackageReachableFinding(),
		jsNotReachableFinding(),
		jsUnknownFinding(),
	}

	out1 := render.ToTable(findings)
	out2 := render.ToTable(findings)
	assert.Equal(t, string(out1), string(out2), "ToTable must be deterministic across calls")
}

// TestSARIF_JS_LanguageFieldOnFindings verifies that the language field
// ("js" or "ts") flows through to SARIF properties on all JS findings.
func TestSARIF_JS_LanguageFieldOnFindings(t *testing.T) {
	schema := compileSARIFSchema(t)

	// A TypeScript finding: language should be "ts".
	tsF := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GHSA-ts-vuln-001"},
		Module:     "some-ts-lib",
		Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"language": "ts",
		},
		Language: "ts",
		Pillar:   "sca",
	}

	out, err := render.ToSARIF([]*commit0v1.Finding{tsF})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	result := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})[0].(map[string]interface{})
	props := result["properties"].(map[string]interface{})
	assert.Equal(t, "ts", props["language"], "TypeScript finding must carry language=ts in SARIF properties")
}

// TestSARIF_JS_UNKNOWN_IsGateEligible_RendersWithoutSuppression verifies the
// "unknown ≠ safe" invariant at the SARIF render layer: an UNKNOWN JS finding
// renders without suppressions so that any downstream SARIF consumer that
// counts non-suppressed results counts this finding.
func TestSARIF_JS_UNKNOWN_IsGateEligible_RendersWithoutSuppression(t *testing.T) {
	schema := compileSARIFSchema(t)

	f := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GHSA-unknown-js-001"},
		Module:     "dynamic-loader",
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{"language": "js"},
		Language:   "js",
		Pillar:     "sca",
	}

	out, err := render.ToSARIF([]*commit0v1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)
	result := results[0].(map[string]interface{})

	// No suppressions: UNKNOWN is surfaced, not muted.
	_, hasSup := result["suppressions"]
	assert.False(t, hasSup, "UNKNOWN JS finding must not be suppressed (unknown ≠ safe)")

	// Message must explain why it is surfaced.
	msg := result["message"].(map[string]interface{})["text"].(string)
	assert.True(t, strings.Contains(msg, "unknown") || strings.Contains(msg, "Unknown") || strings.Contains(msg, "UNKNOWN"),
		"UNKNOWN result message must mention that reachability is undetermined")
}
