package render_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"

	"github.com/ducthinh993/anst-analyzer/internal/render"
)

// updateGolden regenerates golden files when -update is passed.
var updateGolden = flag.Bool("update", false, "regenerate golden files")

// schemaPath is the vendored SARIF 2.1.0 JSON schema.
const schemaPath = "schema/sarif-schema-2.1.0.json"

// compileSARIFSchema compiles the vendored SARIF schema once for reuse.
func compileSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	// Read the schema file and add it as a resource.
	schemaBytes, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "must read SARIF schema from %s", schemaPath)
	err = compiler.AddResource("sarif-schema-2.1.0.json", bytes.NewReader(schemaBytes))
	require.NoError(t, err, "must add SARIF schema resource")
	schema, err := compiler.Compile("sarif-schema-2.1.0.json")
	require.NoError(t, err, "must compile SARIF schema")
	return schema
}

// validateSARIF validates raw JSON bytes against the compiled SARIF schema.
func validateSARIF(t *testing.T, schema *jsonschema.Schema, data []byte) {
	t.Helper()
	var v interface{}
	require.NoError(t, json.Unmarshal(data, &v), "SARIF must be valid JSON")
	err := schema.Validate(v)
	if err != nil {
		t.Fatalf("SARIF schema validation failed:\n%v", err)
	}
}

// goldenRead reads a golden file and returns its contents.
func goldenRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err, "must read golden file testdata/%s", name)
	return data
}

// goldenWrite writes bytes to a golden file (creates testdata/ if needed).
func goldenWrite(t *testing.T, name string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll("testdata", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", name), data, 0o644))
}

// --- helpers to build test findings ---

func symbolReachableFinding3Steps() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id:      "GO-2024-0001",
			Url:     "https://pkg.go.dev/vuln/GO-2024-0001",
			Aliases: []string{"CVE-2024-12345"},
		},
		Module:     "golang.org/x/net",
		Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Path: &anstv1.ReachabilityPath{
			Steps: []*anstv1.CallStep{
				{
					Location: &anstv1.Location{File: "cmd/main.go", Line: 42, Column: 5},
					Symbol:   "main.main",
				},
				{
					Location: &anstv1.Location{File: "internal/client/client.go", Line: 17, Column: 3},
					Symbol:   "internal/client.Client.Do",
				},
				{
					Location: &anstv1.Location{File: "vendor/golang.org/x/net/http2/transport.go", Line: 99, Column: 12},
					Symbol:   "golang.org/x/net/http2.(*Transport).RoundTrip",
				},
			},
		},
		Properties: map[string]string{
			"goos":            "linux",
			"goarch":          "amd64",
			"algorithm":       "vta",
			"snapshot_digest": "sha256:abc123",
		},
		Pillar:   "sca",
		Language: "go",
	}
}

func notReachableFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id:  "GO-2024-0002",
			Url: "https://pkg.go.dev/vuln/GO-2024-0002",
		},
		Module:     "github.com/example/lib",
		Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_MEDIUM,
		Properties: map[string]string{
			"goos":      "linux",
			"algorithm": "vta",
		},
	}
}

func unknownFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id:  "GO-2024-0003",
			Url: "https://pkg.go.dev/vuln/GO-2024-0003",
		},
		Module:     "github.com/example/reflection",
		Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		Severity:   anstv1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"goos":      "linux",
			"algorithm": "vta",
		},
	}
}

func packageReachableFinding() *anstv1.Finding {
	return &anstv1.Finding{
		Advisory: &anstv1.AdvisoryRef{
			Id:  "GO-2024-0004",
			Url: "https://pkg.go.dev/vuln/GO-2024-0004",
		},
		Module:     "github.com/example/pkg",
		Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		Severity:   anstv1.Severity_SEVERITY_CRITICAL,
		Properties: map[string]string{
			"goos":      "linux",
			"algorithm": "vta",
		},
	}
}

// --- Tests ---

// TestSARIF_SymbolReachable_ThreeStepPath verifies that a SYMBOL_REACHABLE finding
// with 3 call steps produces exactly 3 ordered threadFlowLocations in codeFlows,
// validates against the SARIF schema, and matches the golden file.
func TestSARIF_SymbolReachable_ThreeStepPath(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := symbolReachableFinding3Steps()

	out, err := render.ToSARIF([]*anstv1.Finding{f})
	require.NoError(t, err)

	// Validate against the SARIF schema.
	validateSARIF(t, schema, out)

	// Structural assertions on the parsed output.
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	runs := doc["runs"].([]interface{})
	require.Len(t, runs, 1)
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	require.Len(t, results, 1)
	result := results[0].(map[string]interface{})

	// Must have codeFlows with exactly 1 codeFlow containing 3 locations.
	codeFlows, ok := result["codeFlows"].([]interface{})
	require.True(t, ok, "SYMBOL_REACHABLE result must have codeFlows")
	require.Len(t, codeFlows, 1)

	cf := codeFlows[0].(map[string]interface{})
	threadFlows := cf["threadFlows"].([]interface{})
	require.Len(t, threadFlows, 1)

	locations := threadFlows[0].(map[string]interface{})["locations"].([]interface{})
	assert.Len(t, locations, 3, "3-step path must produce 3 threadFlowLocations in order")

	// Verify first and last step file references.
	loc0 := locations[0].(map[string]interface{})["location"].(map[string]interface{})
	phys0 := loc0["physicalLocation"].(map[string]interface{})
	assert.Equal(t, "cmd/main.go", phys0["artifactLocation"].(map[string]interface{})["uri"])

	loc2 := locations[2].(map[string]interface{})["location"].(map[string]interface{})
	phys2 := loc2["physicalLocation"].(map[string]interface{})
	assert.Equal(t, "vendor/golang.org/x/net/http2/transport.go", phys2["artifactLocation"].(map[string]interface{})["uri"])

	// ruleId must be the advisory ID.
	assert.Equal(t, "GO-2024-0001", result["ruleId"])
	// severity HIGH → level "error".
	assert.Equal(t, "error", result["level"])

	// Golden-file check.
	if *updateGolden {
		goldenWrite(t, "sarif_symbol_reachable.golden.json", out)
	}
	golden := goldenRead(t, "sarif_symbol_reachable.golden.json")
	assert.JSONEq(t, string(golden), string(out), "SARIF output must match golden file")
}

// TestSARIF_NotReachable_NotSilentlyDropped verifies that a NOT_REACHABLE finding
// is never silently absent: it MUST appear as a suppressed result or note-level result.
func TestSARIF_NotReachable_NotSilentlyDropped(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := notReachableFinding()

	out, err := render.ToSARIF([]*anstv1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	require.Len(t, results, 1, "NOT_REACHABLE finding must not be silently dropped")

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GO-2024-0002", result["ruleId"])

	// Must have NO codeFlows (NOT_REACHABLE has no path steps).
	_, hasCF := result["codeFlows"]
	assert.False(t, hasCF, "NOT_REACHABLE finding must omit codeFlows entirely (Red Team #9)")

	// Must be suppressed OR be a note-level result (auditable, not silently absent).
	suppressions, hasSup := result["suppressions"].([]interface{})
	level, _ := result["level"].(string)
	if hasSup {
		require.NotEmpty(t, suppressions, "suppression array must not be empty when present")
		sup := suppressions[0].(map[string]interface{})
		assert.Equal(t, "external", sup["kind"])
		assert.NotEmpty(t, sup["justification"], "suppression must carry a justification")
	} else {
		// Alternatively rendered as a note-level result with a message explaining non-reachability.
		assert.Equal(t, "note", level, "NOT_REACHABLE without suppression must be rendered at note level")
	}
}

// TestSARIF_Unknown_AppearsAsNormalResult verifies that an UNKNOWN finding is NOT
// suppressed — it must appear as a regular (non-suppressed) result.
func TestSARIF_Unknown_AppearsAsNormalResult(t *testing.T) {
	schema := compileSARIFSchema(t)
	f := unknownFinding()

	out, err := render.ToSARIF([]*anstv1.Finding{f})
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	require.Len(t, results, 1, "UNKNOWN finding must appear as a normal result")

	result := results[0].(map[string]interface{})
	assert.Equal(t, "GO-2024-0003", result["ruleId"])

	// UNKNOWN must NOT be suppressed.
	_, hasSup := result["suppressions"]
	assert.False(t, hasSup, "UNKNOWN finding must not have suppressions (unknown ≠ safe)")

	// No codeFlows for path-less findings.
	_, hasCF := result["codeFlows"]
	assert.False(t, hasCF, "UNKNOWN finding (no path) must omit codeFlows (Red Team #9)")
}

// TestSARIF_MixedDocument validates a mixed document containing all four confidence
// tiers against the SARIF schema. This is the critical Red Team #9 regression test:
// path-less findings must omit codeFlows; the whole doc must still be schema-valid.
func TestSARIF_MixedDocument_SchemaValid(t *testing.T) {
	schema := compileSARIFSchema(t)

	findings := []*anstv1.Finding{
		symbolReachableFinding3Steps(),  // has path → codeFlows present
		packageReachableFinding(),       // no path → codeFlows omitted
		unknownFinding(),                // no path → codeFlows omitted
		notReachableFinding(),           // no path → codeFlows omitted, rendered suppressed
	}

	out, err := render.ToSARIF(findings)
	require.NoError(t, err)

	// Primary check: schema validity of the MIXED document.
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))

	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	assert.Len(t, results, 4, "mixed doc must contain all 4 results (none silently dropped)")

	// Collect ruleIds present to ensure none disappeared.
	ruleIDs := make(map[string]bool)
	for _, r := range results {
		res := r.(map[string]interface{})
		ruleIDs[res["ruleId"].(string)] = true
	}
	assert.True(t, ruleIDs["GO-2024-0001"], "SYMBOL_REACHABLE result must be present")
	assert.True(t, ruleIDs["GO-2024-0002"], "NOT_REACHABLE result must be present (not silently dropped)")
	assert.True(t, ruleIDs["GO-2024-0003"], "UNKNOWN result must be present")
	assert.True(t, ruleIDs["GO-2024-0004"], "PACKAGE_REACHABLE result must be present")

	// Only SYMBOL_REACHABLE may have codeFlows; others must omit them.
	for _, r := range results {
		res := r.(map[string]interface{})
		id := res["ruleId"].(string)
		_, hasCF := res["codeFlows"]
		if id == "GO-2024-0001" {
			assert.True(t, hasCF, "SYMBOL_REACHABLE result must have codeFlows")
		} else {
			assert.False(t, hasCF, "path-less result %s must omit codeFlows (Red Team #9)", id)
		}
	}

	// Golden-file check for the mixed document.
	if *updateGolden {
		goldenWrite(t, "sarif_mixed.golden.json", out)
	}
	golden := goldenRead(t, "sarif_mixed.golden.json")
	assert.JSONEq(t, string(golden), string(out))
}

// TestSARIF_SeverityMapping verifies the severity → SARIF level mapping:
// CRITICAL/HIGH → error, MEDIUM → warning, LOW → note, UNSPECIFIED → none.
func TestSARIF_SeverityMapping(t *testing.T) {
	cases := []struct {
		severity  anstv1.Severity
		wantLevel string
	}{
		{anstv1.Severity_SEVERITY_CRITICAL, "error"},
		{anstv1.Severity_SEVERITY_HIGH, "error"},
		{anstv1.Severity_SEVERITY_MEDIUM, "warning"},
		{anstv1.Severity_SEVERITY_LOW, "note"},
		{anstv1.Severity_SEVERITY_UNSPECIFIED, "none"},
	}

	schema := compileSARIFSchema(t)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.severity.String(), func(t *testing.T) {
			f := &anstv1.Finding{
				Advisory:   &anstv1.AdvisoryRef{Id: "GO-TEST-0001"},
				Module:     "example.com/mod",
				Confidence: anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
				Severity:   tc.severity,
			}
			out, err := render.ToSARIF([]*anstv1.Finding{f})
			require.NoError(t, err)
			validateSARIF(t, schema, out)

			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(out, &doc))
			result := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})[0].(map[string]interface{})
			assert.Equal(t, tc.wantLevel, result["level"])
		})
	}
}

// TestSARIF_EmptyFindings verifies that an empty finding list produces a valid
// SARIF document with an empty results array.
func TestSARIF_EmptyFindings(t *testing.T) {
	schema := compileSARIFSchema(t)
	out, err := render.ToSARIF(nil)
	require.NoError(t, err)
	validateSARIF(t, schema, out)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))
	results := doc["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	assert.Empty(t, results)
}
