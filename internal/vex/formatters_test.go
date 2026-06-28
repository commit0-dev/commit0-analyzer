package vex

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden regenerates golden files when -update is passed.
var updateGolden = flag.Bool("update", false, "regenerate golden files")

// sampleDocument builds a document exercising every VEX status: not_affected
// (proven NOT_REACHABLE), affected (reachable, with and without a fix), and
// under_investigation (UNKNOWN and incomplete-NOT_REACHABLE — the anti-clean cases).
func sampleDocument() *Document {
	return BuildDocument(fixedTime, []StatementInput{
		{
			VulnID: "CVE-2024-1000", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
			Ecosystem: "Go", PackageName: "golang.org/x/net", FixedVersion: "v0.17.0",
			Reachability: ReachabilitySymbolReachable,
		},
		{
			VulnID: "CVE-2024-2000", Ecosystem: "npm", PackageName: "lodash",
			Reachability: ReachabilityNotReachable,
		},
		{
			VulnID: "CVE-2024-3000", Ecosystem: "PyPI", PackageName: "requests",
			Reachability: ReachabilityUnknown,
		},
		{
			VulnID: "CVE-2024-4000", Ecosystem: "Maven", PackageName: "org.apache.logging.log4j:log4j-core",
			Reachability: ReachabilityNotReachable, Incomplete: true,
		},
	})
}

func goldenPath(name string) string { return filepath.Join("testdata", name) }

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(name)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output for %s does not match golden\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func mustJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return m
}

func TestOpenVEXFormatter_Golden(t *testing.T) {
	got, err := OpenVEXFormatter{}.Format(sampleDocument())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "openvex.golden.json", got)

	m := mustJSON(t, got)
	if m["@context"] != openVEXContext {
		t.Errorf("@context = %v", m["@context"])
	}
	if m["author"] != Author {
		t.Errorf("author = %v", m["author"])
	}
	stmts, ok := m["statements"].([]any)
	if !ok || len(stmts) != 4 {
		t.Fatalf("want 4 statements, got %v", m["statements"])
	}
	// Anti-clean: no incomplete/unknown statement may be not_affected.
	for _, s := range stmts {
		sm := s.(map[string]any)
		status := sm["status"].(string)
		if status == string(StatusNotAffected) {
			if sm["justification"] != string(JustificationVulnerableCodeNotInExecutePath) {
				t.Errorf("not_affected missing required justification: %v", sm)
			}
		}
		if status == string(StatusAffected) {
			if sm["action_statement"] == nil || sm["action_statement"] == "" {
				t.Errorf("affected missing required action_statement: %v", sm)
			}
		}
	}
}

func TestCycloneDXFormatter_Golden(t *testing.T) {
	got, err := CycloneDXFormatter{}.Format(sampleDocument())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "cyclonedx.golden.json", got)

	m := mustJSON(t, got)
	if m["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", m["bomFormat"])
	}
	if m["specVersion"] != "1.5" {
		t.Errorf("specVersion = %v", m["specVersion"])
	}
	vulns, ok := m["vulnerabilities"].([]any)
	if !ok || len(vulns) != 4 {
		t.Fatalf("want 4 vulnerabilities, got %v", m["vulnerabilities"])
	}
	validStates := map[string]bool{"not_affected": true, "exploitable": true, "in_triage": true, "resolved": true}
	for _, v := range vulns {
		vm := v.(map[string]any)
		an := vm["analysis"].(map[string]any)
		if !validStates[an["state"].(string)] {
			t.Errorf("invalid CycloneDX state %v", an["state"])
		}
	}
}

func TestCSAFFormatter_Golden(t *testing.T) {
	got, err := CSAFFormatter{}.Format(sampleDocument())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "csaf.golden.json", got)

	m := mustJSON(t, got)
	docMeta := m["document"].(map[string]any)
	if docMeta["category"] != "csaf_vex" {
		t.Errorf("category = %v", docMeta["category"])
	}
	if docMeta["csaf_version"] != "2.0" {
		t.Errorf("csaf_version = %v", docMeta["csaf_version"])
	}
	vulns := m["vulnerabilities"].([]any)
	if len(vulns) != 4 {
		t.Fatalf("want 4 vulnerabilities, got %d", len(vulns))
	}
	// The incomplete NOT_REACHABLE finding must be under_investigation, never
	// known_not_affected (cardinal sin at the CSAF layer).
	for _, v := range vulns {
		vm := v.(map[string]any)
		if vm["cve"] == "CVE-2024-4000" {
			ps := vm["product_status"].(map[string]any)
			if ps["known_not_affected"] != nil {
				t.Errorf("incomplete finding wrongly listed as known_not_affected: %v", ps)
			}
			if ps["under_investigation"] == nil {
				t.Errorf("incomplete finding must be under_investigation: %v", ps)
			}
		}
	}
}

// TestFormatters_Deterministic asserts every formatter is byte-identical across
// repeated renders of the same document (no map-iteration leaks, no time.Now()).
func TestFormatters_Deterministic(t *testing.T) {
	for _, f := range allFormatters() {
		a, err := f.Format(sampleDocument())
		if err != nil {
			t.Fatal(err)
		}
		b, err := f.Format(sampleDocument())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s formatter is not deterministic", f.Name())
		}
	}
}
