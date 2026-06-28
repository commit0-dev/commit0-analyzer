package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// TestEmitVEX_StatusMappingAndCardinalSin drives the scan-side VEX wiring end to
// end: it builds findings spanning every confidence tier, emits OpenVEX to a
// file, and asserts the status mapping — in particular that an UNKNOWN finding
// and an incomplete NOT_REACHABLE finding are under_investigation, never
// not_affected.
func TestEmitVEX_StatusMappingAndCardinalSin(t *testing.T) {
	findings := []*anstv1.Finding{
		{
			Advisory:   &anstv1.AdvisoryRef{Id: "CVE-2024-0001", Aliases: []string{"GHSA-xxxx"}},
			Module:     "golang.org/x/net",
			Confidence: anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		},
		{
			Advisory:   &anstv1.AdvisoryRef{Id: "CVE-2024-0002"},
			Module:     "github.com/foo/bar",
			Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		},
		{
			Advisory:   &anstv1.AdvisoryRef{Id: "CVE-2024-0003"},
			Module:     "github.com/baz/qux",
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		},
		{
			// Incomplete NOT_REACHABLE: must NOT become not_affected.
			Advisory:   &anstv1.AdvisoryRef{Id: "CVE-2024-0004"},
			Module:     "github.com/partial/dep",
			Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
			Incomplete: true,
		},
		{
			// Synthetic/no-advisory marker: skipped entirely.
			Advisory:   &anstv1.AdvisoryRef{},
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		},
	}
	advByID := map[string]*advisory.Advisory{
		"CVE-2024-0001": {ID: "CVE-2024-0001", Module: "golang.org/x/net", Ecosystem: advisory.EcosystemGo, VersionRanges: []advisory.VersionRange{{Fixed: "v0.17.0"}}},
		"CVE-2024-0002": {ID: "CVE-2024-0002", Module: "github.com/foo/bar", Ecosystem: advisory.EcosystemGo},
		"CVE-2024-0003": {ID: "CVE-2024-0003", Module: "github.com/baz/qux", Ecosystem: advisory.EcosystemGo},
		"CVE-2024-0004": {ID: "CVE-2024-0004", Module: "github.com/partial/dep", Ecosystem: advisory.EcosystemGo},
	}

	out := filepath.Join(t.TempDir(), "vex.json")
	err := emitVEX(scanFlags{vexFormat: "openvex", vexOut: out}, findings, advByID, false)
	if err != nil {
		t.Fatalf("emitVEX: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read VEX output: %v", err)
	}
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse VEX: %v", err)
	}

	if len(doc.Statements) != 4 {
		t.Fatalf("want 4 statements (synthetic skipped), got %d", len(doc.Statements))
	}
	byVuln := map[string]string{}
	for _, s := range doc.Statements {
		byVuln[s.Vulnerability.Name] = s.Status
		if s.Status == "not_affected" && s.Justification == "" {
			t.Errorf("%s: not_affected without justification", s.Vulnerability.Name)
		}
	}
	want := map[string]string{
		"CVE-2024-0001": "affected",
		"CVE-2024-0002": "not_affected",
		"CVE-2024-0003": "under_investigation",
		"CVE-2024-0004": "under_investigation", // incomplete NOT_REACHABLE — cardinal-sin guard
	}
	for id, ws := range want {
		if byVuln[id] != ws {
			t.Errorf("%s: status %q want %q", id, byVuln[id], ws)
		}
	}
}

// TestEmitVEX_ScanLevelIncompleteGuard covers the host-side incomplete path that
// the per-finding flag alone cannot express: a NOT_REACHABLE finding whose own
// Incomplete=false, emitted under a scan-level incomplete=true (e.g. the JS
// modelIncomplete partial dependency closure). The reachability proof was built
// over an incomplete graph, so it must map to under_investigation, never
// not_affected — the cardinal-sin guard.
func TestEmitVEX_ScanLevelIncompleteGuard(t *testing.T) {
	findings := []*anstv1.Finding{
		{
			// NOT_REACHABLE with per-finding Incomplete=false: only the scan
			// aggregate flags the partial closure.
			Advisory:   &anstv1.AdvisoryRef{Id: "CVE-2024-1000"},
			Module:     "github.com/partial/closure",
			Confidence: anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
			Incomplete: false,
		},
	}
	advByID := map[string]*advisory.Advisory{
		"CVE-2024-1000": {ID: "CVE-2024-1000", Module: "github.com/partial/closure", Ecosystem: advisory.EcosystemGo},
	}

	out := filepath.Join(t.TempDir(), "vex.json")
	if err := emitVEX(scanFlags{vexFormat: "openvex", vexOut: out}, findings, advByID, true); err != nil {
		t.Fatalf("emitVEX: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read VEX output: %v", err)
	}
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status string `json:"status"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse VEX: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("want 1 statement, got %d", len(doc.Statements))
	}
	if got := doc.Statements[0].Status; got != "under_investigation" {
		t.Errorf("scan-incomplete NOT_REACHABLE: status %q want %q (cardinal-sin guard)", got, "under_investigation")
	}
}

// TestEmitVEX_UnknownFormatErrors ensures an unrecognised --vex value surfaces
// an error rather than silently producing nothing.
func TestEmitVEX_UnknownFormatErrors(t *testing.T) {
	err := emitVEX(scanFlags{vexFormat: "bogus", vexOut: "-"}, nil, nil, false)
	if err == nil {
		t.Fatal("want error for unknown VEX format")
	}
}
