package parity

import (
	"bytes"
	"strings"
	"testing"
)

func sampleReport(t *testing.T) *Report {
	t.Helper()
	commit0Analyzer, osv := loadCompareInputs(t)
	return &Report{
		GeneratedFrom: "test",
		Comparisons:   []ComparisonResult{Compare("go-fixture", ToolOSVScanner, commit0Analyzer, osv)},
		Assertions: []Assertion{
			{Name: "determinism/go-fixture", Passed: true, Detail: "byte-identical"},
			{Name: "fail-closed/go-fixture", Passed: true, Detail: "exit 3"},
		},
		SkippedComparators: []SkipNote{{Comparator: ToolTrivy, Reason: "binary not on PATH"}},
	}
}

func TestReportJSONDeterministic(t *testing.T) {
	a, err := sampleReport(t).ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	b, err := sampleReport(t).ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("report JSON is not byte-identical across runs")
	}
}

func TestReportMarkdownContainsSummaryAndMiss(t *testing.T) {
	md := sampleReport(t).ToMarkdown()
	for _, want := range []string{
		"# Advisory parity report",
		"## Coverage summary",
		"## False negatives (misses)",
		"CVE-2024-9999", // the miss must be listed explicitly
		"## Empirical non-negotiables",
		"## Skipped comparators",
		ToolTrivy,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestComputeCoverageGain(t *testing.T) {
	baseline := []Finding{
		{Tool: ToolAnst, VulnID: "CVE-2024-1", Package: "p"},
		{Tool: ToolAnst, VulnID: "GHSA-aaaa", Aliases: []string{"CVE-2024-2"}, Package: "q"},
	}
	full := []Finding{
		// Same vuln as baseline #1 — not new.
		{Tool: ToolAnst, VulnID: "CVE-2024-1", Package: "p"},
		// Same vuln as baseline #2 by alias intersection — not new.
		{Tool: ToolAnst, VulnID: "CVE-2024-2", Package: "q"},
		// Genuinely new advisory the baseline did not carry.
		{Tool: ToolAnst, VulnID: "CVE-2024-9", Package: "r"},
	}
	g := ComputeCoverageGain("c", "go-vuln-db,osv", "go-vuln-db,osv,ghsa", baseline, full)
	if g.NewFindings != 1 {
		t.Fatalf("NewFindings = %d, want 1", g.NewFindings)
	}
	if len(g.NewIDs) != 1 || g.NewIDs[0] != "CVE-2024-9" {
		t.Fatalf("NewIDs = %v, want [CVE-2024-9]", g.NewIDs)
	}
	if g.BaselineCount != 2 || g.FullCount != 3 {
		t.Fatalf("counts = %d/%d, want 2/3", g.BaselineCount, g.FullCount)
	}
}

func TestComputeCoverageGainZeroWhenAggregated(t *testing.T) {
	// When the full set's extra source is already aggregated by the baseline
	// (every full finding matches a baseline finding), the measured gain is 0 —
	// a legitimate, reportable result, not an error.
	baseline := []Finding{{Tool: ToolAnst, VulnID: "CVE-1", Package: "p"}}
	full := []Finding{{Tool: ToolAnst, VulnID: "CVE-1", Package: "p"}}
	g := ComputeCoverageGain("c", "go-vuln-db,osv", "go-vuln-db,osv,ghsa", baseline, full)
	if g.NewFindings != 0 || len(g.NewIDs) != 0 {
		t.Fatalf("expected zero gain, got %d %v", g.NewFindings, g.NewIDs)
	}
}

func TestReportMarkdownRendersCoverageGain(t *testing.T) {
	r := &Report{
		GeneratedFrom: "test",
		CoverageGains: []CoverageGain{
			{Corpus: "go", BaselineSources: "go-vuln-db,osv", FullSources: "go-vuln-db,osv,ghsa", BaselineCount: 47, FullCount: 47, NewFindings: 0},
		},
	}
	md := r.ToMarkdown()
	if !strings.Contains(md, "## Coverage gain over the 2-source baseline") {
		t.Error("markdown missing coverage-gain section")
	}
}

func TestReportSortStable(t *testing.T) {
	r := &Report{
		Comparisons: []ComparisonResult{
			{Corpus: "z", Comparator: "grype"},
			{Corpus: "a", Comparator: "trivy"},
			{Corpus: "a", Comparator: "grype"},
		},
		Assertions: []Assertion{{Name: "b"}, {Name: "a"}},
	}
	r.Sort()
	if r.Comparisons[0].Corpus != "a" || r.Comparisons[0].Comparator != "grype" {
		t.Errorf("comparisons not sorted: %+v", r.Comparisons[0])
	}
	if r.Comparisons[2].Corpus != "z" {
		t.Errorf("comparisons not sorted: %+v", r.Comparisons[2])
	}
	if r.Assertions[0].Name != "a" {
		t.Errorf("assertions not sorted: %+v", r.Assertions)
	}
}
