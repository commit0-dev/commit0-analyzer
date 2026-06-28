package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestStampProvenance verifies that the cross-source audit trail is stamped onto
// findings: provenance is recorded whenever the matched advisory carries source
// metadata, while severity_conflict and stale_source appear only when a real
// disagreement or stale source exists. Findings with no advisory, no matched
// advisory, or no source metadata are left untouched.
func TestStampProvenance(t *testing.T) {
	advByID := map[string]*advisory.Advisory{
		// Two sources disagree on severity and are both stale (age > soft SLA).
		"GO-2024-0001": {
			ID: "GO-2024-0001",
			SourceMeta: []advisory.SourceContribution{
				{Name: "ghsa", Severity: advisory.SeverityHigh, SnapshotAge: "100h"},
				{Name: "osv.dev", Severity: advisory.SeverityMedium, SnapshotAge: "100h"},
			},
		},
		// Single recent source: provenance only, no conflict, not stale.
		"GO-2024-0002": {
			ID: "GO-2024-0002",
			SourceMeta: []advisory.SourceContribution{
				{Name: "osv.dev", Severity: advisory.SeverityHigh, SnapshotAge: "1h"},
			},
		},
		// No source metadata: nothing to surface.
		"GO-2024-0003": {ID: "GO-2024-0003"},
	}

	conflicted := &commit0v1.Finding{Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0001"}}
	clean := &commit0v1.Finding{Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0002"}}
	noMeta := &commit0v1.Finding{Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0003"}}
	unmatched := &commit0v1.Finding{Advisory: &commit0v1.AdvisoryRef{Id: "GO-9999-9999"}}
	noAdvisory := &commit0v1.Finding{Module: "synthetic-plugin-error"}

	stampProvenance([]*commit0v1.Finding{conflicted, clean, noMeta, unmatched, noAdvisory}, advByID)

	cp := conflicted.GetProperties()
	assert.Equal(t, "ghsa HIGH; osv.dev MEDIUM", cp["provenance"],
		"provenance must list every contributing source deterministically (no wall-clock age)")
	assert.Equal(t, "ghsa:HIGH,osv.dev:MEDIUM", cp["severity_conflict"],
		"a real severity disagreement must be surfaced")
	assert.Equal(t, "ghsa,osv.dev", cp["stale_source"],
		"sources past the soft freshness SLA must be flagged stale")

	clp := clean.GetProperties()
	assert.Equal(t, "osv.dev HIGH", clp["provenance"])
	_, hasConflict := clp["severity_conflict"]
	assert.False(t, hasConflict, "no conflict when a single source agrees with itself")
	_, hasStale := clp["stale_source"]
	assert.False(t, hasStale, "a recent source must not be flagged stale")

	assert.Nil(t, noMeta.GetProperties(),
		"advisory with no source metadata must leave the finding untouched")
	assert.Nil(t, unmatched.GetProperties(),
		"unmatched advisory ID must leave the finding untouched")
	assert.Nil(t, noAdvisory.GetProperties(),
		"synthetic finding with no advisory must be left untouched")
}

// TestStampSources verifies that advisory source attribution is propagated onto
// findings' properties["sources"], that synthetic findings (no advisory) are
// skipped, and that an unmapped advisory ID leaves the finding untouched.
func TestStampSources(t *testing.T) {
	sourcesByID := map[string][]string{
		"GO-2024-0001": {"go-vuln-db", "osv.dev"},
		"GO-2024-0002": {"osv.dev"},
	}

	findings := []*commit0v1.Finding{
		{Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0001"}},                                                 // both sources
		{Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0002"}, Properties: map[string]string{"goos": "linux"}}, // existing props preserved
		{Advisory: &commit0v1.AdvisoryRef{Id: "GO-9999-9999"}},                                                 // unmapped → untouched
		{Module: "synthetic-plugin-error"},                                                                  // nil advisory → skipped
	}

	stampSources(findings, sourcesByID)

	assert.Equal(t, "go-vuln-db,osv.dev", findings[0].GetProperties()["sources"],
		"merged multi-source attribution must be stamped")

	assert.Equal(t, "osv.dev", findings[1].GetProperties()["sources"])
	assert.Equal(t, "linux", findings[1].GetProperties()["goos"],
		"existing properties must be preserved")

	_, ok := findings[2].GetProperties()["sources"]
	assert.False(t, ok, "unmapped advisory ID must not get a sources property")

	assert.Nil(t, findings[3].GetProperties(),
		"synthetic finding with no advisory must be left untouched (no panic, no props)")
}

// TestStampRisk verifies that the fused risk score and underlying signals are
// stamped onto findings from the matched advisory, that a NOT_REACHABLE finding
// scores 0, and that findings with no matched advisory are skipped.
func TestStampRisk(t *testing.T) {
	advByID := map[string]*advisory.Advisory{
		"GO-2024-0001": {
			ID:   "GO-2024-0001",
			CVSS: []advisory.CVSSMetric{{Version: "3.1", BaseScore: 7.5, Vector: "CVSS:3.1/x"}},
			KEV:  &advisory.KEVEntry{Listed: true},
			EPSS: &advisory.EPSSScore{Probability: 0.9},
			CWEs: []string{"CWE-79"},
		},
		"GO-2024-0002": {ID: "GO-2024-0002"},
	}

	reachable := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
	}
	notReachable := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0002"},
		Confidence: commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
	}
	noAdvisory := &commit0v1.Finding{Module: "synthetic-plugin-error"}

	stampRisk([]*commit0v1.Finding{reachable, notReachable, noAdvisory}, advByID)

	// Reachable + KEV → critical tier, signals surfaced.
	rp := reachable.GetProperties()
	assert.Equal(t, "critical", rp["risk_tier"], "KEV-listed reachable finding must be critical tier")
	assert.Equal(t, "true", rp["kev"])
	assert.Equal(t, "7.5", rp["cvss"])
	assert.Equal(t, "0.9", rp["epss"])
	assert.Equal(t, "CWE-79", rp["cwe"])
	assert.NotEmpty(t, rp["risk_score"])
	assert.NotEmpty(t, rp["risk_rationale"])

	// NOT_REACHABLE → score 0, tier none.
	np := notReachable.GetProperties()
	assert.Equal(t, "0.0", np["risk_score"], "NOT_REACHABLE must score 0")
	assert.Equal(t, "none", np["risk_tier"])

	// No matched advisory → untouched.
	assert.Nil(t, noAdvisory.GetProperties(),
		"finding with no matched advisory must be left untouched")
}
