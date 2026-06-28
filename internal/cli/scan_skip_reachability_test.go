package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/vex"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestPackageLevelFinding verifies the shape of the findings emitted by the
// --skip-reachability-analysis path. The cardinal rule is that skipping
// reachability NEVER narrows: the confidence must be CONFIDENCE_UNKNOWN (never
// NOT_REACHABLE), so the gate cannot read a real advisory match as a clean pass
// and a VEX statement can never become not_affected.
func TestPackageLevelFinding(t *testing.T) {
	adv := &advisory.Advisory{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Aliases: []string{"CVE-2024-0001"},
	}

	f := packageLevelFinding(adv, "github.com/example/pkg", "go")

	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence(),
		"skip-reachability findings must be UNKNOWN, never NOT_REACHABLE")
	assert.Equal(t, "github.com/example/pkg", f.GetModule())
	assert.Equal(t, "go", f.GetLanguage())
	assert.Equal(t, "sca", f.GetPillar())
	assert.Equal(t, "GHSA-xxxx-yyyy-zzzz", f.GetAdvisory().GetId())
	assert.Equal(t, []string{"CVE-2024-0001"}, f.GetAdvisory().GetAliases())
	assert.False(t, f.GetIncomplete(), "a decidable advisory match is not per-finding incomplete")

	// An UNKNOWN finding maps to ReachabilityUnknown (→ VEX under_investigation),
	// never to the NOT_REACHABLE mapping that would yield not_affected.
	assert.Equal(t, vex.ReachabilityUnknown, vexReachability(f.GetConfidence()))
	assert.NotEqual(t, vex.ReachabilityNotReachable, vexReachability(f.GetConfidence()))
}

// TestPackageLevelFinding_undecidableMirrorsIncomplete confirms the per-finding
// Incomplete flag tracks the advisory's own undecidability (e.g. an unparseable
// version), independent of the scan-level reachability-skipped signal.
func TestPackageLevelFinding_undecidableMirrorsIncomplete(t *testing.T) {
	adv := &advisory.Advisory{ID: "OSV-1", Incomplete: true}
	f := packageLevelFinding(adv, "left-pad", "js")
	assert.True(t, f.GetIncomplete())
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence())
}
