package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"

	"github.com/commit0-dev/commit0-analyzer/internal/policy"
)

// TestIgnore_FutureExpiry_Suppresses verifies that an ignore entry whose ExpiresAt
// is in the future suppresses the matching finding from gate evaluation.
func TestIgnore_FutureExpiry_Suppresses(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/x/net",
		Reason:     "confirmed not reachable in prod",
		ExpiresAt:  time.Now().Add(48 * time.Hour),
	}
	require.NoError(t, entry.Validate())

	f := makeHighFinding() // GO-2024-0001 / golang.org/x/net
	assert.True(t, entry.Matches(f), "entry with future expiry must match finding")
	assert.False(t, entry.IsExpired(), "entry with future expiry must not be expired")
}

// TestIgnore_ExpiredEntry_DoesNotSuppress validates Red Team #15d fail-closed rule:
// an expired ignore MUST NOT suppress the finding (fails closed, not open).
func TestIgnore_ExpiredEntry_DoesNotSuppress(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/x/net",
		Reason:     "was confirmed safe — now expired",
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // one hour in the past
	}
	require.NoError(t, entry.Validate())

	f := makeHighFinding()
	// The entry structurally matches but is expired: must NOT suppress.
	assert.True(t, entry.Matches(f), "expired entry still structurally matches")
	assert.True(t, entry.IsExpired(), "entry must be expired")

	// Gate-level check: an expired ignore must not suppress the finding.
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
		Ignores:      []policy.IgnoreEntry{entry},
	}
	code := p.Evaluate([]*commit0v1.Finding{f})
	assert.Equal(t, policy.ExitGateFailure, code,
		"expired ignore must NOT suppress finding; gate must fail (Red Team #15d fail-closed)")
}

// TestIgnore_EmptyReason_Rejected validates that an ignore entry with an empty
// reason is rejected at validation time (mandatory non-empty reason).
func TestIgnore_EmptyReason_Rejected(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/x/net",
		Reason:     "", // empty — must be rejected
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	err := entry.Validate()
	require.Error(t, err, "ignore entry with empty reason must be rejected")
	assert.Contains(t, err.Error(), "reason", "error must mention the reason field")
}

// TestIgnore_WildcardAdvisoryID_Rejected validates that wildcard / glob patterns in
// AdvisoryID are rejected (exact tuple only, no wildcards per Red Team #15d).
func TestIgnore_WildcardAdvisoryID_Rejected(t *testing.T) {
	wildcards := []string{"GO-*", "CVE-*", "*", "GO-2024-*", "GO-2024-000?"}
	for _, wc := range wildcards {
		wc := wc
		t.Run(wc, func(t *testing.T) {
			entry := policy.IgnoreEntry{
				AdvisoryID: wc,
				Module:     "golang.org/x/net",
				Reason:     "valid reason",
				ExpiresAt:  time.Now().Add(24 * time.Hour),
			}
			err := entry.Validate()
			require.Error(t, err, "wildcard advisory ID %q must be rejected", wc)
			assert.Contains(t, err.Error(), "wildcard", "error must mention wildcard restriction")
		})
	}
}

// TestIgnore_WildcardModule_Rejected validates that wildcard patterns in Module
// are also rejected.
func TestIgnore_WildcardModule_Rejected(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/*",
		Reason:     "valid reason",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	err := entry.Validate()
	require.Error(t, err, "wildcard module must be rejected")
	assert.Contains(t, err.Error(), "wildcard")
}

// TestIgnore_SymbolReachableCritical_RequiresElevatedFlag validates Red Team #15d:
// ignoring a SYMBOL_REACHABLE CRITICAL finding requires the ElevatedIgnore flag.
func TestIgnore_SymbolReachableCritical_RequiresElevatedFlag(t *testing.T) {
	criticalFinding := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-CRIT"},
		Module:     "golang.org/x/net",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_CRITICAL,
		Path: &commit0v1.ReachabilityPath{
			Steps: []*commit0v1.CallStep{
				{Location: &commit0v1.Location{File: "cmd/main.go", Line: 1}, Symbol: "main.main"},
			},
		},
	}

	// Without elevated flag: must be rejected.
	entryNoFlag := policy.IgnoreEntry{
		AdvisoryID:    "GO-2024-CRIT",
		Module:        "golang.org/x/net",
		Reason:        "valid reason",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		ElevatedIgnore: false,
	}
	err := entryNoFlag.ValidateAgainstFinding(criticalFinding)
	require.Error(t, err, "ignoring SYMBOL_REACHABLE CRITICAL without elevated flag must be rejected")
	assert.Contains(t, err.Error(), "elevated")

	// With elevated flag: must be accepted.
	entryWithFlag := policy.IgnoreEntry{
		AdvisoryID:    "GO-2024-CRIT",
		Module:        "golang.org/x/net",
		Reason:        "valid reason with explicit acknowledgment",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		ElevatedIgnore: true,
	}
	err = entryWithFlag.ValidateAgainstFinding(criticalFinding)
	require.NoError(t, err, "ignoring SYMBOL_REACHABLE CRITICAL with elevated flag must be accepted")
}

// TestIgnore_ExactTupleMatching verifies that an ignore entry matches ONLY the
// exact (AdvisoryID, Module) tuple and does not accidentally suppress other findings.
func TestIgnore_ExactTupleMatching(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/x/net",
		Reason:     "confirmed safe",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	exactMatch := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Module:     "golang.org/x/net",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
	}
	differentAdvisory := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-9999"},
		Module:     "golang.org/x/net",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
	}
	differentModule := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Module:     "github.com/other/lib",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
	}

	assert.True(t, entry.Matches(exactMatch), "exact (advisoryID, module) must match")
	assert.False(t, entry.Matches(differentAdvisory), "different advisory ID must not match")
	assert.False(t, entry.Matches(differentModule), "different module must not match")
}

// TestIgnore_OptionalSymbol_NarrowerMatch verifies that when Symbol is set the entry
// only matches findings whose path contains that symbol.
func TestIgnore_OptionalSymbol_NarrowerMatch(t *testing.T) {
	entry := policy.IgnoreEntry{
		AdvisoryID: "GO-2024-0001",
		Module:     "golang.org/x/net",
		Symbol:     "golang.org/x/net/http2.(*Transport).RoundTrip",
		Reason:     "confirmed safe for this symbol",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	withMatchingSymbol := &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Module:   "golang.org/x/net",
		Path: &commit0v1.ReachabilityPath{
			Steps: []*commit0v1.CallStep{
				{Symbol: "golang.org/x/net/http2.(*Transport).RoundTrip"},
			},
		},
	}
	withOtherSymbol := &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Module:   "golang.org/x/net",
		Path: &commit0v1.ReachabilityPath{
			Steps: []*commit0v1.CallStep{
				{Symbol: "golang.org/x/net/http2.(*ClientConn).RoundTrip"},
			},
		},
	}
	noPath := &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{Id: "GO-2024-0001"},
		Module:   "golang.org/x/net",
	}

	assert.True(t, entry.Matches(withMatchingSymbol), "entry with symbol must match finding containing that symbol")
	assert.False(t, entry.Matches(withOtherSymbol), "entry with symbol must not match finding with different symbol")
	assert.False(t, entry.Matches(noPath), "entry with symbol must not match finding with no path")
}

// TestIgnore_LoadFromYAML verifies that ignore entries can be parsed from YAML and
// validated (error on empty reason, error on wildcard).
func TestIgnore_LoadFromYAML(t *testing.T) {
	yaml := []byte(`
fail-on: high
reachable-only: false
ignores:
  - advisory-id: "GO-2024-0001"
    module: "golang.org/x/net"
    reason: "confirmed safe in this context"
    expires-at: "2099-01-01"
  - advisory-id: "GO-2024-0002"
    module: "github.com/example/lib"
    reason: "scheduled remediation in sprint 42"
    expires-at: "2099-06-30"
`)
	p, err := policy.LoadPolicy(yaml)
	require.NoError(t, err)
	require.Len(t, p.Ignores, 2)

	assert.Equal(t, "GO-2024-0001", p.Ignores[0].AdvisoryID)
	assert.Equal(t, "golang.org/x/net", p.Ignores[0].Module)
	assert.NotEmpty(t, p.Ignores[0].Reason)
	assert.False(t, p.Ignores[0].IsExpired())

	assert.Equal(t, "GO-2024-0002", p.Ignores[1].AdvisoryID)
}

// TestIgnore_LoadFromYAML_EmptyReason_Error verifies that loading a policy with an
// ignore entry missing a reason returns an error.
func TestIgnore_LoadFromYAML_EmptyReason_Error(t *testing.T) {
	yaml := []byte(`
fail-on: high
ignores:
  - advisory-id: "GO-2024-0001"
    module: "golang.org/x/net"
    reason: ""
    expires-at: "2099-01-01"
`)
	_, err := policy.LoadPolicy(yaml)
	require.Error(t, err, "loading policy with empty reason must fail")
}

// TestIgnore_LoadFromYAML_Wildcard_Error verifies that loading a policy with a
// wildcard in advisory-id returns an error.
func TestIgnore_LoadFromYAML_Wildcard_Error(t *testing.T) {
	yaml := []byte(`
fail-on: high
ignores:
  - advisory-id: "GO-*"
    module: "golang.org/x/net"
    reason: "valid reason"
    expires-at: "2099-01-01"
`)
	_, err := policy.LoadPolicy(yaml)
	require.Error(t, err, "loading policy with wildcard advisory-id must fail")
}
