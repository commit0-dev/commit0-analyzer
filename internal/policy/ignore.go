package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// IgnoreEntry suppresses a specific finding from gate evaluation.
//
// Constraints (Red Team #15d):
//   - AdvisoryID and Module must be exact strings — no wildcards, no globs.
//   - Reason must be non-empty (mandatory justification).
//   - ExpiresAt must be set to a bounded future date; an expired entry fails closed
//     (does NOT suppress the finding).
//   - Ignoring a SYMBOL_REACHABLE CRITICAL finding requires ElevatedIgnore = true.
//   - Ignored findings are always rendered into SARIF as suppressed (not absent).
type IgnoreEntry struct {
	// AdvisoryID is the exact advisory identifier (e.g. "GO-2024-0001", "CVE-2024-12345").
	// Wildcards and glob patterns are forbidden.
	AdvisoryID string `yaml:"advisory-id"`
	// Module is the exact Go module path (e.g. "golang.org/x/net").
	// Wildcards are forbidden.
	Module string `yaml:"module"`
	// Symbol is an optional exact symbol name. When set, the entry only matches
	// findings whose ReachabilityPath contains this symbol.
	Symbol string `yaml:"symbol,omitempty"`
	// Reason is a mandatory human-readable justification for the suppression.
	Reason string `yaml:"reason"`
	// ExpiresAt is the date after which this ignore entry no longer applies.
	// An expired entry fails closed: the finding is NOT suppressed.
	ExpiresAt time.Time `yaml:"expires-at"`
	// ElevatedIgnore must be true to suppress a SYMBOL_REACHABLE CRITICAL finding.
	// This is a deliberate speed-bump to prevent accidental broad suppression.
	ElevatedIgnore bool `yaml:"elevated-ignore,omitempty"`
}

// wildcardChars contains characters that indicate a glob or wildcard pattern.
var wildcardChars = []string{"*", "?", "[", "]", "{", "}"}

// containsWildcard reports whether s contains any wildcard character.
func containsWildcard(s string) bool {
	for _, ch := range wildcardChars {
		if strings.Contains(s, ch) {
			return true
		}
	}
	return false
}

// Validate checks that the IgnoreEntry is structurally valid:
//   - Reason is non-empty.
//   - AdvisoryID and Module contain no wildcard characters.
//
// It does NOT validate ElevatedIgnore against a specific finding's confidence/severity;
// use ValidateAgainstFinding for that.
func (e IgnoreEntry) Validate() error {
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("ignore entry for %q / %q: reason must be non-empty (mandatory justification required)",
			e.AdvisoryID, e.Module)
	}
	if containsWildcard(e.AdvisoryID) {
		return fmt.Errorf("ignore entry advisory-id %q contains a wildcard character; only exact IDs are permitted (Red Team #15d)",
			e.AdvisoryID)
	}
	if containsWildcard(e.Module) {
		return fmt.Errorf("ignore entry module %q contains a wildcard character; only exact module paths are permitted (Red Team #15d)",
			e.Module)
	}
	return nil
}

// ValidateAgainstFinding checks the additional constraint that ignoring a
// SYMBOL_REACHABLE CRITICAL finding requires the ElevatedIgnore flag.
// Call this after Validate() when you have a concrete finding to check against.
func (e IgnoreEntry) ValidateAgainstFinding(f *commit0v1.Finding) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if f.GetConfidence() == commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE &&
		f.GetSeverity() == commit0v1.Severity_SEVERITY_CRITICAL {
		if !e.ElevatedIgnore {
			return fmt.Errorf(
				"ignore entry for %q / %q: ignoring a SYMBOL_REACHABLE CRITICAL finding requires elevated-ignore: true (Red Team #15d)",
				e.AdvisoryID, e.Module)
		}
	}
	return nil
}

// IsExpired reports whether this ignore entry has passed its expiry date.
// An expired entry fails closed: it does NOT suppress findings.
func (e IgnoreEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		// No expiry set — treat as already expired (fail closed).
		return true
	}
	return time.Now().After(e.ExpiresAt)
}

// Matches reports whether this entry applies to the given finding.
// It checks the exact (AdvisoryID, Module) tuple and, when Symbol is set,
// whether any step in the finding's ReachabilityPath carries that symbol.
//
// Matches does NOT check expiry; callers must call IsExpired separately.
func (e IgnoreEntry) Matches(f *commit0v1.Finding) bool {
	if f.GetAdvisory().GetId() != e.AdvisoryID {
		return false
	}
	if f.GetModule() != e.Module {
		return false
	}
	if e.Symbol == "" {
		return true
	}
	// Symbol is set: check whether any step in the path matches.
	if f.GetPath() == nil {
		return false
	}
	for _, step := range f.GetPath().GetSteps() {
		if step.GetSymbol() == e.Symbol {
			return true
		}
	}
	return false
}

// isActiveIgnore reports whether e is valid, non-expired, and matches f.
// This is the single gating predicate used by the policy engine.
//
// Elevated-ignore guard (Red Team #15d): if the entry matches but the finding is
// SYMBOL_REACHABLE + CRITICAL and ElevatedIgnore is not set, the entry is treated
// as inactive (fail-closed). A warning is printed to stderr so the user knows their
// ignore was refused rather than silently accepted.
func isActiveIgnore(e IgnoreEntry, f *commit0v1.Finding) bool {
	if e.IsExpired() {
		return false
	}
	if !e.Matches(f) {
		return false
	}
	// Guard: a proven-reachable CRITICAL finding must not be silently suppressed
	// without an explicit acknowledgment. ValidateAgainstFinding enforces this
	// invariant; treat a failed validation as "not active" (fail-closed).
	if err := e.ValidateAgainstFinding(f); err != nil {
		fmt.Fprintf(os.Stderr,
			"commit0-analyzer: ignore refused for %q / %q — %v (finding NOT suppressed)\n",
			e.AdvisoryID, e.Module, err)
		return false
	}
	return true
}
