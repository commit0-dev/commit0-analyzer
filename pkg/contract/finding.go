package contract

import (
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// FindingWrapper wraps a proto Finding with Go-level safety helpers.
// Obtain one via [WrapFinding].
type FindingWrapper struct {
	f *commit0v1.Finding
}

// WrapFinding returns a FindingWrapper for f.
// f must not be nil; passing nil will panic on any method call.
func WrapFinding(f *commit0v1.Finding) FindingWrapper {
	return FindingWrapper{f: f}
}

// Finding returns the underlying proto Finding.
func (w FindingWrapper) Finding() *commit0v1.Finding {
	return w.f
}

// IsSuppressible reports whether this finding may be silently suppressed by a
// policy gate.
//
// The invariant "unknown ≠ safe" is encoded here:
//   - CONFIDENCE_UNKNOWN → false  (must surface; reachability is unresolved)
//   - CONFIDENCE_SYMBOL_REACHABLE → false  (definitely reachable; must surface)
//   - CONFIDENCE_PACKAGE_REACHABLE → false  (reachable at package level; must surface)
//   - CONFIDENCE_NOT_REACHABLE → true  (only tier a policy gate may suppress)
//
// No downstream component should check Confidence directly for suppression
// purposes; always call IsSuppressible() so this invariant is enforced in one
// place.
func (w FindingWrapper) IsSuppressible() bool {
	return w.f.Confidence == commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE
}
