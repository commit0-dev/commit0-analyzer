// Package contract provides the versioned gRPC plugin contract for anst-analyzer.
//
// It re-exports the generated protobuf types from the anstv1 sub-package and
// adds Go-level helpers that encode the project's core safety invariants:
//
//   - Version compatibility: [Compatible] enforces the host/plugin handshake rule
//     (same major, host minor >= plugin minor).
//   - Suppression guard: [FindingWrapper.IsSuppressible] returns false for
//     CONFIDENCE_UNKNOWN, preventing silent suppression of unresolved findings.
//
// The generated types live in [github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1].
// Callers that need the raw proto types import that sub-package directly; callers
// that need the safety helpers use this package.
package contract
