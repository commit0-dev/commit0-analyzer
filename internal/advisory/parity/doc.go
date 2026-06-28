// Package parity is the advisory-intelligence quality harness: it measures
// commit0-analyzer's advisory coverage against external scanners (osv-scanner,
// grype, trivy, govulncheck) on a fixed corpus of real repositories and records
// the false-positive / false-negative deltas with a reason for each.
//
// # Why this exists
//
// "Industry-level" means measured, not asserted. Code review is not delivery: a
// real scan→compare against established tools is the only honest way to claim
// coverage parity. This package produces a deterministic, machine-readable
// report so the docs only ever state numbers the harness actually measured.
//
// # The cardinal classification rule
//
// When a comparator flags a vulnerability that commit0-analyzer did not report, the harness
// must distinguish two very different cases:
//
//   - commit0-analyzer correctly suppressed it because the vulnerable dependency is provably
//     NOT_REACHABLE — a sound suppression, commit0-analyzer's differentiator, NOT a miss.
//   - commit0-analyzer has no record of it at all — a genuine false negative (a miss).
//
// A suppression counts as correct ONLY when commit0-analyzer carries the same advisory with
// a NOT_REACHABLE verdict. Anything else a comparator found and commit0-analyzer did not is a
// miss. Treating an unproven gap as a "correct suppression" would launder a false
// negative into a feature, which this harness forbids ([classifyAgainstCommit0]).
//
// # Hermetic split
//
// The pure comparison, classification, parsing, and report-rendering logic in
// this file set is fully unit-tested with fixtures and runs under the default
// `go test`. The live runner that shells out to commit0-analyzer and the external comparator
// binaries lives in runner.go behind the `parity` build tag, so the default test
// build stays hermetic (no network, no external binaries).
package parity
