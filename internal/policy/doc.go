// Package policy implements the policy-as-code gate for anst-analyzer.
//
// # Exit Code Contract
//
// The gate produces one of three exit codes (Red Team #8):
//
//   - 0 ([ExitPass]): all findings are within policy thresholds and the scan
//     completed without errors.
//   - 1 ([ExitGateFailure]): one or more gate-eligible findings exceed the
//     configured severity threshold.
//   - 3 ([ExitOperationalError]): the scan was incomplete, crashed, or an
//     unrecoverable host error occurred. Never exits 0 on partial results.
//
// Code 2 is intentionally absent: it is reserved by Go's runtime for panic exits
// and is used by govulncheck, making it ambiguous. Always use 3 for operational errors.
//
// Use [RunWithRecovery] to wrap the top-level scan function so that panics are
// caught and mapped to code 3 rather than crashing with Go's exit code 2.
//
// # Gating Tiers (Red Team #15c)
//
// Under reachable-only mode, gate-eligible tiers are:
//   - SYMBOL_REACHABLE: confirmed call-graph path exists.
//   - PACKAGE_REACHABLE: package is imported and reachable, symbol unknown.
//   - UNKNOWN: reachability could not be determined (unknown ≠ safe).
//
// Only CONFIDENCE_NOT_REACHABLE findings are excludable under reachable-only.
// All other tiers are surfaced and counted.
//
// # Ignore List (Red Team #15d)
//
// Ignore entries are exact (AdvisoryID, Module[, Symbol]) tuples. They must have:
//   - A non-empty Reason (mandatory justification).
//   - A bounded ExpiresAt date. Expired entries fail closed: they do NOT suppress.
//   - No wildcards or globs in any field.
//   - ElevatedIgnore = true when suppressing a SYMBOL_REACHABLE CRITICAL finding.
//
// Ignored findings are always rendered into SARIF as suppressed results (not absent)
// so they remain auditable in GitHub code scanning.
package policy
