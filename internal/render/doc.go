// Package render converts normalized findings into output formats.
//
// # Supported Formats (MVP)
//
//   - SARIF 2.1.0 ([ToSARIF]): GitHub code scanning compatible. Each Finding
//     lowers to a SARIF result + optional codeFlows. Findings without a
//     ReachabilityPath MUST omit codeFlows entirely — an empty codeFlows array
//     is schema-invalid and causes GitHub to reject the whole upload (Red Team #9).
//
//   - JSON ([ToJSON]): structured machine-readable output with stable schema and
//     deterministic key/sort order across calls.
//
//   - Table ([ToTable]): TTY-friendly human-readable output sorted by severity.
//
// # SARIF codeFlows Rule (Red Team #9)
//
// codeFlows is emitted ONLY when a Finding has at least one CallStep in its
// ReachabilityPath. Path-less findings (PACKAGE_REACHABLE, UNKNOWN,
// NOT_REACHABLE) omit codeFlows and carry evidence in result.properties and
// result.message instead. A mixed document containing all four confidence tiers
// remains schema-valid because path-less results simply lack the optional
// codeFlows field.
//
// # Severity Mapping to SARIF result.level
//
//   - CRITICAL / HIGH  → "error"
//   - MEDIUM           → "warning"
//   - LOW              → "note"
//   - UNSPECIFIED      → "none"
//
// # NOT_REACHABLE Representation
//
// NOT_REACHABLE findings are never silently absent. They are rendered as
// suppressed SARIF results (suppressions[0].kind = "external") with a
// justification, so they remain auditable in GitHub code scanning. The level
// is overridden to "note" so suppressed results do not block CI even if a
// viewer ignores the suppression field.
//
// # Determinism
//
// All renderers sort findings by advisory ID before emitting output. JSON map
// keys are stable via encoding/json struct field ordering. Two calls with
// identical input always produce byte-identical output.
//
// # Regenerating Golden Files
//
// Run tests with -update to regenerate the golden files under testdata/:
//
//	go test ./internal/render/... -update
package render
