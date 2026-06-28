// Package advisory resolves vulnerability advisories for the commit0-analyzer scan target.
//
// # MVP Scope: Go Vulnerability Database Only
//
// The only advisory source in the MVP is the Go vulnerability database
// (https://vuln.go.dev). It is the only public source that reliably carries
// symbol-level data (specific vulnerable functions/methods), which is required
// for CONFIDENCE_SYMBOL_REACHABLE findings.
//
// Multi-source advisory resolution (OSV.dev, GHSA) is a roadmap item deferred
// from the MVP. Those sources are package-level only; adding them increases CVE
// coverage but does not improve symbol precision. The [Source] interface in
// source.go is the seam through which future sources will plug in.
//
// # Responsibilities
//
//   - Parse OSV-format JSON records from the Go vuln DB into internal [Advisory]
//     values with correct [Advisory.SymbolLevel] classification.
//   - Match a module@version against affected version ranges (SEMVER, half-open
//     [introduced, fixed) intervals).
//   - Cache advisory data on disk with atomic writes (temp→fsync→rename) and
//     cross-process file locking to prevent torn reads under concurrent access.
//   - Pin and verify snapshots by content digest; hard-error on digest mismatch
//     (a mutable snapshot defeats reproducible CI).
//   - Warn loudly — via [StalenessWarningError] — when the snapshot is older
//     than a configurable threshold. The warning is surfaced, never silently
//     swallowed, because unknown ≠ safe at the data boundary.
//   - Convert internal [Advisory] values to *commit0v1.Advisory for embedding in
//     an AnalyzeRequest; provenance fields (digest, age) go into finding
//     properties, not the wire Advisory.
//
// # Data Boundary Invariant
//
// "unknown ≠ safe": a failed or stale advisory lookup must never be treated as
// "no vulnerabilities found". Callers must propagate errors and warnings and
// degrade to CONFIDENCE_UNKNOWN rather than suppressing findings.
//
// # Advisory Distribution
//
// This package NEVER bundles or redistributes Go vuln DB content. Offline mode
// consumes the user's own pre-fetched snapshot (sidesteps licensing concerns).
// The network-fetch path (not yet implemented; roadmap) will write to the cache
// directory using [atomicWrite] to keep the fetch and offline paths consistent.
package advisory
