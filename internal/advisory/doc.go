// Package advisory resolves vulnerability advisories for the commit0-analyzer scan target.
//
// # Advisory Sources
//
// Advisories are fetched from multiple sources and merged:
//
//   - Go vulnerability database (https://vuln.go.dev) — the only public source
//     that reliably carries symbol-level data (specific vulnerable
//     functions/methods), which is required for CONFIDENCE_SYMBOL_REACHABLE
//     findings (govulndb.go, fetcher.go).
//   - OSV.dev per-ecosystem bundles for all supported ecosystems (osv.go).
//   - GitHub Security Advisories — offline OSV bundle as the breadth floor,
//     plus the live GraphQL API when GITHUB_TOKEN is set (ghsa_source.go).
//   - GitLab advisory database — the MIT-licensed community mirror by default
//     (gitlab_source.go).
//   - NVD — opt-in CPE-based breadth matching, always package-level (nvd.go).
//
// Sources plug in through the [Source] interface (source.go) and are composed
// by MultiSource (merge.go): advisories are grouped by alias equivalence and
// folded fail-safe (max severity, union of ranges and sources; Withdrawn only
// when unanimous). An [EnrichmentChain] then layers on CVSS score computation,
// NVD CVSS/CWE authority, CISA KEV listing, EPSS probability, and CWE
// normalization, and risk.go fuses advisory data with the reachability tier
// into a deterministic 0–100 risk score.
//
// # Version Matching
//
// Each ecosystem registers a tri-state version comparator
// (comparator_registry.go): a version is Affected, NotAffected, or
// Undecidable. An unparseable version or unregistered ecosystem is
// Undecidable — never NotAffected — and the advisory is forwarded with
// Incomplete set. Only NotAffected may drop an advisory.
//
// # Responsibilities
//
//   - Parse OSV-format JSON (and GitLab YAML) records into internal [Advisory]
//     values with correct [Advisory.SymbolLevel] classification.
//   - Match a package@version against affected ranges via the per-ecosystem
//     comparators (SEMVER half-open [introduced, fixed) intervals and exact
//     version lists).
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
// This package NEVER bundles or redistributes advisory database content.
// Offline mode consumes the user's own pre-fetched snapshot (sidesteps
// licensing concerns). The network-fetch path writes to the cache directory
// using [atomicWrite] to keep the fetch and offline paths consistent.
package advisory
