package advisory

import (
	"strings"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// SourceGoVulnDB is the source attribution tag for the Go vulnerability database.
const SourceGoVulnDB = "go-vuln-db"

// Severity is the risk level of a vulnerability, derived from the CVSS base
// score or the textual severity in an OSV record's severity[] array.
// The integer values are ordered: Unspecified < Low < Medium < High < Critical.
type Severity int

const (
	// SeverityUnspecified is the zero value when no severity data is present.
	SeverityUnspecified Severity = iota
	// SeverityLow corresponds to CVSS base score 0.1–3.9.
	SeverityLow
	// SeverityMedium corresponds to CVSS base score 4.0–6.9.
	SeverityMedium
	// SeverityHigh corresponds to CVSS base score 7.0–8.9.
	SeverityHigh
	// SeverityCritical corresponds to CVSS base score 9.0–10.0.
	SeverityCritical
)

// cvssScoreToSeverity maps a CVSS v3/v4 numeric base score to the Severity
// enum following the standard CVSS severity bands:
//
//	0.0        → None     → SeverityUnspecified
//	0.1 – 3.9  → Low      → SeverityLow
//	4.0 – 6.9  → Medium   → SeverityMedium
//	7.0 – 8.9  → High     → SeverityHigh
//	9.0 – 10.0 → Critical → SeverityCritical
func cvssScoreToSeverity(score float64) Severity {
	switch {
	case score <= 0.0:
		return SeverityUnspecified
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

// CVSSMetric is a single parsed CVSS vector together with its computed base
// score. It is additive enrichment carried Go-side only — it never appears on
// the wire Advisory proto.
//
// BaseScore semantics by version:
//   - "3.0" / "3.1": the exact base score computed from the vector per the
//     official CVSS v3.x specification.
//   - "4.0": the vector is captured losslessly but BaseScore is 0 because the
//     exact v4.0 base-score math is deferred (see cvss.go). A zero BaseScore on a
//     v4.0 metric therefore means "not yet computed", and severityFromMetrics
//     deliberately does NOT downgrade severity from it — unknown ≠ safe.
type CVSSMetric struct {
	// Version is the CVSS version: "3.0", "3.1", or "4.0".
	Version string
	// Vector is the full CVSS vector string, captured losslessly.
	Vector string
	// BaseScore is the computed base score (see type doc for v4.0 caveat).
	BaseScore float64
	// Source attributes which feed supplied this metric (e.g. "nvd", "ghsa").
	// Empty when the producing source did not record an attribution.
	Source string
}

// EPSSScore is the FIRST Exploit Prediction Scoring System signal for a CVE.
// Filled by the EPSS enricher (later phase); nil when no EPSS data was fetched.
type EPSSScore struct {
	// Probability is the EPSS probability of exploitation in the next 30 days [0,1].
	Probability float64
	// Percentile is the EPSS percentile rank among all scored CVEs [0,1].
	Percentile float64
	// Date is the EPSS model date (YYYY-MM-DD) the score was published on.
	Date string
}

// KEVEntry is the CISA Known Exploited Vulnerabilities catalog signal for a CVE.
// Filled by the KEV enricher (later phase); nil when the CVE is not in the catalog
// OR the catalog could not be fetched — the distinction is carried by the scan's
// incomplete flag, never by silently treating a missing entry as "not exploited".
type KEVEntry struct {
	// Listed is true when the CVE appears in the KEV catalog.
	Listed bool
	// DateAdded is the catalog addition date (YYYY-MM-DD).
	DateAdded string
	// DueDate is the federal remediation due date (YYYY-MM-DD).
	DueDate string
	// KnownRansomware is true when CISA marks the entry as used in ransomware.
	KnownRansomware bool
}

// RiskScore is the fused, explainable risk-prioritization signal. Filled by the
// risk-fusion phase; nil until then.
type RiskScore struct {
	// Score is the numeric risk on a 0–100 scale.
	Score float64
	// Tier is the human-readable band (e.g. "critical", "high").
	Tier string
	// Rationale explains, deterministically, how the score was derived.
	Rationale string
}

// SourceContribution records what a single source contributed to a merged
// advisory so cross-source conflict resolution and provenance reporting can
// decide without re-querying the source.
type SourceContribution struct {
	// Name is the source name (e.g. "ghsa", "nvd", "go-vuln-db").
	Name string
	// Severity is the severity this source reported for the advisory.
	Severity Severity
	// Vector is the CVSS vector this source reported, if any.
	Vector string
	// FetchedAt is the RFC3339 time this source's data was fetched.
	FetchedAt string
	// SnapshotAge is a human-readable freshness string (e.g. "72h").
	SnapshotAge string
}

// Symbol is a vulnerable function or method within a package.
type Symbol struct {
	// Package is the fully-qualified Go import path (e.g. "crypto/tls").
	Package string
	// Name is the symbol name (e.g. "Conn.Read" or "ParseCert").
	Name string
}

// VersionRange represents a single semver range event pair.
// Both Introduced and Fixed are canonical semver strings (e.g. "v1.2.3").
// An empty Introduced means "since the beginning" (v0.0.0).
// An empty Fixed and empty LastAffected means "unfixed" (still vulnerable).
// At most one of Fixed and LastAffected is set per range.
type VersionRange struct {
	Introduced   string // inclusive lower bound; empty = v0.0.0
	Fixed        string // exclusive upper bound; empty = no fix yet
	LastAffected string // inclusive upper bound (OSV last_affected); empty = not used
}

// Advisory is the internal representation of a resolved vulnerability advisory.
//
// Provenance fields (SnapshotDigest, SnapshotAge, DBSourceVersion) are carried
// here so downstream components can stamp them into finding properties without
// coupling to cache internals. They do NOT appear on the wire Advisory proto.
type Advisory struct {
	// ID is the canonical advisory identifier (e.g. "GO-2024-0001").
	ID string
	// Ecosystem is the package ecosystem this advisory belongs to (e.g. "Go").
	// Set by the Source implementation that produced this advisory.
	Ecosystem string
	// Module is the affected Go module path.
	Module string
	// Aliases are alternative identifiers (CVE, GHSA IDs).
	Aliases []string
	// VersionRanges are the affected semver ranges.
	VersionRanges []VersionRange
	// Symbols are the specific vulnerable symbols (empty when SymbolLevel=false).
	Symbols []Symbol
	// SymbolLevel is true when at least one import entry carries symbol data.
	// When false, the analyzer must degrade to package-level confidence.
	SymbolLevel bool
	// Sources lists the advisory data sources (always includes SourceGoVulnDB for MVP).
	Sources []string

	// Withdrawn is the RFC3339 timestamp at which this advisory was retracted by
	// the Go vuln DB maintainers. A non-empty value means the advisory is no
	// longer considered a real vulnerability. Query filters these out before
	// returning results; this field is exposed so callers can inspect the
	// reason an advisory was excluded when needed (e.g. in debug logging).
	Withdrawn string

	// FixRefs holds the URLs from the OSV references[] array whose type is "FIX".
	// These point at the commits or patches that resolved the vulnerability and
	// are used by later pipeline phases to fetch and extract vulnerable symbols.
	// Sorted and deduplicated; empty slice when the record has no FIX references.
	// Not included in ToProto — consumed Go-side before the proto is built.
	FixRefs []string

	// Incomplete is set to true when the version comparison for this advisory was
	// undecidable (e.g. unparseable version string, unrecognised ecosystem). The
	// advisory is still included in query results so the host can emit a synthetic
	// UNKNOWN finding; dropping it would be a silent false negative.
	// Not part of the wire proto.
	Incomplete bool

	// Versions is the explicit version list from the OSV affected[].versions field.
	// It is populated when an affected entry has no SEMVER/ECOSYSTEM ranges — only
	// the versions enumeration. AffectsVersionV uses it for exact-membership matching
	// when VersionRanges is empty. When VersionRanges is non-empty, Versions is
	// ignored (the range comparison is authoritative).
	// Not part of the wire proto.
	Versions []string

	// UndecidableRanges is true when the OSV affected entry carried a non-version
	// (GIT-commit) range commit0-analyzer cannot compare AND no versions[] enumeration to fall
	// back on. AffectsVersionV returns VersionUndecidable in that case so the
	// advisory is forwarded as an UNKNOWN finding rather than silently dropped
	// (unknown != safe). It distinguishes a GIT-range-only entry (undecidable) from
	// a truly empty entry with no version constraint at all (not affected).
	// Not part of the wire proto.
	UndecidableRanges bool

	// Severity is the vulnerability risk level parsed from the OSV severity[]
	// array (CVSS v3/v4 base score) or database_specific.severity string.
	// SeverityUnspecified (zero value) means no severity data was present.
	// The host may use this to surface risk tiers in findings without touching
	// the wire proto (which is out of scope for this advisory layer).
	// Not part of the wire proto.
	Severity Severity

	// Provenance — not part of the wire proto; stamped into finding properties.
	SnapshotDigest  string // content digest of the snapshot this advisory came from
	SnapshotAge     string // human-readable age string (e.g. "72h")
	DBSourceVersion string // version string reported by the DB (e.g. "2024-06-01T00:00:00Z")

	// ── Enrichment (additive; Go-side only, never on the wire proto) ──────────
	// These are populated by enrichers and downstream phases. A nil/empty value
	// means "no signal fetched", which is NEVER interpreted as "safe": a fetch
	// failure is surfaced as incomplete by the enrichment chain.

	// CVSS holds every parsed CVSS metric for this advisory (possibly from
	// multiple sources / versions). Severity is derived from these via
	// severityFromMetrics when present.
	CVSS []CVSSMetric
	// EPSS is the exploit-prediction signal for this advisory's CVE; nil when none.
	EPSS *EPSSScore
	// KEV is the CISA known-exploited signal for this advisory's CVE; nil when none.
	KEV *KEVEntry
	// CWEs are the associated CWE identifiers (e.g. "CWE-79"); empty when none.
	CWEs []string
	// RiskScore is the fused risk-prioritization signal; nil until computed.
	RiskScore *RiskScore
	// SourceMeta records per-source contributions for conflict resolution and
	// provenance; empty until populated by the merge layer.
	SourceMeta []SourceContribution
}

// VersionVerdict is the tri-state result of a version range comparison.
//
// A parse error or unrecognised ecosystem always returns VersionUndecidable,
// never VersionNotAffected. This ensures that an unparseable or unrouted version
// does not silently drop an advisory host-side (which would be a false negative).
type VersionVerdict int

const (
	// VersionNotAffected means the version is provably outside every affected range.
	// This is the ONLY safe reason to drop an advisory.
	VersionNotAffected VersionVerdict = iota

	// VersionAffected means the version falls within at least one affected range.
	VersionAffected

	// VersionUndecidable means the comparison could not be completed — typically
	// due to an unparseable version string or an unrecognised ecosystem. The
	// advisory MUST still be forwarded and the dep MUST be marked incomplete=true.
	VersionUndecidable
)

// AffectsVersionV is the tri-state version of AffectsVersion.
//
// Routing is ecosystem-aware, delegating to the comparator registered for
// a.Ecosystem via [RegisterComparator]. The built-in registrations cover Go,
// npm, crates.io, and PyPI. New ecosystems register their comparator in their
// own file's init() without editing this function.
//
// When no comparator is registered for a.Ecosystem, or when a comparator
// returns VersionUndecidable, the caller must treat the advisory as "still
// possibly affected" and emit a synthetic UNKNOWN finding + set incomplete=true.
//
// A parse error in any comparator returns VersionUndecidable, never
// VersionNotAffected. This ensures that an unparseable or unrouted version
// does not silently drop an advisory host-side (which would be a false negative).
func (a *Advisory) AffectsVersionV(version string) VersionVerdict {
	if len(a.VersionRanges) == 0 {
		// No ranges to check. Fall through to versions-list matching if available.
		if len(a.Versions) == 0 {
			if a.UndecidableRanges {
				// A non-version (GIT-commit) range was present but there is no
				// versions[] enumeration to evaluate it against — genuinely
				// undecidable. Forward as UNKNOWN rather than dropping (unknown != safe).
				return VersionUndecidable
			}
			// No version constraint at all (no ranges and no versions): the advisory
			// cannot identify any affected version, so matching it name-only would
			// fire on every version. Treat it as not affected, matching osv-scanner's
			// handling of such degenerate records.
			return VersionNotAffected
		}
		// Versions-only entry: match against the explicit enumeration.
		// The queried version may carry a "v" prefix from canonical(); strip it for
		// comparison because OSV versions[] entries never carry a "v" prefix.
		bare := strings.TrimPrefix(version, "v")
		for _, v := range a.Versions {
			if v == bare {
				return VersionAffected
			}
		}
		return VersionNotAffected
	}

	// Look up the ecosystem-specific comparator. An unregistered ecosystem is
	// undecidable for every range — never silently not-affected.
	cmp := lookupComparator(a.Ecosystem)
	if cmp == nil {
		return VersionUndecidable
	}

	hasUndecidable := false
	for _, r := range a.VersionRanges {
		switch v := cmp(version, r); v {
		case VersionAffected:
			return VersionAffected
		case VersionUndecidable:
			hasUndecidable = true
		}
	}
	if hasUndecidable {
		return VersionUndecidable
	}
	return VersionNotAffected
}

// AffectsVersion reports whether the advisory affects the given version.
//
// Routing is ecosystem-aware:
//   - npm: uses node-semver semantics via npmVersionInRange (bare versions, no "v"
//     prefix required, correct prerelease and 4-part-version handling).
//   - All other ecosystems (Go, etc.): uses the existing Go semver path via
//     versionInRange, which requires a canonical "vX.Y.Z" string.
//
// Returns false on any parse error (conservative: unknown → not matched).
//
// Deprecated: prefer AffectsVersionV, which returns a tri-state verdict so that
// parse errors and unknown ecosystems are never silently treated as not-affected.
func (a *Advisory) AffectsVersion(version string) bool {
	for _, r := range a.VersionRanges {
		var matched bool
		if a.Ecosystem == EcosystemNPM {
			matched = npmVersionInRange(version, r)
		} else {
			matched = versionInRange(version, r)
		}
		if matched {
			return true
		}
	}
	return false
}

// ToProto converts the internal Advisory into the wire *commit0v1.Advisory type
// ready to embed in an AnalyzeRequest. Provenance fields are NOT included here;
// callers stamp them into Finding.properties separately.
func (a *Advisory) ToProto() *commit0v1.Advisory {
	proto := &commit0v1.Advisory{
		Id:          a.ID,
		Module:      a.Module,
		SymbolLevel: a.SymbolLevel,
		Sources:     append([]string(nil), a.Sources...),
	}

	// Aggregate the affected version ranges into a single string representation.
	// For MVP, encode as a semicolon-separated list of range expressions.
	if len(a.VersionRanges) > 0 {
		proto.VersionRange = formatVersionRanges(a.VersionRanges)
	}

	// Convert symbols.
	for _, s := range a.Symbols {
		proto.Symbols = append(proto.Symbols, &commit0v1.Symbol{
			Package: s.Package,
			Name:    s.Name,
		})
	}

	return proto
}

// formatVersionRanges converts the internal VersionRange slice to a human-
// readable string for the wire Advisory.version_range field.
// Format: "[introduced,fixed)" per range, semicolon-separated.
func formatVersionRanges(ranges []VersionRange) string {
	if len(ranges) == 0 {
		return ""
	}
	var out string
	for i, r := range ranges {
		if i > 0 {
			out += "; "
		}
		introduced := r.Introduced
		if introduced == "" {
			introduced = "0"
		}
		switch {
		case r.Fixed != "":
			out += "[" + introduced + "," + r.Fixed + ")"
		case r.LastAffected != "":
			out += "[" + introduced + "," + r.LastAffected + "]"
		default:
			out += ">=" + introduced
		}
	}
	return out
}
