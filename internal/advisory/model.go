package advisory

import (
	"strings"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
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
// Routing is ecosystem-aware:
//   - npm: uses node-semver semantics via npmVersionInRangeV.
//   - Go: uses the Go-semver path via versionInRangeV (requires "v"-prefixed canonical form).
//   - crates.io: uses Cargo SemVer semantics via cargoVersionInRangeV. Cargo versions
//     never carry a "v" prefix, so the leading "v" added by canonical() is stripped here.
//   - PyPI: uses PEP 440 semantics via pep440VersionInRangeV.
//   - Unknown/unimplemented ecosystem: returns VersionUndecidable.
//
// A parse error in any comparator returns VersionUndecidable, never
// VersionNotAffected. The caller must treat Undecidable as "still possibly
// affected" and emit a synthetic UNKNOWN finding + set incomplete=true.
func (a *Advisory) AffectsVersionV(version string) VersionVerdict {
	if len(a.VersionRanges) == 0 {
		// No ranges to check. Fall through to versions-list matching if available.
		if len(a.Versions) == 0 {
			// Neither ranges nor a versions list — genuinely undecidable.
			return VersionUndecidable
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

	hasUndecidable := false
	for _, r := range a.VersionRanges {
		var v VersionVerdict
		switch a.Ecosystem {
		case EcosystemNPM:
			v = npmVersionInRangeV(version, r)
		case EcosystemGo:
			// Go semver requires the "v"-prefixed canonical form.
			v = versionInRangeV(version, r)
		case EcosystemCratesIO:
			// Cargo versions never carry a "v" prefix. The call path (lookup /
			// dirSource.query) applies canonical() before calling AffectsVersionV,
			// which adds a leading "v". Strip it here so cargoVersionInRangeV
			// receives the bare form it expects (e.g. "1.2.3" not "v1.2.3").
			cargoVer := strings.TrimPrefix(version, "v")
			v = cargoVersionInRangeV(cargoVer, r)
		case EcosystemPyPI:
			// PyPI uses PEP 440 semantics (ECOSYSTEM type in OSV, not SEMVER).
			v = pep440VersionInRangeV(version, r)
		default:
			// Unknown ecosystem: cannot compare → undecidable for every range.
			return VersionUndecidable
		}
		switch v {
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

// ToProto converts the internal Advisory into the wire *anstv1.Advisory type
// ready to embed in an AnalyzeRequest. Provenance fields are NOT included here;
// callers stamp them into Finding.properties separately.
func (a *Advisory) ToProto() *anstv1.Advisory {
	proto := &anstv1.Advisory{
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
		proto.Symbols = append(proto.Symbols, &anstv1.Symbol{
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
