package advisory

import (
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// SourceGoVulnDB is the source attribution tag for the Go vulnerability database.
const SourceGoVulnDB = "go-vuln-db"

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

	// Provenance — not part of the wire proto; stamped into finding properties.
	SnapshotDigest  string // content digest of the snapshot this advisory came from
	SnapshotAge     string // human-readable age string (e.g. "72h")
	DBSourceVersion string // version string reported by the DB (e.g. "2024-06-01T00:00:00Z")
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
