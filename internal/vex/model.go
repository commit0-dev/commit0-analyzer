package vex

import (
	"sort"
	"strings"
	"time"
)

// Author is the VEX document author/publisher commit0-analyzer stamps into every document.
const Author = "commit0-analyzer"

// Status is a VEX exploitability status. The string values are the OpenVEX
// vocabulary; the CycloneDX and CSAF formatters translate them to their own
// vocabularies.
type Status string

const (
	// StatusNotAffected means the vulnerable code is provably not reachable.
	// Only a complete NOT_REACHABLE analysis may produce this status.
	StatusNotAffected Status = "not_affected"
	// StatusAffected means the vulnerable code is reachable (package or symbol).
	StatusAffected Status = "affected"
	// StatusUnderInvestigation means reachability is unknown or analysis was
	// incomplete. This is the conservative status for anything commit0-analyzer could not
	// prove safe — it is NEVER not_affected.
	StatusUnderInvestigation Status = "under_investigation"
	// StatusFixed means the product ships a fixed version. commit0-analyzer does not emit it
	// today (it reports reachability, not remediation state) but the model carries
	// it so the formatters cover the full vocabulary.
	StatusFixed Status = "fixed"
)

// Justification is the machine-readable reason a not_affected status holds.
type Justification string

const (
	// JustificationVulnerableCodeNotInExecutePath is the only justification commit0-analyzer
	// emits: the vulnerable symbol/package is not on any execution path.
	JustificationVulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"
	// JustificationComponentNotPresent is reserved for the case where the
	// component is not present in the resolved graph at all.
	JustificationComponentNotPresent Justification = "component_not_present"
)

// Reachability is the verdict the VEX status maps from. It mirrors the analyzer
// confidence tiers without coupling this package to the wire proto.
type Reachability int

const (
	// ReachabilityUnknown means reachability could not be determined.
	ReachabilityUnknown Reachability = iota
	// ReachabilityNotReachable means no path to the vulnerable code was found.
	ReachabilityNotReachable
	// ReachabilityPackageReachable means the vulnerable package is reachable.
	ReachabilityPackageReachable
	// ReachabilitySymbolReachable means the vulnerable symbol is reachable.
	ReachabilitySymbolReachable
)

// MapStatus is the cardinal-sin guard. It maps a reachability verdict to a VEX
// status, given whether the producing analysis was incomplete.
//
// The invariant: under_investigation for anything unproven; not_affected ONLY
// for a complete, proven NOT_REACHABLE verdict. An incomplete analysis can never
// yield not_affected — a partial analysis cannot prove the vulnerable code is
// unreachable, so it stays under_investigation. A reachable finding stays
// affected regardless of incompleteness (affected is the honest, non-clean
// status; extra unexplored paths only reinforce it).
func MapStatus(r Reachability, incomplete bool) (Status, Justification) {
	switch r {
	case ReachabilitySymbolReachable, ReachabilityPackageReachable:
		return StatusAffected, ""
	case ReachabilityNotReachable:
		if incomplete {
			// Analysis was partial; we cannot prove unreachability. Never clean.
			return StatusUnderInvestigation, ""
		}
		return StatusNotAffected, JustificationVulnerableCodeNotInExecutePath
	default:
		// ReachabilityUnknown and any unrecognised value: conservative.
		return StatusUnderInvestigation, ""
	}
}

// Vulnerability identifies the flaw a statement is about.
type Vulnerability struct {
	// ID is the canonical identifier (CVE preferred, else GHSA/GO/etc.).
	ID string
	// Aliases are alternative identifiers (e.g. the GHSA when ID is a CVE).
	Aliases []string
}

// Product identifies the affected component by Package URL (purl).
type Product struct {
	// PURL is the Package URL (e.g. "pkg:golang/golang.org/x/net").
	PURL string
}

// Statement is one (vulnerability, product) assertion with a VEX status.
type Statement struct {
	Vuln Vulnerability
	// Product is the single affected component this statement is about. One
	// product per statement keeps statements trivially sortable by (vuln, purl).
	Product Product
	Status  Status
	// Justification is set only for not_affected.
	Justification Justification
	// ActionStatement is the remediation guidance for affected statements.
	ActionStatement string
	// Timestamp is when this assertion was made (injected by the caller).
	Timestamp time.Time
}

// Document is a complete VEX document: an authored, timestamped set of
// statements.
type Document struct {
	Author     string
	Timestamp  time.Time
	Statements []Statement
}

// Sort orders the statements deterministically by vulnerability id, then purl,
// then status. Call it before formatting to guarantee reproducible output.
func (d *Document) Sort() {
	sort.SliceStable(d.Statements, func(i, j int) bool {
		a, b := d.Statements[i], d.Statements[j]
		if a.Vuln.ID != b.Vuln.ID {
			return a.Vuln.ID < b.Vuln.ID
		}
		if a.Product.PURL != b.Product.PURL {
			return a.Product.PURL < b.Product.PURL
		}
		return a.Status < b.Status
	})
}

// purlTypes maps an advisory ecosystem string (the advisory.Ecosystem* values)
// to its Package URL type per the purl spec.
var purlTypes = map[string]string{
	"Go":        "golang",
	"npm":       "npm",
	"crates.io": "cargo",
	"PyPI":      "pypi",
	"Maven":     "maven",
	"NuGet":     "nuget",
	"Packagist": "composer",
	"RubyGems":  "gem",
	"Hex":       "hex",
	"Pub":       "pub",
	"SwiftURL":  "swift",
}

// PackageURL builds a Package URL (purl) for a package in the given advisory
// ecosystem. version may be empty for a package-level identity (commit0-analyzer does not
// invent a version it does not have). Returns "" when the ecosystem is unknown
// or the name is empty so callers can fall back to a name identifier.
func PackageURL(ecosystem, name, version string) string {
	typ := purlTypes[ecosystem]
	if typ == "" || name == "" {
		return ""
	}
	namePart := name
	if typ == "maven" {
		// Maven coordinates are "group:artifact"; purl uses "group/artifact".
		namePart = strings.ReplaceAll(name, ":", "/")
	}
	purl := "pkg:" + typ + "/" + namePart
	if version != "" {
		purl += "@" + version
	}
	return purl
}

// StatementInput is the per-finding data BuildDocument turns into a Statement.
type StatementInput struct {
	// VulnID is the canonical advisory id of the finding.
	VulnID string
	// Aliases are the finding's alternative identifiers.
	Aliases []string
	// Ecosystem is the advisory ecosystem (advisory.Ecosystem*), used for purl.
	Ecosystem string
	// PackageName is the affected package/module name.
	PackageName string
	// Version is the installed version, if known (empty = package-level purl).
	Version string
	// FixedVersion is the lowest fixed version, if known, for the action statement.
	FixedVersion string
	// Reachability is the finding's reachability verdict.
	Reachability Reachability
	// Incomplete is true when the analysis producing the finding was partial.
	Incomplete bool
}

// BuildDocument turns per-finding inputs into a sorted VEX Document. ts is the
// injected document timestamp (also stamped on each statement). Inputs whose
// VulnID is empty are skipped (no advisory to attest to).
func BuildDocument(ts time.Time, inputs []StatementInput) *Document {
	doc := &Document{Author: Author, Timestamp: ts}
	for _, in := range inputs {
		if in.VulnID == "" {
			continue
		}
		status, justification := MapStatus(in.Reachability, in.Incomplete)
		stmt := Statement{
			Vuln:          Vulnerability{ID: in.VulnID, Aliases: dedupeSorted(in.Aliases)},
			Product:       Product{PURL: PackageURL(in.Ecosystem, in.PackageName, in.Version)},
			Status:        status,
			Justification: justification,
			Timestamp:     ts,
		}
		if status == StatusAffected {
			stmt.ActionStatement = actionStatement(in.PackageName, in.FixedVersion)
		}
		doc.Statements = append(doc.Statements, stmt)
	}
	doc.Sort()
	return doc
}

// actionStatement returns OpenVEX-required remediation text for an affected
// component. OpenVEX requires a non-empty action_statement for affected.
func actionStatement(pkg, fixedVersion string) string {
	if fixedVersion != "" {
		if pkg != "" {
			return "Update " + pkg + " to " + fixedVersion + " or later."
		}
		return "Update to " + fixedVersion + " or later."
	}
	return "Investigate and apply available mitigations; no fixed version is recorded."
}

// dedupeSorted returns a sorted, de-duplicated copy of in with empties removed.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
