package parity

import (
	"sort"
	"strings"
)

// Tool names recorded on findings and in the report. commit0-analyzer is the subject under
// test; the rest are the external comparators it is measured against.
const (
	ToolCommit0        = "commit0-analyzer"
	ToolOSVScanner  = "osv-scanner"
	ToolGrype       = "grype"
	ToolTrivy       = "trivy"
	ToolGovulncheck = "govulncheck"
)

// Reachability verdicts as commit0-analyzer reports them in the native JSON Confidence
// field. They are normalized (lower-case, prefix-stripped) from the proto enum
// strings so the comparison logic does not depend on the proto package.
const (
	reachSymbol       = "symbol"
	reachPackage      = "package"
	reachUnknown      = "unknown"
	reachNotReachable = "not_reachable"
)

// Finding is one vulnerability finding normalized across tools so commit0-analyzer and a
// comparator can be compared on a common identity. Only the fields needed for
// coverage comparison are kept; richer per-tool detail is intentionally dropped.
type Finding struct {
	// Tool is the producing tool name (one of the Tool* constants).
	Tool string
	// VulnID is the tool's primary identifier for the vulnerability
	// (e.g. "CVE-2024-1234", "GHSA-xxxx", "GO-2024-0001").
	VulnID string
	// Aliases are alternative identifiers (CVE/GHSA/GO ids) the tool attached.
	Aliases []string
	// Ecosystem is the package ecosystem (e.g. "Go", "npm"); may be empty when
	// a tool does not report it.
	Ecosystem string
	// Package is the affected package/module name.
	Package string
	// Version is the affected installed version, when the tool reports it.
	Version string

	// Reachability is commit0-analyzer's verdict for this finding (one of the reach*
	// constants); empty for comparator findings, which carry no reachability.
	Reachability string
	// Incomplete is true when commit0-analyzer could not decide reachability for this finding
	// (unknown ≠ safe): such a finding is surfaced, never dropped. The real signal
	// commit0-analyzer emits is confidence == CONFIDENCE_UNKNOWN and/or
	// properties["synthetic"] == "true" (a crashed/timed-out plugin marker); commit0-analyzer
	// never emits a properties["incomplete"] key, so the harness must not read one.
	Incomplete bool

	// KEV is true when commit0-analyzer flagged this finding's advisory as listed in CISA's
	// Known Exploited Vulnerabilities catalog (properties["kev"] == "true").
	KEV bool
	// RiskTier is the fused risk band commit0-analyzer stamped (properties["risk_tier"], e.g.
	// "critical", "high"); empty when no risk signal was computed.
	RiskTier string
}

// identifiers returns the normalized, sorted, de-duplicated set of identifiers
// for a finding: its primary VulnID unioned with its aliases. Matching across
// tools is by intersection of these sets, because one tool may key a finding by
// CVE while another keys the same vulnerability by GHSA.
func (f Finding) identifiers() []string {
	seen := make(map[string]struct{}, len(f.Aliases)+1)
	add := func(id string) {
		n := normalizeID(id)
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	add(f.VulnID)
	for _, a := range f.Aliases {
		add(a)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// pkgName returns the normalized package name for cross-tool comparison.
func (f Finding) pkgName() string {
	return strings.ToLower(strings.TrimSpace(f.Package))
}

// normalizeID canonicalizes a vulnerability identifier for set comparison:
// trimmed and upper-cased so "cve-2024-1" and "CVE-2024-1" match.
func normalizeID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// sameVuln reports whether two findings refer to the same vulnerability on the
// same package. Identity requires (1) at least one shared identifier and (2) the
// same package name when both findings name a package. When either side omits the
// package name, identifier intersection alone decides — a deliberate, documented
// loosening so a comparator that does not emit a package coordinate is not
// silently treated as a different vulnerability (which would inflate misses).
func sameVuln(a, b Finding) bool {
	if !identifiersIntersect(a.identifiers(), b.identifiers()) {
		return false
	}
	an, bn := a.pkgName(), b.pkgName()
	if an == "" || bn == "" {
		return true
	}
	return an == bn
}

// identifiersIntersect reports whether two sorted identifier slices share any
// element. Both inputs come from identifiers(), so they are sorted and unique.
func identifiersIntersect(a, b []string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			return true
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return false
}

// isReachable reports whether an commit0-analyzer finding is reachable (symbol or package).
func (f Finding) isReachable() bool {
	return f.Reachability == reachSymbol || f.Reachability == reachPackage
}

// isNotReachable reports whether an commit0-analyzer finding carries a NOT_REACHABLE
// verdict. A NOT_REACHABLE verdict only counts as a sound suppression when the
// analysis was also complete (see classifyAgainstCommit0, which pairs this with
// !Incomplete to mirror vex.MapStatus): an incomplete analysis cannot prove
// unreachability, so it must not be laundered into a suppression.
func (f Finding) isNotReachable() bool {
	return f.Reachability == reachNotReachable
}
