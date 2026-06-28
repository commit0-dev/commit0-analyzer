package render

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// confidenceShort maps Confidence enum values to short display labels.
var confidenceShort = map[commit0v1.Confidence]string{
	commit0v1.Confidence_CONFIDENCE_UNKNOWN:          "UNKNOWN",
	commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE:    "NOT_REACHABLE",
	commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE: "PKG_REACHABLE",
	commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE:  "SYM_REACHABLE",
}

// severityShort maps Severity enum values to short display labels.
var severityShort = map[commit0v1.Severity]string{
	commit0v1.Severity_SEVERITY_UNSPECIFIED: "UNSPEC",
	commit0v1.Severity_SEVERITY_LOW:         "LOW",
	commit0v1.Severity_SEVERITY_MEDIUM:      "MEDIUM",
	commit0v1.Severity_SEVERITY_HIGH:        "HIGH",
	commit0v1.Severity_SEVERITY_CRITICAL:    "CRITICAL",
}

// ToTable converts a slice of findings into a TTY-friendly human-readable table.
//
// Columns: ADVISORY | SEVERITY | CONFIDENCE | MODULE | PATH
//
// Findings are sorted by (severity desc, advisory ID asc) for readability.
// The PATH column shows the first file:line of the reachability path when present,
// or "-" for path-less findings. nil input produces a header-only table noting
// no findings.
func ToTable(findings []*commit0v1.Finding) []byte {
	// Sort: severity descending, then advisory ID ascending.
	sorted := make([]*commit0v1.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		si := sorted[i].GetSeverity()
		sj := sorted[j].GetSeverity()
		// Higher severity rank first.
		ri := severityRankTable[si]
		rj := severityRankTable[sj]
		if ri != rj {
			return ri > rj
		}
		return sorted[i].GetAdvisory().GetId() < sorted[j].GetAdvisory().GetId()
	})

	var buf bytes.Buffer

	// Header.
	header := fmt.Sprintf("%-20s  %-10s  %-15s  %-12s  %-35s  %s",
		"ADVISORY", "SEVERITY", "CONFIDENCE", "RISK", "MODULE", "ENTRY POINT")
	buf.WriteString(header)
	buf.WriteByte('\n')
	buf.WriteString(strings.Repeat("-", len(header)+10))
	buf.WriteByte('\n')

	if len(sorted) == 0 {
		buf.WriteString("No findings.\n")
		return buf.Bytes()
	}

	for _, f := range sorted {
		advisoryID := f.GetAdvisory().GetId()
		sev := severityShort[f.GetSeverity()]
		conf := confidenceShort[f.GetConfidence()]
		mod := f.GetModule()

		entryPoint := "-"
		if p := f.GetPath(); p != nil && len(p.GetSteps()) > 0 {
			first := p.GetSteps()[0]
			if loc := first.GetLocation(); loc != nil && loc.GetFile() != "" {
				entryPoint = fmt.Sprintf("%s:%d", loc.GetFile(), loc.GetLine())
			} else if first.GetSymbol() != "" {
				entryPoint = first.GetSymbol()
			}
		}

		line := fmt.Sprintf("%-20s  %-10s  %-15s  %-12s  %-35s  %s",
			truncate(advisoryID, 20),
			truncate(sev, 10),
			truncate(conf, 15),
			truncate(riskCell(f), 12),
			truncate(mod, 35),
			entryPoint,
		)
		buf.WriteString(line)
		buf.WriteByte('\n')

		// For SYMBOL_REACHABLE findings, print a condensed call path below the row.
		if f.GetConfidence() == commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE {
			if p := f.GetPath(); p != nil {
				for i, step := range p.GetSteps() {
					prefix := "  ├─"
					if i == len(p.GetSteps())-1 {
						prefix = "  └─"
					}
					sym := step.GetSymbol()
					if loc := step.GetLocation(); loc != nil && loc.GetFile() != "" {
						sym = fmt.Sprintf("%s (%s:%d)", sym, loc.GetFile(), loc.GetLine())
					}
					buf.WriteString(prefix)
					buf.WriteString(" ")
					buf.WriteString(sym)
					buf.WriteByte('\n')
				}
			}
		}

		// Cross-source audit trail: surface provenance (and any severity conflict
		// or stale source) as an indented note line when present.
		if note := provenanceNote(f); note != "" {
			buf.WriteString(note)
			buf.WriteByte('\n')
		}
	}

	return buf.Bytes()
}

// provenanceNote renders the indented cross-source audit line for a finding from
// its stamped properties, or "" when the finding carries no provenance signal.
func provenanceNote(f *commit0v1.Finding) string {
	props := f.GetProperties()
	prov := props["provenance"]
	if prov == "" {
		return ""
	}
	note := "  provenance: " + prov
	if c := props["severity_conflict"]; c != "" {
		note += "  [severity conflict: " + c + "]"
	}
	if s := props["stale_source"]; s != "" {
		note += "  [stale: " + s + "]"
	}
	return note
}

// severityRankTable is the sorting rank for severities in the table (higher = more severe).
var severityRankTable = map[commit0v1.Severity]int{
	commit0v1.Severity_SEVERITY_UNSPECIFIED: 0,
	commit0v1.Severity_SEVERITY_LOW:         1,
	commit0v1.Severity_SEVERITY_MEDIUM:      2,
	commit0v1.Severity_SEVERITY_HIGH:        3,
	commit0v1.Severity_SEVERITY_CRITICAL:    4,
}

// riskCell renders the fused risk signal for the table's RISK column from the
// finding's properties (stamped by the risk-fusion pass). It prefers the numeric
// score, then the tier label, and shows "-" when no risk signal is present.
func riskCell(f *commit0v1.Finding) string {
	props := f.GetProperties()
	score := props["risk_score"]
	tier := strings.ToUpper(props["risk_tier"])
	switch {
	case score != "" && tier != "":
		return tier + " " + score
	case score != "":
		return score
	case tier != "":
		return tier
	default:
		return "-"
	}
}

// truncate returns s truncated to maxLen runes, appending "…" if shortened.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return string(runes[:maxLen-1]) + "…"
}
