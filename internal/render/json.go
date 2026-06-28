package render

import (
	"encoding/json"
	"sort"
	"strconv"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// jsonAdvisory is the stable JSON representation of an advisory reference.
type jsonAdvisory struct {
	ID      string   `json:"id"`
	URL     string   `json:"url,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// jsonLocation is the stable JSON representation of a source location.
type jsonLocation struct {
	File   string `json:"file"`
	Line   int32  `json:"line"`
	Column int32  `json:"column,omitempty"`
}

// jsonCallStep is the stable JSON representation of one call-chain frame.
type jsonCallStep struct {
	Location *jsonLocation `json:"location,omitempty"`
	Symbol   string        `json:"symbol,omitempty"`
}

// jsonPath is the stable JSON representation of a reachability path.
type jsonPath struct {
	Steps []jsonCallStep `json:"steps"`
}

// jsonRisk is the stable JSON representation of the fused risk-prioritization
// signal. It mirrors the risk_* properties stamped by the risk-fusion pass so the
// risk score is a first-class, typed field in JSON output (not only a string in
// the properties map). Omitted entirely when a finding carries no risk signal.
type jsonRisk struct {
	Score     float64 `json:"score"`
	Tier      string  `json:"tier,omitempty"`
	Rationale string  `json:"rationale,omitempty"`
	CVSS      string  `json:"cvss,omitempty"`
	EPSS      string  `json:"epss,omitempty"`
	KEV       string  `json:"kev,omitempty"`
	CWE       string  `json:"cwe,omitempty"`
}

// jsonFinding is the stable JSON schema for a single finding.
// Field order is fixed by struct tag order; deterministic key order is guaranteed
// by encoding/json marshalling struct fields in declaration order.
type jsonFinding struct {
	Advisory   jsonAdvisory      `json:"advisory"`
	Module     string            `json:"module"`
	Confidence string            `json:"confidence"`
	Severity   string            `json:"severity"`
	Risk       *jsonRisk         `json:"risk,omitempty"`
	Provenance *jsonProvenance   `json:"provenance,omitempty"`
	Path       *jsonPath         `json:"path,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	Pillar     string            `json:"pillar,omitempty"`
	Language   string            `json:"language,omitempty"`
}

// jsonProvenance is the stable JSON representation of the cross-source audit
// trail stamped by the provenance pass. It mirrors the provenance/
// severity_conflict/stale_source properties so the merge layer's evidence is a
// first-class field, not only a string in the properties map. Omitted entirely
// when a finding carries no provenance signal.
type jsonProvenance struct {
	// Summary is the per-source provenance string ("name SEVERITY vector"),
	// NOT the source list. It is deliberately named "summary" rather than
	// "sources" to avoid colliding with the finding's properties["sources"]
	// (the comma-joined contributing-source list), which is a different value.
	Summary          string `json:"summary"`
	SeverityConflict string `json:"severity_conflict,omitempty"`
	StaleSources     string `json:"stale_sources,omitempty"`
}

// ToJSON converts a slice of findings into a stable JSON byte slice.
//
// Output guarantees:
//   - Findings are sorted by advisory ID (deterministic across calls).
//   - Map keys inside Properties are emitted in sorted order by encoding/json.
//   - All fields use fixed struct tag names; the schema is stable across versions.
//   - nil input produces a valid empty JSON array ("[]").
func ToJSON(findings []*commit0v1.Finding) ([]byte, error) {
	// Sort by advisory ID for deterministic output.
	sorted := make([]*commit0v1.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetAdvisory().GetId() < sorted[j].GetAdvisory().GetId()
	})

	out := make([]jsonFinding, 0, len(sorted))
	for _, f := range sorted {
		jf := toJSONFinding(f)
		out = append(out, jf)
	}

	// MarshalIndent for readability; struct field order guarantees stable key order.
	return json.MarshalIndent(out, "", "  ")
}

// toJSONFinding converts a single proto Finding to the stable jsonFinding schema.
func toJSONFinding(f *commit0v1.Finding) jsonFinding {
	adv := jsonAdvisory{}
	if a := f.GetAdvisory(); a != nil {
		adv.ID = a.GetId()
		adv.URL = a.GetUrl()
		if len(a.GetAliases()) > 0 {
			adv.Aliases = a.GetAliases()
		}
	}

	jf := jsonFinding{
		Advisory:   adv,
		Module:     f.GetModule(),
		Confidence: f.GetConfidence().String(),
		Severity:   f.GetSeverity().String(),
		Pillar:     f.GetPillar(),
		Language:   f.GetLanguage(),
	}

	// Path: only populate when steps are present.
	if p := f.GetPath(); p != nil && len(p.GetSteps()) > 0 {
		steps := make([]jsonCallStep, 0, len(p.GetSteps()))
		for _, s := range p.GetSteps() {
			step := jsonCallStep{Symbol: s.GetSymbol()}
			if loc := s.GetLocation(); loc != nil {
				step.Location = &jsonLocation{
					File:   loc.GetFile(),
					Line:   loc.GetLine(),
					Column: loc.GetColumn(),
				}
			}
			steps = append(steps, step)
		}
		jf.Path = &jsonPath{Steps: steps}
	}

	// Properties: copy map; encoding/json marshals map keys in sorted order.
	if props := f.GetProperties(); len(props) > 0 {
		jf.Properties = make(map[string]string, len(props))
		for k, v := range props {
			jf.Properties[k] = v
		}
		jf.Risk = riskFromProperties(props)
		jf.Provenance = provenanceFromProperties(props)
	}

	return jf
}

// provenanceFromProperties extracts the cross-source audit trail from a finding's
// properties into a typed jsonProvenance, or returns nil when no provenance
// signal is present.
func provenanceFromProperties(props map[string]string) *jsonProvenance {
	prov := props["provenance"]
	if prov == "" {
		return nil
	}
	return &jsonProvenance{
		Summary:          prov,
		SeverityConflict: props["severity_conflict"],
		StaleSources:     props["stale_source"],
	}
}

// riskFromProperties extracts the fused risk signal from a finding's properties
// into a typed jsonRisk, or returns nil when no risk score/tier is present.
func riskFromProperties(props map[string]string) *jsonRisk {
	score, hasScore := props["risk_score"]
	tier := props["risk_tier"]
	if !hasScore && tier == "" {
		return nil
	}
	r := &jsonRisk{
		Tier:      tier,
		Rationale: props["risk_rationale"],
		CVSS:      props["cvss"],
		EPSS:      props["epss"],
		KEV:       props["kev"],
		CWE:       props["cwe"],
	}
	if hasScore {
		if v, err := strconv.ParseFloat(score, 64); err == nil {
			r.Score = v
		}
	}
	return r
}
