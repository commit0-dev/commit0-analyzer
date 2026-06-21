package render

import (
	"encoding/json"
	"sort"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
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

// jsonFinding is the stable JSON schema for a single finding.
// Field order is fixed by struct tag order; deterministic key order is guaranteed
// by encoding/json marshalling struct fields in declaration order.
type jsonFinding struct {
	Advisory   jsonAdvisory      `json:"advisory"`
	Module     string            `json:"module"`
	Confidence string            `json:"confidence"`
	Severity   string            `json:"severity"`
	Path       *jsonPath         `json:"path,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	Pillar     string            `json:"pillar,omitempty"`
	Language   string            `json:"language,omitempty"`
}

// ToJSON converts a slice of findings into a stable JSON byte slice.
//
// Output guarantees:
//   - Findings are sorted by advisory ID (deterministic across calls).
//   - Map keys inside Properties are emitted in sorted order by encoding/json.
//   - All fields use fixed struct tag names; the schema is stable across versions.
//   - nil input produces a valid empty JSON array ("[]").
func ToJSON(findings []*anstv1.Finding) ([]byte, error) {
	// Sort by advisory ID for deterministic output.
	sorted := make([]*anstv1.Finding, len(findings))
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
func toJSONFinding(f *anstv1.Finding) jsonFinding {
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
	}

	return jf
}
