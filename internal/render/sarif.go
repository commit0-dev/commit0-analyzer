package render

import (
	"encoding/json"
	"fmt"
	"sort"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// sarifVersion is the SARIF specification version emitted by this renderer.
const sarifVersion = "2.1.0"

// sarifSchemaURI is the canonical URI for the SARIF 2.1.0 JSON schema.
const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// ToSARIF converts a slice of findings into a SARIF 2.1.0 JSON document.
//
// Key invariants (Red Team #8, #9):
//   - codeFlows is OMITTED ENTIRELY for any finding with zero CallSteps.
//     An empty threadFlow.locations is schema-invalid and causes GitHub to reject
//     the entire upload (one blank path = zero findings shown).
//   - NOT_REACHABLE findings are rendered as suppressed results (kind=external),
//     never silently absent, so they remain auditable.
//   - UNKNOWN findings appear as ordinary results with no suppression.
//   - Findings are sorted by advisory ID for deterministic output.
//
// The caller may pass nil; the result is a valid SARIF document with an empty
// results array.
func ToSARIF(findings []*anstv1.Finding) ([]byte, error) {
	// Sort findings by advisory ID for deterministic output.
	sorted := make([]*anstv1.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetAdvisory().GetId() < sorted[j].GetAdvisory().GetId()
	})

	results := make([]sarifResult, 0, len(sorted))
	for _, f := range sorted {
		r, err := findingToSARIFResult(f)
		if err != nil {
			return nil, fmt.Errorf("sarif: converting finding %q: %w", f.GetAdvisory().GetId(), err)
		}
		results = append(results, r)
	}

	doc := sarifDocument{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifToolComponent{
						Name:           "anst-analyzer",
						InformationURI: "https://github.com/ducthinh993/anst-analyzer",
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// findingToSARIFResult converts a single Finding to a sarifResult.
func findingToSARIFResult(f *anstv1.Finding) (sarifResult, error) {
	r := sarifResult{
		RuleID:  f.GetAdvisory().GetId(),
		Level:   severityToSARIFLevel(f.GetSeverity()),
		Message: sarifMessage{Text: buildResultMessage(f)},
	}

	// Populate result.properties with confidence, sources, and analyzer metadata.
	props := map[string]interface{}{
		"confidence": f.GetConfidence().String(),
		"module":     f.GetModule(),
	}
	if adv := f.GetAdvisory(); adv != nil {
		if adv.GetUrl() != "" {
			props["advisory_url"] = adv.GetUrl()
		}
		if len(adv.GetAliases()) > 0 {
			props["aliases"] = adv.GetAliases()
		}
	}
	for k, v := range f.GetProperties() {
		props[k] = v
	}
	if f.GetPillar() != "" {
		props["pillar"] = f.GetPillar()
	}
	if f.GetLanguage() != "" {
		props["language"] = f.GetLanguage()
	}
	r.Properties = props

	// codeFlows: ONLY when the finding has at least one CallStep (Red Team #9).
	// An empty threadFlow.locations is schema-invalid.
	if path := f.GetPath(); path != nil && len(path.GetSteps()) > 0 {
		locs := make([]sarifThreadFlowLocation, 0, len(path.GetSteps()))
		for _, step := range path.GetSteps() {
			tfl := sarifThreadFlowLocation{}
			if loc := step.GetLocation(); loc != nil {
				tfl.Location = &sarifLocation{
					PhysicalLocation: &sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: loc.GetFile()},
						Region: &sarifRegion{
							StartLine:   int(loc.GetLine()),
							StartColumn: int(loc.GetColumn()),
						},
					},
					Message: &sarifMessage{Text: step.GetSymbol()},
				}
			}
			locs = append(locs, tfl)
		}
		r.CodeFlows = []sarifCodeFlow{
			{
				ThreadFlows: []sarifThreadFlow{
					{Locations: locs},
				},
			},
		}
	}
	// Path-less findings (PACKAGE_REACHABLE, UNKNOWN, NOT_REACHABLE) omit codeFlows.

	// NOT_REACHABLE: render as suppressed so the finding is auditable (Red Team #15d).
	if f.GetConfidence() == anstv1.Confidence_CONFIDENCE_NOT_REACHABLE {
		r.Suppressions = []sarifSuppression{
			{
				Kind:          "external",
				Status:        "accepted",
				Justification: "Analyzer determined no call path from any entry point reaches the vulnerable symbol/package.",
			},
		}
		// Override level to "note" for suppressed results so they don't block CI
		// even when suppressions are ignored by a viewer.
		r.Level = "note"
	}

	return r, nil
}

// severityToSARIFLevel maps a Severity enum to a SARIF result level string.
//
// Mapping:
//   - CRITICAL / HIGH → "error"
//   - MEDIUM         → "warning"
//   - LOW            → "note"
//   - UNSPECIFIED    → "none"
func severityToSARIFLevel(s anstv1.Severity) string {
	switch s {
	case anstv1.Severity_SEVERITY_CRITICAL, anstv1.Severity_SEVERITY_HIGH:
		return "error"
	case anstv1.Severity_SEVERITY_MEDIUM:
		return "warning"
	case anstv1.Severity_SEVERITY_LOW:
		return "note"
	default:
		return "none"
	}
}

// buildResultMessage returns a human-readable message for the SARIF result.
func buildResultMessage(f *anstv1.Finding) string {
	id := f.GetAdvisory().GetId()
	mod := f.GetModule()
	conf := f.GetConfidence().String()
	switch f.GetConfidence() {
	case anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE:
		return fmt.Sprintf("Vulnerability %s in %s: a concrete call path to the vulnerable symbol was found (%s).", id, mod, conf)
	case anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
		return fmt.Sprintf("Vulnerability %s in %s: the vulnerable package is reachable but symbol-level confirmation is unavailable (%s).", id, mod, conf)
	case anstv1.Confidence_CONFIDENCE_NOT_REACHABLE:
		return fmt.Sprintf("Vulnerability %s in %s: no call path to the vulnerable symbol was found (%s). Suppressed but auditable.", id, mod, conf)
	default: // UNKNOWN
		return fmt.Sprintf("Vulnerability %s in %s: reachability could not be determined (%s). Surfaced because unknown ≠ safe.", id, mod, conf)
	}
}

// --- SARIF 2.1.0 data model structs ---
// Only the fields we emit are included; omitempty drops absent optional fields.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifToolComponent `json:"driver"`
}

type sarifToolComponent struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
}

type sarifResult struct {
	RuleID       string                 `json:"ruleId"`
	Level        string                 `json:"level"`
	Message      sarifMessage           `json:"message"`
	CodeFlows    []sarifCodeFlow        `json:"codeFlows,omitempty"`
	Suppressions []sarifSuppression     `json:"suppressions,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location *sarifLocation `json:"location,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *sarifMessage          `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}
