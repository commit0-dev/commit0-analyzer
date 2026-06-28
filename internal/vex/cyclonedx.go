package vex

// CycloneDXFormatter renders a Document as a CycloneDX 1.5 BOM carrying a
// vulnerabilities[] array with per-vulnerability analysis state (CycloneDX-VEX).
type CycloneDXFormatter struct{}

// Name returns the formatter's stable short name.
func (CycloneDXFormatter) Name() string { return "cyclonedx" }

// FileName returns the conventional filename for multi-format output.
func (CycloneDXFormatter) FileName() string { return "anst.cyclonedx.vex.json" }

type cdxDoc struct {
	BOMFormat       string    `json:"bomFormat"`
	SpecVersion     string    `json:"specVersion"`
	Version         int       `json:"version"`
	Metadata        cdxMeta   `json:"metadata"`
	Vulnerabilities []cdxVuln `json:"vulnerabilities"`
}

type cdxMeta struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     []cdxTool  `json:"tools,omitempty"`
}

type cdxTool struct {
	Name string `json:"name"`
}

type cdxVuln struct {
	ID       string       `json:"id"`
	Analysis cdxAnalysis  `json:"analysis"`
	Affects  []cdxAffect  `json:"affects"`
}

type cdxAnalysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// Format renders the document. One CycloneDX vulnerability is emitted per
// statement (anst keys statements per (vuln, product), which CycloneDX models as
// a vulnerability with an affects[] ref). Statements are already sorted upstream.
func (f CycloneDXFormatter) Format(d *Document) ([]byte, error) {
	out := cdxDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMeta{
			Timestamp: rfc3339(d.Timestamp),
			Tools:     []cdxTool{{Name: authorOf(d)}},
		},
	}
	for _, s := range d.Statements {
		v := cdxVuln{
			ID:      s.Vuln.ID,
			Analysis: cdxAnalysis{State: cdxState(s.Status)},
			Affects: []cdxAffect{{Ref: productID(s.Product)}},
		}
		if s.Status == StatusNotAffected {
			v.Analysis.Justification = "code_not_reachable"
		}
		if s.ActionStatement != "" {
			v.Analysis.Detail = s.ActionStatement
		}
		out.Vulnerabilities = append(out.Vulnerabilities, v)
	}
	return marshalIndent(out)
}

// cdxState maps a VEX status to a CycloneDX impactAnalysisState value.
func cdxState(s Status) string {
	switch s {
	case StatusNotAffected:
		return "not_affected"
	case StatusAffected:
		return "exploitable"
	case StatusFixed:
		return "resolved"
	default:
		// StatusUnderInvestigation and any unrecognised value.
		return "in_triage"
	}
}
