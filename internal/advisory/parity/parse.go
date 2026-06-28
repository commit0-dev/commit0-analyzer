package parity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseCommit0 parses commit0-analyzer's native `--format json` output into normalized
// findings. The schema is the stable jsonFinding array emitted by
// internal/render.ToJSON: each entry carries an advisory {id, aliases}, module,
// confidence, severity, an optional language, and a flat properties map. The
// confidence string is the proto enum (e.g. "CONFIDENCE_NOT_REACHABLE") which is
// normalized to a reach* verdict.
//
// Incompleteness uses the REAL signal commit0-analyzer emits — confidence ==
// CONFIDENCE_UNKNOWN and/or properties["synthetic"] == "true" (the crashed/
// timed-out plugin marker stamped by internal/host). commit0-analyzer never emits an
// "incomplete"/"ecosystem"/"version" property, so this parser must not depend on
// any: doing so would read every finding as complete and let an incomplete
// NOT_REACHABLE be laundered into a sound suppression.
func ParseCommit0(data []byte) ([]Finding, error) {
	var raw []struct {
		Advisory struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		} `json:"advisory"`
		Module     string            `json:"module"`
		Confidence string            `json:"confidence"`
		Language   string            `json:"language"`
		Properties map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse commit0-analyzer json: %w", err)
	}
	out := make([]Finding, 0, len(raw))
	for _, r := range raw {
		reach := normalizeConfidence(r.Confidence)
		out = append(out, Finding{
			Tool:         ToolCommit0,
			VulnID:       r.Advisory.ID,
			Aliases:      r.Advisory.Aliases,
			Ecosystem:    r.Language,
			Package:      r.Module,
			Reachability: reach,
			Incomplete:   reach == reachUnknown || r.Properties["synthetic"] == "true",
			KEV:          r.Properties["kev"] == "true",
			RiskTier:     r.Properties["risk_tier"],
		})
	}
	return out, nil
}

// ParseCommit0VEX parses commit0-analyzer's OpenVEX (`--vex openvex`) document into a map from
// normalized vulnerability identifier (the statement's name plus every alias) to
// its VEX status string (e.g. "not_affected", "under_investigation", "affected").
// Indexing aliases too lets the harness look a finding up by any of its ids. An
// unparseable document is an error — never a silent empty map that could read as
// "no statuses".
func ParseCommit0VEX(data []byte) (map[string]string, error) {
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Status string `json:"status"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse commit0-analyzer openvex json: %w", err)
	}
	out := make(map[string]string, len(doc.Statements))
	for _, s := range doc.Statements {
		ids := append([]string{s.Vulnerability.Name}, s.Vulnerability.Aliases...)
		for _, id := range ids {
			if n := normalizeID(id); n != "" {
				out[n] = s.Status
			}
		}
	}
	return out, nil
}

// normalizeConfidence maps an commit0-analyzer proto Confidence enum string to a reach*
// verdict. An unrecognized value maps to reachUnknown (unknown ≠ safe): it is
// never treated as not-reachable, so it can never be mistaken for a sound
// suppression in the comparison.
func normalizeConfidence(c string) string {
	switch strings.ToUpper(strings.TrimSpace(c)) {
	case "CONFIDENCE_SYMBOL_REACHABLE":
		return reachSymbol
	case "CONFIDENCE_PACKAGE_REACHABLE":
		return reachPackage
	case "CONFIDENCE_NOT_REACHABLE":
		return reachNotReachable
	default:
		return reachUnknown
	}
}

// ParseOSVScanner parses osv-scanner `--format json` output. Schema:
// {results: [{packages: [{package: {name, version, ecosystem},
// vulnerabilities: [{id, aliases}]}]}]}.
func ParseOSVScanner(data []byte) ([]Finding, error) {
	var raw struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID      string   `json:"id"`
					Aliases []string `json:"aliases"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}
	var out []Finding
	for _, res := range raw.Results {
		for _, p := range res.Packages {
			for _, v := range p.Vulnerabilities {
				out = append(out, Finding{
					Tool:      ToolOSVScanner,
					VulnID:    v.ID,
					Aliases:   v.Aliases,
					Ecosystem: p.Package.Ecosystem,
					Package:   p.Package.Name,
					Version:   p.Package.Version,
				})
			}
		}
	}
	return out, nil
}

// ParseGrype parses grype `-o json` output. Schema:
// {matches: [{vulnerability: {id}, relatedVulnerabilities: [{id}],
// artifact: {name, version, type}}]}.
func ParseGrype(data []byte) ([]Finding, error) {
	var raw struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
			RelatedVulnerabilities []struct {
				ID string `json:"id"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse grype json: %w", err)
	}
	out := make([]Finding, 0, len(raw.Matches))
	for _, m := range raw.Matches {
		aliases := make([]string, 0, len(m.RelatedVulnerabilities))
		for _, r := range m.RelatedVulnerabilities {
			aliases = append(aliases, r.ID)
		}
		out = append(out, Finding{
			Tool:      ToolGrype,
			VulnID:    m.Vulnerability.ID,
			Aliases:   aliases,
			Ecosystem: m.Artifact.Type,
			Package:   m.Artifact.Name,
			Version:   m.Artifact.Version,
		})
	}
	return out, nil
}

// ParseTrivy parses trivy `--format json` output. Schema:
// {Results: [{Type, Vulnerabilities: [{VulnerabilityID, PkgName,
// InstalledVersion}]}]}.
func ParseTrivy(data []byte) ([]Finding, error) {
	var raw struct {
		Results []struct {
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []Finding
	for _, res := range raw.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, Finding{
				Tool:      ToolTrivy,
				VulnID:    v.VulnerabilityID,
				Ecosystem: res.Type,
				Package:   v.PkgName,
				Version:   v.InstalledVersion,
			})
		}
	}
	return out, nil
}

// ParseGovulncheck parses govulncheck `-json` output, a stream of newline- or
// brace-delimited JSON message objects. Two message kinds matter: "osv" carries
// the advisory metadata (id, aliases, affected module) and "finding" reports a
// reachable trace. govulncheck only emits a finding when the vulnerable symbol is
// called, so every parsed finding is symbol-reachable by that tool's definition.
// The osv messages seed identity/module data the findings reference by OSV id.
func ParseGovulncheck(data []byte) ([]Finding, error) {
	type osvMsg struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		} `json:"affected"`
	}
	type traceFrame struct {
		Module  string `json:"module"`
		Package string `json:"package"`
	}
	type envelope struct {
		OSV     *osvMsg `json:"osv"`
		Finding *struct {
			OSV   string       `json:"osv"`
			Trace []traceFrame `json:"trace"`
		} `json:"finding"`
	}

	dec := json.NewDecoder(bufio.NewReader(bytes.NewReader(data)))
	osvByID := map[string]osvMsg{}
	// Dedup findings: govulncheck emits one message per call site, many sharing
	// the same OSV id. Coverage parity cares about the vulnerability, not each site.
	seen := map[string]struct{}{}
	var out []Finding
	for {
		var e envelope
		if err := dec.Decode(&e); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("parse govulncheck json stream: %w", err)
		}
		switch {
		case e.OSV != nil:
			osvByID[e.OSV.ID] = *e.OSV
		case e.Finding != nil:
			id := e.Finding.OSV
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			f := Finding{
				Tool:         ToolGovulncheck,
				VulnID:       id,
				Reachability: reachSymbol, // govulncheck findings are call-proven
			}
			if meta, ok := osvByID[id]; ok {
				f.Aliases = meta.Aliases
				if len(meta.Affected) > 0 {
					f.Package = meta.Affected[0].Package.Name
					f.Ecosystem = meta.Affected[0].Package.Ecosystem
				}
			}
			if f.Package == "" && len(e.Finding.Trace) > 0 {
				f.Package = e.Finding.Trace[0].Module
			}
			out = append(out, f)
		}
	}
	return out, nil
}
