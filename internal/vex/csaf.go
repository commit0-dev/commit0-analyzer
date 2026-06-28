package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// CSAFFormatter renders a Document as a CSAF 2.0 "csaf_vex" document. CSAF groups
// assertions per vulnerability with product_status arrays, so multiple commit0-analyzer
// statements about the same vulnerability collapse into one CSAF vulnerability.
type CSAFFormatter struct{}

// Name returns the formatter's stable short name.
func (CSAFFormatter) Name() string { return "csaf" }

// FileName returns the conventional filename for multi-format output.
func (CSAFFormatter) FileName() string { return "commit0.csaf.json" }

type csafDoc struct {
	Document        csafMeta    `json:"document"`
	ProductTree     csafTree    `json:"product_tree"`
	Vulnerabilities []csafVuln  `json:"vulnerabilities"`
}

type csafMeta struct {
	Category    string        `json:"category"`
	CSAFVersion string        `json:"csaf_version"`
	Title       string        `json:"title"`
	Publisher   csafPublisher `json:"publisher"`
	Tracking    csafTracking  `json:"tracking"`
}

type csafPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type csafTracking struct {
	ID                 string            `json:"id"`
	Status             string            `json:"status"`
	Version            string            `json:"version"`
	InitialReleaseDate string            `json:"initial_release_date"`
	CurrentReleaseDate string            `json:"current_release_date"`
	RevisionHistory    []csafRevision    `json:"revision_history"`
}

type csafRevision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

type csafTree struct {
	FullProductNames []csafProduct `json:"full_product_names"`
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type csafVuln struct {
	CVE           string            `json:"cve,omitempty"`
	IDs           []csafID          `json:"ids,omitempty"`
	ProductStatus csafProductStatus `json:"product_status"`
	Flags         []csafFlag        `json:"flags,omitempty"`
	Remediations  []csafRemediation `json:"remediations,omitempty"`
}

type csafID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type csafProductStatus struct {
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
}

type csafFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type csafRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

// Format renders the document grouped by vulnerability.
func (f CSAFFormatter) Format(d *Document) ([]byte, error) {
	// Collect products (product_id == purl) deterministically.
	productSet := map[string]struct{}{}
	// Preserve insertion order keyed by first appearance in the sorted statements.
	var vulnOrder []string
	byVuln := map[string][]Statement{}
	for _, s := range d.Statements {
		pid := productID(s.Product)
		productSet[pid] = struct{}{}
		if _, ok := byVuln[s.Vuln.ID]; !ok {
			vulnOrder = append(vulnOrder, s.Vuln.ID)
		}
		byVuln[s.Vuln.ID] = append(byVuln[s.Vuln.ID], s)
	}

	out := csafDoc{
		Document: csafMeta{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       "commit0 reachability VEX",
			Publisher: csafPublisher{
				Category:  "vendor",
				Name:      authorOf(d),
				Namespace: "https://github.com/commit0-dev/commit0-analyzer",
			},
			Tracking: csafTracking{
				ID:                 csafTrackingID(d),
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: rfc3339(d.Timestamp),
				CurrentReleaseDate: rfc3339(d.Timestamp),
				RevisionHistory: []csafRevision{{
					Number:  "1",
					Date:    rfc3339(d.Timestamp),
					Summary: "Initial reachability assessment.",
				}},
			},
		},
	}

	// product_tree: sorted product ids.
	products := make([]string, 0, len(productSet))
	for p := range productSet {
		products = append(products, p)
	}
	sort.Strings(products)
	for _, p := range products {
		out.ProductTree.FullProductNames = append(out.ProductTree.FullProductNames,
			csafProduct{ProductID: p, Name: p})
	}

	// One CSAF vulnerability per distinct id, in sorted statement order.
	for _, vid := range vulnOrder {
		stmts := byVuln[vid]
		v := csafVuln{}
		if isCVE(vid) {
			v.CVE = vid
		} else {
			v.IDs = []csafID{{SystemName: "commit0 advisory id", Text: vid}}
		}
		var notAffectedFlagged []string
		for _, s := range stmts {
			pid := productID(s.Product)
			switch s.Status {
			case StatusAffected:
				v.ProductStatus.KnownAffected = append(v.ProductStatus.KnownAffected, pid)
				cat := "none_available"
				if hasFixedVersion(s.ActionStatement) {
					cat = "vendor_fix"
				}
				v.Remediations = append(v.Remediations, csafRemediation{
					Category:   cat,
					Details:    s.ActionStatement,
					ProductIDs: []string{pid},
				})
			case StatusNotAffected:
				v.ProductStatus.KnownNotAffected = append(v.ProductStatus.KnownNotAffected, pid)
				if s.Justification == JustificationVulnerableCodeNotInExecutePath {
					notAffectedFlagged = append(notAffectedFlagged, pid)
				}
			case StatusFixed:
				v.ProductStatus.Fixed = append(v.ProductStatus.Fixed, pid)
			default:
				// StatusUnderInvestigation and any unrecognised value.
				v.ProductStatus.UnderInvestigation = append(v.ProductStatus.UnderInvestigation, pid)
			}
		}
		if len(notAffectedFlagged) > 0 {
			sort.Strings(notAffectedFlagged)
			v.Flags = []csafFlag{{
				Label:      string(JustificationVulnerableCodeNotInExecutePath),
				ProductIDs: notAffectedFlagged,
			}}
		}
		out.Vulnerabilities = append(out.Vulnerabilities, v)
	}

	return marshalIndent(out)
}

// csafTrackingID derives a deterministic tracking id from the document content.
func csafTrackingID(d *Document) string {
	h := sha256.New()
	b, _ := json.Marshal(d.Statements)
	h.Write(b)
	h.Write([]byte(rfc3339(d.Timestamp)))
	return "commit0-vex-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// isCVE reports whether id is a CVE identifier.
func isCVE(id string) bool {
	return len(id) > 4 && id[:4] == "CVE-"
}

// hasFixedVersion reports whether an affected action statement names a fix.
// (BuildDocument writes an "Update … to …" sentence only when a fix is known.)
func hasFixedVersion(action string) bool {
	return action != "" && action != "Investigate and apply available mitigations; no fixed version is recorded."
}
