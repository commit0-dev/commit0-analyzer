package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// openVEXContext is the OpenVEX JSON-LD context URL the documents declare.
const openVEXContext = "https://openvex.dev/ns/v0.2.0"

// OpenVEXFormatter renders a Document as an OpenVEX v0.2.0 JSON document. It is
// the reference VEX implementation.
type OpenVEXFormatter struct{}

// Name returns the formatter's stable short name.
func (OpenVEXFormatter) Name() string { return "openvex" }

// FileName returns the conventional filename for multi-format output.
func (OpenVEXFormatter) FileName() string { return "commit0.openvex.json" }

type openVEXDoc struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVuln   `json:"vulnerability"`
	Products        []openVEXProd `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
	Timestamp       string        `json:"timestamp,omitempty"`
}

type openVEXVuln struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type openVEXProd struct {
	ID string `json:"@id"`
}

// Format renders the document. The @id is derived from a content hash so the
// same scan yields a byte-identical document (no random/UUID id).
func (f OpenVEXFormatter) Format(d *Document) ([]byte, error) {
	out := openVEXDoc{
		Context:   openVEXContext,
		Author:    authorOf(d),
		Timestamp: rfc3339(d.Timestamp),
		Version:   1,
	}
	for _, s := range d.Statements {
		st := openVEXStatement{
			Vulnerability: openVEXVuln{Name: s.Vuln.ID, Aliases: s.Vuln.Aliases},
			Products:      []openVEXProd{{ID: productID(s.Product)}},
			Status:        string(s.Status),
			Timestamp:     rfc3339(s.Timestamp),
		}
		if s.Justification != "" {
			st.Justification = string(s.Justification)
		}
		if s.ActionStatement != "" {
			st.ActionStatement = s.ActionStatement
		}
		out.Statements = append(out.Statements, st)
	}
	out.ID = openVEXID(out)
	return marshalIndent(out)
}

// openVEXID computes a deterministic @id from the document's stable content.
func openVEXID(doc openVEXDoc) string {
	h := sha256.New()
	// Hash the stable, id-free content (statements + timestamp + author).
	stripped := doc
	stripped.ID = ""
	b, _ := json.Marshal(stripped)
	h.Write(b)
	return "https://openvex.dev/docs/commit0-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// rfc3339 formats a time in UTC RFC3339, or "" for the zero time.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// authorOf returns the document author, defaulting to the package Author.
func authorOf(d *Document) string {
	if d.Author != "" {
		return d.Author
	}
	return Author
}

// productID returns the purl when present, else a placeholder so the product is
// never silently empty (an empty @id would be invalid and would hide the gap).
func productID(p Product) string {
	if p.PURL != "" {
		return p.PURL
	}
	return "unknown-product"
}

// marshalIndent renders v as indented JSON with a trailing newline.
func marshalIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
