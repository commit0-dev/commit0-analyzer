package vex

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Formatter renders a Document into a serialized VEX document.
type Formatter interface {
	// Name is the formatter's stable short name (e.g. "openvex").
	Name() string
	// FileName is the conventional filename used for multi-format output.
	FileName() string
	// Format renders the document to bytes.
	Format(d *Document) ([]byte, error)
}

// allFormatters returns every formatter, in deterministic (name-sorted) order.
func allFormatters() []Formatter {
	return []Formatter{CSAFFormatter{}, CycloneDXFormatter{}, OpenVEXFormatter{}}
}

// Formatters resolves a --vex flag value into formatters. Accepted values are
// "openvex", "cyclonedx", "csaf", "all", and comma-separated combinations. An
// unrecognised value is an error (unknown ≠ a silent no-op).
func Formatters(spec string) ([]Formatter, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return nil, nil
	}
	if spec == "all" {
		return allFormatters(), nil
	}
	byName := map[string]Formatter{}
	for _, f := range allFormatters() {
		byName[f.Name()] = f
	}
	seen := map[string]struct{}{}
	var out []Formatter
	for _, part := range strings.Split(spec, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if name == "all" {
			return allFormatters(), nil
		}
		f, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown VEX format %q: must be openvex|cyclonedx|csaf|all", name)
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, f)
	}
	// Deterministic order regardless of how the user listed them.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Write renders the document with each formatter and writes the output.
//
//   - A single formatter writes to out. When out is "" or "-", it writes to
//     stdout.
//   - Multiple formatters require a directory out (stdout cannot carry several
//     documents); one file per formatter (Formatter.FileName) is written there.
//
// Write creates parent directories for file outputs as needed.
func Write(formatters []Formatter, doc *Document, out string, stdout io.Writer) error {
	if len(formatters) == 0 {
		return nil
	}
	toStdout := out == "" || out == "-"

	if len(formatters) == 1 {
		data, err := formatters[0].Format(doc)
		if err != nil {
			return fmt.Errorf("render %s VEX: %w", formatters[0].Name(), err)
		}
		if toStdout {
			_, werr := stdout.Write(data)
			return werr
		}
		if mkErr := os.MkdirAll(filepath.Dir(out), 0o755); mkErr != nil {
			return fmt.Errorf("create VEX output dir: %w", mkErr)
		}
		return os.WriteFile(out, data, 0o644)
	}

	// Multiple formatters: out must be a directory.
	if toStdout {
		return fmt.Errorf("--vex-out must be a directory when multiple VEX formats are requested")
	}
	if mkErr := os.MkdirAll(out, 0o755); mkErr != nil {
		return fmt.Errorf("create VEX output dir %q: %w", out, mkErr)
	}
	for _, f := range formatters {
		data, err := f.Format(doc)
		if err != nil {
			return fmt.Errorf("render %s VEX: %w", f.Name(), err)
		}
		dest := filepath.Join(out, f.FileName())
		if werr := os.WriteFile(dest, data, 0o644); werr != nil {
			return fmt.Errorf("write %s VEX to %s: %w", f.Name(), dest, werr)
		}
	}
	return nil
}
