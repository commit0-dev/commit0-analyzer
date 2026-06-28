// Command standalone is a thin CLI runner for the rust-reachability engine.
// It constructs an AnalyzeRequest from flags and prints findings as JSON.
// Used for development, gate demonstration, and perf baseline capture.
//
// Usage:
//
//	standalone -module /path/to/cargo/root -adv-id RUSTSEC-2024-0001 \
//	           -adv-module serde
//	standalone -module /path/to/cargo/root -advisories advisories.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"github.com/commit0-dev/commit0-analyzer/plugins/rust-reachability/internal/cargo"
	"github.com/commit0-dev/commit0-analyzer/plugins/rust-reachability/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "standalone: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		moduleRoot = flag.String("module", "", "absolute path to the Cargo workspace or crate root (required)")
		advJSON    = flag.String("advisories", "", "path to a JSON file containing []Advisory")
		advID      = flag.String("adv-id", "", "single advisory ID (e.g. RUSTSEC-2024-0001)")
		advModule  = flag.String("adv-module", "", "single advisory crate name (e.g. serde)")
		advPkg     = flag.String("adv-pkg", "", "single advisory symbol package path (e.g. serde::de)")
		advSym     = flag.String("adv-sym", "", "single advisory symbol name (e.g. Deserialize)")
	)
	flag.Parse()

	if *moduleRoot == "" {
		return fmt.Errorf("-module is required")
	}

	// Build advisory list.
	var advisories []*commit0v1.Advisory
	if *advJSON != "" {
		data, err := os.ReadFile(*advJSON)
		if err != nil {
			return fmt.Errorf("read advisories: %w", err)
		}
		if err := json.Unmarshal(data, &advisories); err != nil {
			return fmt.Errorf("parse advisories: %w", err)
		}
	} else if *advID != "" {
		adv := &commit0v1.Advisory{
			Id:          *advID,
			Module:      *advModule,
			SymbolLevel: *advSym != "",
			Ecosystem:   commit0v1.Ecosystem_ECOSYSTEM_CRATES_IO,
		}
		if *advPkg != "" && *advSym != "" {
			adv.Symbols = []*commit0v1.Symbol{{
				Package: *advPkg,
				Name:    *advSym,
			}}
		}
		advisories = append(advisories, adv)
	}

	// Load cargo closure.
	manifest, loadErr := cargo.LoadManifest(context.Background(), *moduleRoot)
	if loadErr != nil {
		// Non-fatal: engine degrades to UNKNOWN+incomplete.
		fmt.Fprintf(os.Stderr, "warning: %v\n", loadErr)
	}

	// Run engine.
	a := &engine.Analyzer{
		Manifest:   manifest,
		Advisories: advisories,
	}
	findings := a.Analyze()

	// Serialize findings to a readable JSON form.
	type findingJSON struct {
		AdvisoryID string            `json:"advisory_id"`
		Module     string            `json:"module"`
		Confidence string            `json:"confidence"`
		Incomplete bool              `json:"incomplete,omitempty"`
		Properties map[string]string `json:"properties,omitempty"`
	}

	var out []findingJSON
	for _, f := range findings {
		out = append(out, findingJSON{
			AdvisoryID: f.GetAdvisory().GetId(),
			Module:     f.GetModule(),
			Confidence: f.GetConfidence().String(),
			Incomplete: f.GetIncomplete(),
			Properties: f.GetProperties(),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
