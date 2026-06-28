// Command standalone is a thin CLI runner for the go-reachability engine.
// It constructs an AnalyzeRequest from flags and prints findings as JSON.
// Used for development, Gate G1 demonstration, and perf baseline capture.
//
// Usage:
//
//	standalone -module /path/to/module -adv-id GO-TEST-0001 \
//	           -adv-module example.com/vulnlib \
//	           -adv-pkg example.com/vulnlib -adv-sym VulnerableFunc
//	standalone -module /path/to/module -advisories advisories.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	engine "github.com/commit0-dev/commit0-analyzer/plugins/go-reachability/internal/engine"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "standalone: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		moduleRoot = flag.String("module", "", "absolute path to the Go module root (required)")
		advJSON    = flag.String("advisories", "", "path to a JSON file containing []Advisory")
		advID      = flag.String("adv-id", "", "single advisory ID (e.g. GO-TEST-0001)")
		advModule  = flag.String("adv-module", "", "single advisory module path")
		advPkg     = flag.String("adv-pkg", "", "single advisory package path")
		advSym     = flag.String("adv-sym", "", "single advisory symbol name")
		goos       = flag.String("goos", "", "GOOS override")
		goarch     = flag.String("goarch", "", "GOARCH override")
		tags       = flag.String("tags", "", "comma-separated build tags")
		algorithm  = flag.String("algorithm", "vta", "call-graph algorithm: vta or rta")
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
		}
		if *advPkg != "" && *advSym != "" {
			adv.Symbols = []*commit0v1.Symbol{{
				Package: *advPkg,
				Name:    *advSym,
			}}
		}
		advisories = append(advisories, adv)
	}

	// Build request.
	req := &commit0v1.AnalyzeRequest{
		ModuleRoot: *moduleRoot,
		BuildConfig: &commit0v1.BuildConfig{
			Goos:   *goos,
			Goarch: *goarch,
		},
		Advisories: advisories,
	}
	if *tags != "" {
		req.BuildConfig.Tags = strings.Split(*tags, ",")
	}

	// Select algorithm.
	var builder engine.GraphBuilder
	switch *algorithm {
	case "rta":
		builder = engine.RTAGraphBuilder
	default:
		builder = engine.DefaultGraphBuilder
	}

	findings, err := engine.Analyze(context.Background(), req, builder)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	// Serialize to a readable JSON form.
	type stepJSON struct {
		Symbol string `json:"symbol"`
		File   string `json:"file,omitempty"`
		Line   int32  `json:"line,omitempty"`
	}
	type findingJSON struct {
		AdvisoryID string            `json:"advisory_id"`
		Module     string            `json:"module"`
		Confidence string            `json:"confidence"`
		Path       []stepJSON        `json:"path,omitempty"`
		Properties map[string]string `json:"properties,omitempty"`
	}

	var out []findingJSON
	for _, f := range findings {
		ff := findingJSON{
			AdvisoryID: f.GetAdvisory().GetId(),
			Module:     f.GetModule(),
			Confidence: f.GetConfidence().String(),
			Properties: f.GetProperties(),
		}
		if f.GetPath() != nil {
			for _, s := range f.GetPath().GetSteps() {
				st := stepJSON{Symbol: s.GetSymbol()}
				if loc := s.GetLocation(); loc != nil {
					st.File = loc.GetFile()
					st.Line = loc.GetLine()
				}
				ff.Path = append(ff.Path, st)
			}
		}
		out = append(out, ff)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
