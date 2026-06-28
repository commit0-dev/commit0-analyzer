// Package corpus provides the reachability corpus harness and precision/recall
// metrics for commit0-analyzer. It runs the analyzer over labeled fixture modules,
// computes TP/FP/FN counts, and optionally records govulncheck baseline metadata.
//
// The harness calls the reachability engine via exec of the compiled plugin binary
// through the host infrastructure (host.Launch / host.Run), validating the full
// host-driven pipeline end-to-end.
//
// Baseline comparison (scope caveat): the recorded baseline pins the analyzer's
// OWN precision/recall numbers against the labeled corpus, regenerated
// deliberately to avoid unpinned drift (Red Team #13). govulncheck itself is
// NOT run and its findings are NOT compared — only GovulncheckVersion and
// DBDigest are recorded as provenance metadata. A true side-by-side
// FP-suppression-vs-govulncheck comparison is a roadmap item, not implemented here.
package corpus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/host"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// CorpusCase defines a single labeled corpus entry.
type CorpusCase struct {
	// Name is a short human-readable identifier (e.g. "reachable-cve").
	Name string
	// ModuleDir is the path to the fixture module root (absolute or relative to
	// the testdata/corpus/ directory inside the repo).
	ModuleDir string
	// AdvisoryID is the advisory to check in this module.
	AdvisoryID string
	// Expected is the labeled expected outcome.
	Expected Label
	// SnapshotDir is the path to the advisory snapshot directory for this case.
	// All cases in a run normally share one snapshot (set via RunOptions).
	SnapshotDir string
	// Entrypoints are the go/packages patterns for entry points.
	// Empty = default ("." — let the engine auto-detect main vs library).
	Entrypoints []string
}

// RunOptions configures a harness run.
type RunOptions struct {
	// SnapshotDir is the shared advisory snapshot directory for all cases.
	// Individual cases may override via CorpusCase.SnapshotDir.
	SnapshotDir string
	// PluginBinary is the path to the compiled go-reachability plugin binary.
	// If empty the harness builds it from source into a temp directory.
	PluginBinary string
	// GovulncheckVersion is the pinned govulncheck version recorded in metrics.
	// The harness does NOT run govulncheck live; this is metadata only.
	GovulncheckVersion string
	// SkipPluginBuild skips compiling the plugin binary; PluginBinary must be set.
	SkipPluginBuild bool
}

// Run executes the corpus cases via the host → plugin pipeline and returns
// aggregated Metrics. Each case runs through host.Run so the full end-to-end
// path (advisory resolution → AnalyzeRequest → plugin subprocess → findings) is
// exercised, not just the engine in-process.
func Run(ctx context.Context, cases []CorpusCase, opts RunOptions) (*Metrics, error) {
	m := &Metrics{
		GovulncheckVersion: opts.GovulncheckVersion,
	}

	// Resolve snapshot digest for the metrics report.
	snapshotDir := opts.SnapshotDir
	if snapshotDir != "" {
		if dig, err := readSnapshotDigest(snapshotDir); err == nil {
			m.DBDigest = dig
		}
	}

	// Build or locate the plugin binary — only needed when there are cases to run.
	pluginBin := opts.PluginBinary
	pluginHash := ""

	if len(cases) > 0 {
		if pluginBin == "" && !opts.SkipPluginBuild {
			var err error
			pluginBin, err = buildPluginBinary(ctx)
			if err != nil {
				return nil, fmt.Errorf("corpus: build plugin binary: %w", err)
			}
		}
		if pluginBin == "" {
			return nil, fmt.Errorf("corpus: no plugin binary available (set PluginBinary or allow build)")
		}

		// Compute the hash of the plugin binary for registry registration.
		var err error
		pluginHash, err = host.SHA256OfFile(pluginBin)
		if err != nil {
			return nil, fmt.Errorf("corpus: hash plugin binary: %w", err)
		}
	}

	for _, c := range cases {
		if ctx.Err() != nil {
			return m, ctx.Err()
		}

		snapDir := c.SnapshotDir
		if snapDir == "" {
			snapDir = snapshotDir
		}

		conf, runErr := runCase(ctx, c, snapDir, pluginBin, pluginHash)
		if runErr != nil {
			// A hard error means the case could not be evaluated — UNKNOWN (conservative).
			conf = commit0v1.Confidence_CONFIDENCE_UNKNOWN
		}

		m.Evaluate(c.Name, c.AdvisoryID, c.Expected, conf)
	}

	return m, nil
}

// runCase runs the engine on a single corpus case via the host and returns the
// confidence of the first finding for c.AdvisoryID.
func runCase(
	ctx context.Context,
	c CorpusCase,
	snapshotDir, pluginBin, pluginHash string,
) (commit0v1.Confidence, error) {
	modDir := c.ModuleDir
	if !filepath.IsAbs(modDir) {
		modDir = filepath.Join(corpusRoot(), modDir)
	}

	// Query the advisory from the pinned snapshot.
	advs, err := queryAdvisory(ctx, c.AdvisoryID, snapshotDir)
	if err != nil {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			fmt.Errorf("corpus case %q: advisory query: %w", c.Name, err)
	}

	req := &commit0v1.AnalyzeRequest{
		ModuleRoot:  modDir,
		Entrypoints: c.Entrypoints,
		Advisories:  advs,
	}

	// Register the plugin in a fresh registry.
	reg := host.NewRegistry()
	manifest := &host.Manifest{
		Name:      "go-reachability",
		ExecPath:  pluginBin,
		Pillar:    "sca",
		Languages: []string{"go"},
		SHA256:    pluginHash,
	}
	if err := reg.Add(manifest); err != nil {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			fmt.Errorf("corpus case %q: registry.Add: %w", c.Name, err)
	}

	results, err := host.Run(ctx, reg, req, host.RunOptions{})
	if err != nil {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			fmt.Errorf("corpus case %q: host.Run: %w", c.Name, err)
	}

	// Scan all plugin results for the advisory.
	for _, pr := range results {
		if pr.Err != nil {
			// Plugin error → UNKNOWN (fail-closed).
			return commit0v1.Confidence_CONFIDENCE_UNKNOWN, pr.Err
		}
		for _, f := range pr.Findings {
			if f.GetAdvisory().GetId() == c.AdvisoryID {
				return f.GetConfidence(), nil
			}
		}
	}

	// No finding at all → UNKNOWN (conservative).
	return commit0v1.Confidence_CONFIDENCE_UNKNOWN, nil
}

// queryAdvisory fetches an advisory from the pinned snapshot and returns a proto slice.
func queryAdvisory(ctx context.Context, advisoryID, snapshotDir string) ([]*commit0v1.Advisory, error) {
	if snapshotDir == "" {
		return nil, fmt.Errorf("no snapshot directory configured")
	}

	cache := advisory.NewCache(advisory.CacheConfig{
		SnapshotPin:      snapshotDir,
		Offline:          true,
		StalenessWarning: 365 * 24 * 3600 * 1e9, // 1 year — pinned test snapshots don't expire
	})

	advs, err := cache.Get(ctx, advisory.Package{Ecosystem: advisory.EcosystemGo, Name: "example.com/corpusvulnlib"}, "v0.0.0")
	var staleWarn *advisory.StalenessWarningError
	if err != nil && !errors.As(err, &staleWarn) {
		return nil, fmt.Errorf("advisory query: %w", err)
	}
	if staleWarn != nil {
		advs = staleWarn.Advisories
	}

	var result []*commit0v1.Advisory
	for i := range advs {
		if advs[i].ID == advisoryID {
			result = append(result, advs[i].ToProto())
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("advisory %q not found in snapshot %q", advisoryID, snapshotDir)
	}
	return result, nil
}

// buildPluginBinary compiles the go-reachability plugin into a temp directory
// and returns the path to the resulting binary.
func buildPluginBinary(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "anst-plugin-*")
	if err != nil {
		return "", fmt.Errorf("mktemp: %w", err)
	}
	binPath := filepath.Join(tmpDir, "go-reachability")

	pluginPkg := "github.com/commit0-dev/commit0-analyzer/plugins/go-reachability"
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, pluginPkg)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build %s: %w\n%s", pluginPkg, err, out)
	}
	return binPath, nil
}

// BaselineRecord is the pinned baseline metrics file format.
// It is written once (via --regen-baseline) and compared on every run.
type BaselineRecord struct {
	// GovulncheckVersion is the govulncheck version used when this baseline was recorded.
	GovulncheckVersion string `json:"govulncheck_version"`
	// DBDigest is the advisory snapshot digest at baseline-record time.
	DBDigest string `json:"db_digest"`
	// Precision/Recall/FPSuppression are the reference numbers.
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	FPSuppression float64 `json:"fp_suppression"`
	// UnknownViolations is the reference count (must stay 0).
	UnknownViolations int `json:"unknown_violations"`
}

// WriteBaseline serialises m into a BaselineRecord at path.
func WriteBaseline(path string, m *Metrics) error {
	rec := BaselineRecord{
		GovulncheckVersion: m.GovulncheckVersion,
		DBDigest:           m.DBDigest,
		Precision:          m.Precision(),
		Recall:             m.Recall(),
		FPSuppression:      m.FPSuppressionRate(),
		UnknownViolations:  m.UnknownViolations,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadBaseline reads a BaselineRecord from path.
func ReadBaseline(path string) (*BaselineRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec BaselineRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// readSnapshotDigest extracts the content_digest from a snapshot manifest file.
func readSnapshotDigest(snapshotDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(snapshotDir, advisory.ManifestFilename))
	if err != nil {
		return "", err
	}
	var m struct {
		ContentDigest string `json:"content_digest"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", err
	}
	return m.ContentDigest, nil
}

// corpusRoot returns the absolute path to testdata/corpus/ by walking up from
// this source file's location.
func corpusRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		wd, _ := os.Getwd()
		return wd
	}
	// This file is at internal/corpus/harness.go.
	// Repo root is two directories up; testdata/corpus is under repo root.
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(repoRoot, "testdata", "corpus")
}
