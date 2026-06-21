package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
	"github.com/ducthinh993/anst-analyzer/internal/host"
	"github.com/ducthinh993/anst-analyzer/internal/policy"
	"github.com/ducthinh993/anst-analyzer/internal/render"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// scanFlags holds all flag values for the scan sub-command.
type scanFlags struct {
	format     string
	policyFile string
	dbSnapshot string
	offline    bool
	failOn     string
	goos       string
	goarch     string
	tags       string
	pluginBin  string
}

// newScanCmd returns the cobra sub-command for `anst-analyzer scan`.
func newScanCmd() *cobra.Command {
	var flags scanFlags

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a Go module for reachable dependency vulnerabilities",
		Long: `Run the full reachability SCA pipeline against a Go module:

  1. Resolve module dependencies from go.mod/go.sum.
  2. Query the advisory service for each dependency.
  3. Build an AnalyzeRequest with advisory data and build config.
  4. Drive the go-reachability plugin through the host subprocess transport.
  5. Render findings in the requested format (sarif|json|table).
  6. Evaluate the policy gate and exit with the appropriate code.

PATH is the module root to scan. Defaults to the current directory.

Exit codes:
  0  All findings within policy thresholds.
  1  One or more findings exceeded the configured threshold.
  3  Operational error (plugin crash, build failure, missing deps).`,
		Args: cobra.MaximumNArgs(1),
		// RunE returns an error only for operational failures (exit 3).
		// Policy gate failures (exit 1) are signalled via os.Exit from within runScan.
		RunE: func(cmd *cobra.Command, args []string) error {
			moduleRoot := "."
			if len(args) > 0 {
				moduleRoot = args[0]
			}
			abs, err := filepath.Abs(moduleRoot)
			if err != nil {
				return fmt.Errorf("resolve module root %q: %w", moduleRoot, err)
			}

			code := runScan(cmd.Context(), abs, flags)
			if code != policy.ExitPass {
				os.Exit(code)
			}
			return nil
		},
	}

	fs := cmd.Flags()
	fs.StringVar(&flags.format, "format", "sarif", "output format: sarif|json|table")
	fs.StringVar(&flags.policyFile, "policy", "", "path to a YAML policy file (optional)")
	fs.StringVar(&flags.dbSnapshot, "db-snapshot", "", "path to a pinned advisory snapshot directory")
	fs.BoolVar(&flags.offline, "offline", false, "disable network access; requires --db-snapshot")
	fs.StringVar(&flags.failOn, "fail-on", "high", "minimum severity to fail: low|medium|high|critical")
	fs.StringVar(&flags.goos, "goos", "", "GOOS override for build config")
	fs.StringVar(&flags.goarch, "goarch", "", "GOARCH override for build config")
	fs.StringVar(&flags.tags, "tags", "", "comma-separated build tags")
	fs.StringVar(&flags.pluginBin, "plugin-binary", "", "path to pre-built go-reachability plugin binary (skip build)")

	return cmd
}

// runScan executes the full scan pipeline and returns the exit code.
// It never panics; panics are caught by policy.RunWithRecovery in main.
func runScan(ctx context.Context, moduleRoot string, flags scanFlags) int {
	// ── 1. Validate module root ───────────────────────────────────────────────
	goModPath := filepath.Join(moduleRoot, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: %s does not contain a go.mod file: %v\n",
			moduleRoot, err)
		return policy.ExitOperationalError
	}

	// ── 2. Load advisory cache ────────────────────────────────────────────────
	snapshotDir := flags.dbSnapshot
	if flags.offline && snapshotDir == "" {
		fmt.Fprintln(os.Stderr, "anst-analyzer scan: --offline requires --db-snapshot")
		return policy.ExitOperationalError
	}
	if snapshotDir == "" {
		// Default to a user cache directory when no snapshot is pinned.
		// In offline mode this will fail clearly if the cache is absent.
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: cannot locate user cache dir: %v\n", err)
			return policy.ExitOperationalError
		}
		snapshotDir = filepath.Join(cacheDir, "anst-analyzer", "vuln-db")
	}

	// ── 3. Resolve module dependencies ────────────────────────────────────────
	deps, err := listModDeps(ctx, moduleRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: resolve deps: %v\n", err)
		return policy.ExitOperationalError
	}

	// ── 4. Query advisory service for each dep ────────────────────────────────
	cache := advisory.NewCache(advisory.CacheConfig{
		SnapshotPin:      snapshotDir,
		Offline:          flags.offline,
		StalenessWarning: advisory.DefaultStalenessWarning,
	})

	var protoAdvs []*anstv1.Advisory
	incomplete := false
	for _, dep := range deps {
		advs, err := cache.Get(ctx, dep.Path, dep.Version)
		var staleWarn *advisory.StalenessWarningError
		if err != nil && !errors.As(err, &staleWarn) {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: advisory query %s@%s: %v\n",
				dep.Path, dep.Version, err)
			incomplete = true
			continue
		}
		if staleWarn != nil {
			fmt.Fprintf(os.Stderr, "warning: %s\n", staleWarn.Warning)
			advs = staleWarn.Advisories
		}
		for i := range advs {
			protoAdvs = append(protoAdvs, advs[i].ToProto())
		}
	}

	// ── 5. Build AnalyzeRequest ───────────────────────────────────────────────
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: moduleRoot,
		Advisories: protoAdvs,
		BuildConfig: &anstv1.BuildConfig{
			Goos:   flags.goos,
			Goarch: flags.goarch,
		},
	}
	if flags.tags != "" {
		req.BuildConfig.Tags = strings.Split(flags.tags, ",")
	}

	// ── 6. Locate / build the plugin binary ───────────────────────────────────
	pluginBin := flags.pluginBin
	if pluginBin == "" {
		var buildErr error
		pluginBin, buildErr = buildPlugin(ctx)
		if buildErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: build plugin: %v\n", buildErr)
			return policy.ExitOperationalError
		}
	}
	pluginBin, err = filepath.Abs(pluginBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: resolve plugin binary path: %v\n", err)
		return policy.ExitOperationalError
	}

	pluginHash, err := host.SHA256OfFile(pluginBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: hash plugin binary: %v\n", err)
		return policy.ExitOperationalError
	}

	// ── 7. Register plugin and run through host ───────────────────────────────
	reg := host.NewRegistry()
	if addErr := reg.Add(&host.Manifest{
		Name:      "go-reachability",
		ExecPath:  pluginBin,
		Pillar:    "sca",
		Languages: []string{"go"},
		SHA256:    pluginHash,
	}); addErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: register plugin: %v\n", addErr)
		return policy.ExitOperationalError
	}

	results, runErr := host.Run(ctx, reg, req, host.RunOptions{})
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: host.Run: %v\n", runErr)
		return policy.ExitOperationalError
	}

	// Collect all findings and detect plugin errors.
	var findings []*anstv1.Finding
	for _, pr := range results {
		if pr.Err != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: plugin %s error: %v\n",
				pr.Manifest.Name, pr.Err)
			incomplete = true
		}
		findings = append(findings, pr.Findings...)
	}

	// ── 7b. Stamp default severity ────────────────────────────────────────────
	// The engine does not know vulnerability severity (it only knows call-graph
	// reachability). When a finding has SEVERITY_UNSPECIFIED and the confidence
	// is SYMBOL_REACHABLE or PACKAGE_REACHABLE, stamp HIGH as a conservative
	// default so the policy gate can function even when the advisory source does
	// not carry a severity field. UNKNOWN findings keep UNSPECIFIED — their
	// risk is surfaced by the reachable-only gate, not the severity threshold.
	stampDefaultSeverity(findings)

	// ── 8. Render output ──────────────────────────────────────────────────────
	if renderErr := renderFindings(flags.format, findings); renderErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: render: %v\n", renderErr)
		return policy.ExitOperationalError
	}

	// ── 9. Evaluate policy gate ───────────────────────────────────────────────
	pol, polErr := loadPolicyFromFlags(flags)
	if polErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: policy: %v\n", polErr)
		return policy.ExitOperationalError
	}

	return pol.EvaluateWithFlags(findings, policy.EvalFlags{Incomplete: incomplete})
}

// stampDefaultSeverity conservatively stamps SEVERITY_HIGH onto findings that
// are reachable (SYMBOL_REACHABLE or PACKAGE_REACHABLE) but carry no severity.
// This ensures the policy gate works when the advisory source does not provide
// a severity field (e.g. the corpus test snapshot and older Go vuln DB entries).
//
// Rationale: a reachable vulnerability with unknown severity is conservatively
// HIGH rather than UNSPECIFIED (which would never trip the gate). Callers that
// have advisory-level CVSS scores should populate Finding.Severity from those
// scores instead of relying on this default.
func stampDefaultSeverity(findings []*anstv1.Finding) {
	for _, f := range findings {
		if f.GetSeverity() != anstv1.Severity_SEVERITY_UNSPECIFIED {
			continue
		}
		switch f.GetConfidence() {
		case anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
			f.Severity = anstv1.Severity_SEVERITY_HIGH
		}
		// UNKNOWN and NOT_REACHABLE keep SEVERITY_UNSPECIFIED.
	}
}

// renderFindings writes findings to stdout in the requested format.
func renderFindings(format string, findings []*anstv1.Finding) error {
	switch strings.ToLower(format) {
	case "sarif":
		data, err := render.ToSARIF(findings)
		if err != nil {
			return fmt.Errorf("SARIF render: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "json":
		data, err := render.ToJSON(findings)
		if err != nil {
			return fmt.Errorf("JSON render: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "table":
		os.Stdout.Write(render.ToTable(findings))
		return nil
	default:
		return fmt.Errorf("unknown format %q: must be sarif|json|table", format)
	}
}

// loadPolicyFromFlags loads a Policy from a file or synthesises one from flags.
func loadPolicyFromFlags(flags scanFlags) (*policy.Policy, error) {
	if flags.policyFile != "" {
		data, err := os.ReadFile(flags.policyFile)
		if err != nil {
			return nil, fmt.Errorf("read policy file %q: %w", flags.policyFile, err)
		}
		return policy.LoadPolicy(data)
	}

	// Synthesise a minimal policy from --fail-on flag.
	yamlSrc := fmt.Sprintf("fail-on: %s\n", flags.failOn)
	return policy.LoadPolicy([]byte(yamlSrc))
}

// modDep is a resolved module dependency (path + version).
type modDep struct {
	Path    string
	Version string
}

// listModDeps uses `go list -m -json all` to enumerate module dependencies.
// It requires the module to be buildable (no broken replace directives).
// On failure it returns a clear error — callers must treat this as UNKNOWN,
// not as "no deps found" (Red Team #4: non-compiling → UNKNOWN).
func listModDeps(ctx context.Context, moduleRoot string) ([]modDep, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = moduleRoot
	// Propagate GOPATH, GOMODCACHE etc. from the parent environment.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("go list -m all: %w\n%s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("go list -m all: %w", err)
	}

	return parseGoListJSON(out), nil
}

// parseGoListJSON parses the concatenated JSON objects from `go list -m -json all`.
// Each module is a separate JSON object (not a JSON array) so we decode sequentially.
func parseGoListJSON(data []byte) []modDep {
	// `go list -m -json all` emits one JSON object per line-block, terminated by
	// newlines. We use a simple scanner: each top-level '{...}' block is one module.
	var deps []modDep
	s := string(data)
	for {
		start := strings.Index(s, "{")
		if start < 0 {
			break
		}
		end := findMatchingBrace(s, start)
		if end < 0 {
			break
		}
		block := s[start : end+1]
		s = s[end+1:]

		dep := parseModuleBlock(block)
		if dep.Path != "" && dep.Version != "" {
			deps = append(deps, dep)
		}
	}
	return deps
}

// findMatchingBrace returns the index of the closing '}' that matches the '{'
// at openIdx in s, counting depth. Returns -1 if not found.
func findMatchingBrace(s string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseModuleBlock extracts Path and Version from a single `go list -m -json` block.
// We parse manually to avoid importing encoding/json for a simple key extraction.
func parseModuleBlock(block string) modDep {
	return modDep{
		Path:    extractJSONStringField(block, "Path"),
		Version: extractJSONStringField(block, "Version"),
	}
}

// extractJSONStringField extracts a string JSON field value by key name.
func extractJSONStringField(s, key string) string {
	search := `"` + key + `"`
	idx := strings.Index(s, search)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(search):]
	// Find colon.
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	// Trim whitespace.
	rest = strings.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	// Find closing quote (simple scan — values here are module paths and semver).
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// buildPlugin compiles the go-reachability plugin into a temp directory.
// The binary is placed at a stable path within the OS temp dir to allow
// callers to cache it across repeated scan invocations in the same process.
func buildPlugin(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "anst-plugin-*")
	if err != nil {
		return "", fmt.Errorf("mktemp: %w", err)
	}
	binPath := filepath.Join(tmpDir, "go-reachability")

	const pluginPkg = "github.com/ducthinh993/anst-analyzer/plugins/go-reachability"
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, pluginPkg)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build %s: %w\n%s", pluginPkg, err, out)
	}
	return binPath, nil
}
