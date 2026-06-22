package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	format         string
	policyFile     string
	dbSnapshot     string
	offline        bool
	update         bool
	failOn         string
	goos           string
	goarch         string
	tags           string
	pluginBin      string
	jsPluginBin    string // path to pre-built js-reachability plugin binary (skip build)
	source         string // comma-separated source names; default "go-vuln-db,osv"
	sourceExplicit bool   // true when --source was explicitly set by the user
	language       string // "auto"|"go"|"js"; default "auto"
}

// ecosystems records which ecosystem marker files were detected in a module root.
type ecosystems struct {
	hasGo bool // go.mod present
	hasJS bool // package.json present
}

// detectEcosystems checks the module root for go.mod and package.json.
func detectEcosystems(moduleRoot string) ecosystems {
	var e ecosystems
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.mod")); err == nil {
		e.hasGo = true
	}
	if _, err := os.Stat(filepath.Join(moduleRoot, "package.json")); err == nil {
		e.hasJS = true
	}
	return e
}

// resolveLanguage applies the --language override to the detected ecosystems and
// returns (hasGo, hasJS, error). "auto" defers to detection; "go" forces Go only;
// "js" forces JS only. Any other value is an operational error.
func resolveLanguage(lang string, e ecosystems) (hasGo, hasJS bool, err error) {
	switch lang {
	case "go":
		return true, false, nil
	case "js":
		return false, true, nil
	case "auto":
		return e.hasGo, e.hasJS, nil
	default:
		return false, false, fmt.Errorf("unknown --language value %q: must be one of auto|go|js", lang)
	}
}

// sourceAliases maps user-facing --source flag tokens to canonical advisory
// source names (the SourceXxx constants in the advisory package).
// "go-vuln-db" is both the flag token and the canonical name (SourceGoVulnDB).
// "osv" is the short flag token; its canonical name is "osv.dev" (SourceOSV).
// The full canonical name "osv.dev" is also accepted for forward compatibility.
var sourceAliases = map[string]string{
	"go-vuln-db": advisory.SourceGoVulnDB, // SourceGoVulnDB = "go-vuln-db"
	"osv":        advisory.SourceOSV,      // short alias for "osv.dev"
	"osv.dev":    advisory.SourceOSV,      // SourceOSV = "osv.dev" (full canonical)
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

			flags.sourceExplicit = cmd.Flags().Changed("source")
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
	fs.StringVar(&flags.dbSnapshot, "db-snapshot", "", "path to a pinned advisory snapshot directory (read-only; never fetched)")
	fs.BoolVar(&flags.offline, "offline", false, "disable network access; use existing cache or --db-snapshot")
	fs.BoolVar(&flags.update, "update", false, "force re-fetch of advisory data even when cached version is current")
	fs.StringVar(&flags.failOn, "fail-on", "high", "minimum severity to fail: low|medium|high|critical")
	fs.StringVar(&flags.goos, "goos", "", "GOOS override for build config")
	fs.StringVar(&flags.goarch, "goarch", "", "GOARCH override for build config")
	fs.StringVar(&flags.tags, "tags", "", "comma-separated build tags")
	fs.StringVar(&flags.pluginBin, "plugin-binary", "", "path to pre-built go-reachability plugin binary (skip build)")
	fs.StringVar(&flags.jsPluginBin, "js-plugin-binary", "", "path to pre-built js-reachability plugin binary (skip build)")
	fs.StringVar(&flags.source, "source", "go-vuln-db,osv",
		"comma-separated advisory sources to query: go-vuln-db, osv (default: both)")
	fs.StringVar(&flags.language, "language", "auto",
		"ecosystem to scan: go|js|auto (default: auto — detected from go.mod / package.json)")

	return cmd
}

// runScan executes the full scan pipeline and returns the exit code.
// It never panics; panics are caught by policy.RunWithRecovery in main.
func runScan(ctx context.Context, moduleRoot string, flags scanFlags) int {
	// ── 1. Detect ecosystems and validate module root ────────────────────────
	eco := detectEcosystems(moduleRoot)
	scanGo, scanJS, langErr := resolveLanguage(flags.language, eco)
	if langErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: %v\n", langErr)
		return policy.ExitOperationalError
	}

	if !scanGo && !scanJS {
		fmt.Fprintf(os.Stderr,
			"anst-analyzer scan: %s contains neither go.mod nor package.json; nothing to scan\n",
			moduleRoot)
		return policy.ExitOperationalError
	}

	// The Go advisory pipeline (steps 3–5) requires go.mod to resolve deps.
	// Skip it when only the JS ecosystem was selected.
	if scanGo {
		goModPath := filepath.Join(moduleRoot, "go.mod")
		if _, err := os.Stat(goModPath); err != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: --language go selected but %s does not contain a go.mod file: %v\n",
				moduleRoot, err)
			return policy.ExitOperationalError
		}
	}

	// ── 2. Validate --source flag ─────────────────────────────────────────────
	selectedSources, sourceErr := parseSourceFlag(flags.source)
	if sourceErr != nil {
		fmt.Fprintf(os.Stderr, "anst-analyzer scan: --source: %v\n", sourceErr)
		return policy.ExitOperationalError
	}

	// ── 3. Resolve module dependencies (Go only) ─────────────────────────────
	var deps []modDep
	if scanGo {
		var depsErr error
		deps, depsErr = listModDeps(ctx, moduleRoot)
		if depsErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: resolve deps: %v\n", depsErr)
			return policy.ExitOperationalError
		}
	}

	// ── 4. Build advisory sources and refresh (Go only) ──────────────────────
	//
	// Each enabled source is cache-backed (Go-DB via Cache; OSV via
	// OSVBundleSource). Both honour --offline (no Refresh) and --db-snapshot
	// (Go-DB snapshot pin; OSV falls back to its existing cache dir offline).
	//
	// Refresh is called once per enabled source before the per-dep query loop so
	// that Query calls are network-free. A secondary-source Refresh failure → warn
	// + incomplete (never abort); Go-DB Refresh failure → abort (primary source).
	//
	// Three advisory-data modes:
	//   a) --db-snapshot <dir>  → pin Go-DB to that dir (read-only, never fetched).
	//   b) --offline            → read existing caches; no network.
	//   c) default (online)     → refresh both caches from upstream.
	incomplete := false
	var namedSources []advisory.NamedSource
	var protoAdvs []*anstv1.Advisory
	sourcesByID := map[string][]string{}

	if scanGo {
		cacheDir, cacheErr := os.UserCacheDir()
		if cacheErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
			return policy.ExitOperationalError
		}

		// ── 4a. Go vuln DB source ─────────────────────────────────────────────────
		if selectedSources[advisory.SourceGoVulnDB] {
			var cacheCfg advisory.CacheConfig
			cacheCfg.StalenessWarning = advisory.DefaultStalenessWarning

			if flags.dbSnapshot != "" {
				// Pinned snapshot: read-only, manifest-verified, never fetched.
				cacheCfg.SnapshotPin = flags.dbSnapshot
				cacheCfg.Offline = true
			} else {
				cacheCfg.Dir = filepath.Join(cacheDir, "anst-analyzer", "vuln-db")
				cacheCfg.Offline = flags.offline
				if !flags.offline {
					// ANST_VULN_DB_URL overrides the default vuln.go.dev base URL (test seam).
					f := advisory.NewFetcher()
					if override := os.Getenv("ANST_VULN_DB_URL"); override != "" {
						f.BaseURL = override
					}
					cacheCfg.Fetcher = f
					cacheCfg.ForceUpdate = flags.update
				}
			}

			goCache := advisory.NewCache(cacheCfg)

			// Refresh Go-DB (no-op for pinned/offline/no-fetcher).
			// Failure handling ("unknown ≠ safe"):
			//   - RefreshFallbackWarning: probe failed but valid cache exists → warn + incomplete.
			//   - Other error (no cache + fetch failed) → abort (primary source).
			if refreshErr := goCache.Refresh(ctx, modPaths(deps)); refreshErr != nil {
				var fallback *advisory.RefreshFallbackWarning
				if errors.As(refreshErr, &fallback) {
					fmt.Fprintf(os.Stderr, "warning: %s\n", fallback.Warning)
					incomplete = true
				} else {
					fmt.Fprintf(os.Stderr, "anst-analyzer scan: advisory refresh: %v\n", refreshErr)
					return policy.ExitOperationalError
				}
			}

			namedSources = append(namedSources, advisory.NamedSource{
				Name: advisory.SourceGoVulnDB,
				S:    goCache,
			})
		}

		// ── 4b. OSV bundle source ─────────────────────────────────────────────────
		if selectedSources[advisory.SourceOSV] {
			osvCacheDir := filepath.Join(cacheDir, "anst-analyzer", "osv")

			osvSrc := advisory.NewOSVBundleSource(osvCacheDir)
			// ANST_OSV_DB_URL overrides the default OSV GCS base URL (test seam).
			// BaseURL is an exported field on OSVBundleSource for exactly this purpose.
			if override := os.Getenv("ANST_OSV_DB_URL"); override != "" {
				osvSrc.BaseURL = override
			}
			osvSrc.ForceUpdate = flags.update

			// Refresh OSV (secondary source): failure → warn + incomplete, not abort.
			// --offline and --db-snapshot skip the Refresh; OSV falls back to its
			// existing cache dir if populated, or returns empty (nil,nil) if not.
			// A missing OSV cache in offline mode is recorded as incomplete (not silent).
			addOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := osvSrc.Refresh(ctx, advisory.EcosystemGo); refreshErr != nil {
					fmt.Fprintf(os.Stderr, "warning: OSV source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addOSV = false
				}
			} else if flags.offline || flags.dbSnapshot != "" {
				// Offline/snapshot mode: check whether the OSV cache exists.
				// If missing:
				//   - When --source was explicitly set to include osv → warn + incomplete
				//     ("unknown ≠ safe": the user specifically requested OSV coverage).
				//   - When --source was not explicitly set (OSV is the default) → silently
				//     skip. This preserves backward compat for callers using --db-snapshot
				//     (a Go-DB-only mode) who never populated an OSV cache.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemGo) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV cache not populated at %s (run without --offline to fetch); OSV source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemGo))
						incomplete = true
					}
					addOSV = false
				}
			}

			if addOSV {
				namedSources = append(namedSources, advisory.NamedSource{
					Name: advisory.SourceOSV,
					S:    osvSrc,
				})
			}
		}

		// ── 5. Query advisory sources for each Go dep ─────────────────────────────
		multiSrc := advisory.NewMultiSource(namedSources...)

		// sourcesByID records the merged source attribution for each advisory so it
		// can be stamped onto findings (the Finding carries only an advisory ref, not
		// the advisory's Sources, so we propagate it here for visible attribution).
		for _, dep := range deps {
			pkg := advisory.Package{Ecosystem: advisory.EcosystemGo, Name: dep.Path}
			advs, queryErr := multiSrc.Query(ctx, pkg, dep.Version)

			// A *SourcesIncompleteError means one or more sources failed for this dep.
			// Warn + mark incomplete, but still gate on the advisories that succeeded.
			var srcIncomplete *advisory.SourcesIncompleteError
			if queryErr != nil && errors.As(queryErr, &srcIncomplete) {
				for i, name := range srcIncomplete.FailedSources {
					fmt.Fprintf(os.Stderr, "warning: advisory source %q failed for %s@%s: %v\n",
						name, dep.Path, dep.Version, srcIncomplete.Errors[i])
				}
				incomplete = true
			} else if queryErr != nil {
				// A non-StalenessWarning, non-SourcesIncomplete error (e.g. cache corrupt).
				var staleWarn *advisory.StalenessWarningError
				if errors.As(queryErr, &staleWarn) {
					fmt.Fprintf(os.Stderr, "warning: %s\n", staleWarn.Warning)
					advs = staleWarn.Advisories
				} else {
					fmt.Fprintf(os.Stderr, "anst-analyzer scan: advisory query %s@%s: %v\n",
						dep.Path, dep.Version, queryErr)
					incomplete = true
					continue
				}
			}

			for i := range advs {
				protoAdvs = append(protoAdvs, advs[i].ToProto())
				if advs[i].ID != "" {
					sourcesByID[advs[i].ID] = advs[i].Sources
				}
			}
		}
	}

	// ── 5b. npm advisory resolution (JS ecosystem) ───────────────────────────
	//
	// When JS is in scope, obtain the lockfile-resolved dep list from the JS
	// plugin via --list-deps (a fast local-only subprocess). Then query advisories
	// for each (workspace, pkg, version) through the same MultiSource / OSV bundle
	// plumbing as the Go path. Advisory resolution is centralized here in the CLI
	// so that --source, --offline, --db-snapshot, and --update all apply uniformly.
	//
	// go-vuln-db source returns (nil,nil) for npm (it covers only "Go") —
	// confirmed by goVulnDBClient.Query checking pkg.Ecosystem != EcosystemGo.
	// OSV source uses the "npm" bundle (npm/all.zip from the OSV GCS bucket).
	if scanJS {
		// Resolve the JS plugin binary path (same as the manifest lookup used later
		// for registering the gRPC plugin, but needed now for --list-deps).
		jsPluginBin := flags.jsPluginBin
		if jsPluginBin == "" {
			if d := jsDistDir(); d != "" {
				jsPluginBin = filepath.Join(d, "anst-js-reachability")
			}
		}
		if jsPluginBin == "" {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: js plugin not available for --list-deps: cannot locate dist directory\n")
			return policy.ExitOperationalError
		}
		if _, statErr := os.Stat(jsPluginBin); statErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: js plugin binary not found at %s: %v\n", jsPluginBin, statErr)
			return policy.ExitOperationalError
		}

		// Get the dep list from the project model.
		npmDeps, modelIncomplete, listErr := listNPMDeps(ctx, jsPluginBin, moduleRoot)
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: list npm deps: %v\n", listErr)
			return policy.ExitOperationalError
		}
		if modelIncomplete {
			fmt.Fprintf(os.Stderr, "warning: npm project model is incomplete (some deps could not be resolved); scan marked incomplete\n")
			incomplete = true
		}

		// OSV is the only source with npm coverage. go-vuln-db covers only the Go
		// ecosystem and returns no advisories for npm. When JS deps are present but
		// no npm-capable source is selected, the scan has zero advisory coverage for
		// those deps — unknown ≠ safe, so warn and mark incomplete.
		npmCapableSourceSelected := selectedSources[advisory.SourceOSV]
		if len(npmDeps) > 0 && !npmCapableSourceSelected {
			fmt.Fprintf(os.Stderr,
				"warning: JS npm deps found but no npm-capable advisory source is selected "+
					"(osv.dev covers npm; go-vuln-db does not); "+
					"npm packages were not checked for vulnerabilities; scan marked incomplete\n")
			incomplete = true
		}

		if len(npmDeps) > 0 && npmCapableSourceSelected {
			// Build an OSV source for npm; reuse the same cacheDir as the Go OSV path.
			cacheDir, cacheErr := os.UserCacheDir()
			if cacheErr != nil {
				fmt.Fprintf(os.Stderr, "anst-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
				return policy.ExitOperationalError
			}
			osvCacheDir := filepath.Join(cacheDir, "anst-analyzer", "osv")

			osvSrc := advisory.NewOSVBundleSource(osvCacheDir)
			if override := os.Getenv("ANST_OSV_DB_URL"); override != "" {
				osvSrc.BaseURL = override
			}
			osvSrc.ForceUpdate = flags.update

			// Refresh OSV npm bundle (secondary source → failure warns + marks incomplete).
			addNPMOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := osvSrc.Refresh(ctx, advisory.EcosystemNPM); refreshErr != nil {
					fmt.Fprintf(os.Stderr, "warning: OSV npm source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addNPMOSV = false
				}
			} else {
				// Offline/snapshot mode: check whether the npm OSV cache exists.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemNPM) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV npm cache not populated at %s (run without --offline to fetch); OSV npm source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemNPM))
						incomplete = true
					}
					addNPMOSV = false
				}
			}

			if addNPMOSV {
				npmNamedSources := []advisory.NamedSource{
					{Name: advisory.SourceOSV, S: osvSrc},
				}
				// go-vuln-db source is intentionally excluded: it returns (nil,nil) for
				// npm automatically, but we avoid the lookup overhead for clarity.
				npmMultiSrc := advisory.NewMultiSource(npmNamedSources...)

				for _, dep := range npmDeps {
					// Normalize the npm package name to lowercase to match OSV records.
					// OSV stores npm package names lowercase; lockfile names may differ.
					normalizedName := strings.ToLower(dep.Name)
					pkg := advisory.Package{Ecosystem: advisory.EcosystemNPM, Name: normalizedName}
					advs, queryErr := npmMultiSrc.Query(ctx, pkg, dep.Version)

					var srcIncomplete *advisory.SourcesIncompleteError
					if queryErr != nil && errors.As(queryErr, &srcIncomplete) {
						for i, name := range srcIncomplete.FailedSources {
							fmt.Fprintf(os.Stderr, "warning: advisory source %q failed for %s@%s (workspace %s): %v\n",
								name, dep.Name, dep.Version, dep.Workspace, srcIncomplete.Errors[i])
						}
						incomplete = true
					} else if queryErr != nil {
						var staleWarn *advisory.StalenessWarningError
						if errors.As(queryErr, &staleWarn) {
							fmt.Fprintf(os.Stderr, "warning: %s\n", staleWarn.Warning)
							advs = staleWarn.Advisories
						} else {
							fmt.Fprintf(os.Stderr, "anst-analyzer scan: advisory query %s@%s: %v\n",
								dep.Name, dep.Version, queryErr)
							incomplete = true
							continue
						}
					}

					for i := range advs {
						protoAdvs = append(protoAdvs, advs[i].ToProto())
						if advs[i].ID != "" {
							sourcesByID[advs[i].ID] = advs[i].Sources
						}
					}
				}
			}
		}
	}

	// ── 6. Build AnalyzeRequest ───────────────────────────────────────────────
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

	// ── 7. Locate / build plugins and register ────────────────────────────────
	reg := host.NewRegistry()

	if scanGo {
		pluginBin := flags.pluginBin
		if pluginBin == "" {
			var buildErr error
			pluginBin, buildErr = buildPlugin(ctx)
			if buildErr != nil {
				fmt.Fprintf(os.Stderr, "anst-analyzer scan: build plugin: %v\n", buildErr)
				return policy.ExitOperationalError
			}
		}
		var absErr error
		pluginBin, absErr = filepath.Abs(pluginBin)
		if absErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: resolve plugin binary path: %v\n", absErr)
			return policy.ExitOperationalError
		}

		pluginHash, hashErr := host.SHA256OfFile(pluginBin)
		if hashErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: hash plugin binary: %v\n", hashErr)
			return policy.ExitOperationalError
		}

		if addErr := reg.Add(&host.Manifest{
			Name:      "go-reachability",
			ExecPath:  pluginBin,
			Pillar:    "sca",
			Languages: []string{"go"},
			SHA256:    pluginHash,
		}); addErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: register go plugin: %v\n", addErr)
			return policy.ExitOperationalError
		}
	}

	if scanJS {
		m, buildErr := buildJSPluginManifest(flags.jsPluginBin)
		if buildErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: js plugin not available: %v\n", buildErr)
			return policy.ExitOperationalError
		}
		if addErr := reg.Add(m); addErr != nil {
			fmt.Fprintf(os.Stderr, "anst-analyzer scan: register js plugin: %v\n", addErr)
			return policy.ExitOperationalError
		}
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

	// ── 7c. Stamp source attribution ──────────────────────────────────────────
	// Make the multi-source merge visible: record which source(s) reported each
	// finding's advisory into properties["sources"] (e.g. "go-vuln-db,osv.dev").
	stampSources(findings, sourcesByID)

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

// stampSources records, for each finding, which advisory source(s) reported the
// underlying advisory, into properties["sources"] (e.g. "go-vuln-db,osv.dev").
// The Finding carries only an advisory reference, so without this the merged
// multi-source attribution would not be visible in JSON/SARIF/table output.
// Synthetic findings (e.g. a plugin crash, which have no advisory) are skipped.
func stampSources(findings []*anstv1.Finding, sourcesByID map[string][]string) {
	for _, f := range findings {
		if f.GetAdvisory() == nil {
			continue
		}
		srcs := sourcesByID[f.GetAdvisory().GetId()]
		if len(srcs) == 0 {
			continue
		}
		if f.Properties == nil {
			f.Properties = map[string]string{}
		}
		f.Properties["sources"] = strings.Join(srcs, ",")
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
		_, err := os.Stdout.Write(render.ToTable(findings))
		return err
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

// npmDep is a resolved npm package dependency from the JS project model.
type npmDep struct {
	Ecosystem string `json:"ecosystem"` // always "npm"
	Name      string `json:"name"`
	Version   string `json:"version"`
	Workspace string `json:"workspace"`
}

// listDepsOutput is the JSON shape emitted by the JS plugin's --list-deps mode.
type listDepsOutput struct {
	Deps       []npmDep         `json:"deps"`
	Incomplete []incompleteEntry `json:"incomplete"`
	// DeclaredDepCount is the total number of declared runtime deps across all
	// workspaces before resolution. The CLI uses this together with each entry's
	// Kind to determine whether to mark the scan incomplete.
	DeclaredDepCount int `json:"declaredDepCount"`
}

// incompleteEntry mirrors the IncompleteEntry shape from the JS plugin model.
type incompleteEntry struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	// Kind categorizes the incomplete signal. "lockfile-corrupt" is error-level
	// and always marks the scan incomplete. Other kinds are suppressed when
	// DeclaredDepCount is 0 (no runtime deps to resolve, so no real coverage gap).
	Kind string `json:"kind"`
}

// listNPMDeps execs the JS plugin binary in --list-deps mode and returns the
// resolved npm dependency list for the project rooted at moduleRoot.
// It also returns whether the project model is incomplete.
//
// The incomplete signal is kind-aware:
//   - "lockfile-corrupt" entries always mark the model incomplete — a corrupt
//     lockfile is an error regardless of how many runtime deps are declared.
//     Suppressing it when declaredDepCount=0 would produce a false-negative for
//     projects with only devDependencies and a corrupt lockfile.
//   - All other incomplete kinds are suppressed when declaredDepCount=0, because
//     a missing lockfile on a project with no declared runtime deps is not a
//     concern (there is nothing that could be unresolvable).
//
// On any subprocess or parse failure it returns an error (never silently empty).
func listNPMDeps(ctx context.Context, pluginBin, moduleRoot string) ([]npmDep, bool, error) {
	cmd := exec.CommandContext(ctx, pluginBin, "--list-deps", moduleRoot)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, fmt.Errorf("js plugin --list-deps: %w\n%s", err, exitErr.Stderr)
		}
		return nil, false, fmt.Errorf("js plugin --list-deps: %w", err)
	}

	var result listDepsOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, false, fmt.Errorf("js plugin --list-deps: parse output: %w", err)
	}

	// Determine model-level incompleteness by kind:
	//   lockfile-corrupt → always incomplete (error-level signal).
	//   all other kinds  → incomplete only when there are declared deps to resolve.
	modelIncomplete := false
	for _, entry := range result.Incomplete {
		if entry.Kind == "lockfile-corrupt" {
			modelIncomplete = true
			break
		}
	}
	if !modelIncomplete && result.DeclaredDepCount > 0 && len(result.Incomplete) > 0 {
		modelIncomplete = true
	}

	return result.Deps, modelIncomplete, nil
}

// modDep is a resolved module dependency (path + version).
type modDep struct {
	Path    string
	Version string
}

// modPaths returns just the module paths from a dep list, for use with Refresh.
func modPaths(deps []modDep) []string {
	paths := make([]string, len(deps))
	for i, d := range deps {
		paths[i] = d.Path
	}
	return paths
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

// parseSourceFlag validates and parses the --source comma list into a set of
// enabled canonical source names. Accepts both the short flag tokens (e.g. "osv")
// and the full canonical names (e.g. "osv.dev"). Returns an error when any
// token is unrecognised or the resulting set is empty.
func parseSourceFlag(flag string) (map[string]bool, error) {
	enabled := make(map[string]bool)
	for _, raw := range strings.Split(flag, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		canonical, ok := sourceAliases[token]
		if !ok {
			return nil, fmt.Errorf("unknown source %q: must be one of go-vuln-db, osv", token)
		}
		enabled[canonical] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("at least one source must be enabled; got %q", flag)
	}
	return enabled, nil
}

// osvCacheDirExists returns true when the per-ecosystem subdirectory inside
// osvRoot exists and is a directory. Used to detect an unpopulated OSV cache
// in offline mode so we can warn + mark incomplete rather than silently skip.
func osvCacheDirExists(osvRoot, ecosystem string) bool {
	info, err := os.Stat(filepath.Join(osvRoot, ecosystem))
	return err == nil && info.IsDir()
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

// jsDistDir returns the absolute path to the JS plugin's dist directory,
// resolved relative to this source file's location in the repository tree.
// At runtime, the binary is compiled and the source layout is gone, so we
// resolve relative to the executable's location instead (for installed builds).
// Tests and local development use the repo-relative path.
func jsDistDir() string {
	// Prefer the repo-relative path for development and test.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// This file is at internal/cli/scan.go; repo root is two dirs up.
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		candidate := filepath.Join(repoRoot, "plugins", "js-reachability", "dist")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to a path adjacent to the running executable (installed build).
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "plugins", "js-reachability", "dist")
}

// jsSidecarName returns the platform-specific napi sidecar filename, e.g.
// "parser.darwin-arm64.node". It mirrors the naming convention used by the
// oxc-binding package.
func jsSidecarName() string {
	return fmt.Sprintf("parser.%s-%s.node", runtime.GOOS, runtime.GOARCH)
}

// buildJSPluginManifest constructs a Manifest for the js-reachability plugin
// by locating its two-file distribution (main binary + napi sidecar) under
// plugins/js-reachability/dist/ and computing SHA-256 pins for both files.
// When overrideBin is non-empty it is used as the main binary path directly
// (the dist directory is derived from its parent). Returns an error when the
// distribution has not been built yet.
func buildJSPluginManifest(overrideBin string) (*host.Manifest, error) {
	var mainBin string
	var distDir string

	if overrideBin != "" {
		mainBin = overrideBin
		distDir = filepath.Dir(overrideBin)
	} else {
		distDir = jsDistDir()
		if distDir == "" {
			return nil, fmt.Errorf("cannot locate js-reachability dist directory")
		}
		mainBin = filepath.Join(distDir, "anst-js-reachability")
	}
	if _, err := os.Stat(mainBin); err != nil {
		return nil, fmt.Errorf("js-reachability plugin not built: %s not found (run 'make build-js-plugin'): %w", mainBin, err)
	}

	sidecarName := jsSidecarName()
	sidecarPath := filepath.Join(distDir, "oxc-binding", sidecarName)
	if _, err := os.Stat(sidecarPath); err != nil {
		return nil, fmt.Errorf("js-reachability napi sidecar not found: %s (run 'make build-js-plugin'): %w", sidecarPath, err)
	}

	mainHash, err := host.SHA256OfFile(mainBin)
	if err != nil {
		return nil, fmt.Errorf("hash js-reachability binary: %w", err)
	}

	sidecarHash, err := host.SHA256OfFile(sidecarPath)
	if err != nil {
		return nil, fmt.Errorf("hash js-reachability sidecar: %w", err)
	}

	return &host.Manifest{
		Name:      "js-reachability",
		ExecPath:  mainBin,
		Pillar:    "sca",
		Languages: []string{"js", "ts"},
		SHA256:    mainHash,
		AdditionalArtifacts: []host.ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}, nil
}
