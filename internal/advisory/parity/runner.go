//go:build parity

// This file is the live parity runner. It shells out to the built commit0-analyzer binary
// and the external comparator binaries, so it is gated behind the `parity` build
// tag to keep the default `go test` hermetic (no network, no external tools).
//
// Run it with:
//
//	go test -tags parity ./internal/advisory/parity/... -run TestParityHarness -v
//
// (the test wrapper lives in runner_parity_test.go, also tagged `parity`).
package parity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunOptions configures a live parity run.
type RunOptions struct {
	// Commit0Binary is the path to a pre-built commit0-analyzer binary under test.
	Commit0Binary string
	// ResolvePath returns the local filesystem path for a corpus entry. The
	// caller is responsible for checking out / locating each pinned repo.
	ResolvePath func(CorpusEntry) (string, error)
	// Source is the --source value passed to commit0-analyzer for the primary (full) scan
	// (default set when empty).
	Source string
	// BaselineSource is the 2-source baseline (Go-DB + OSV) used to measure the
	// coverage gain of the full source set. Defaults to "go-vuln-db,osv".
	BaselineSource string
	// FullSource is the full source set the gain is measured against. Defaults to
	// "go-vuln-db,osv,ghsa".
	FullSource string
	// Language optionally narrows commit0-analyzer to one ecosystem per corpus entry (keyed by
	// CorpusEntry.Language). Empty means commit0-analyzer auto-detects.
	Language map[string]string
	// Timeout bounds each external command.
	Timeout time.Duration
}

// Run executes the harness over the full corpus and returns a populated report.
// It never claims parity for an absent comparator: missing binaries are recorded
// in SkippedComparators. commit0-analyzer itself is required; an commit0-analyzer failure on an entry is
// surfaced as an assertion failure, never silently skipped.
func Run(ctx context.Context, opts RunOptions) (*Report, error) {
	if opts.Commit0Binary == "" {
		return nil, fmt.Errorf("parity: Commit0Binary is required")
	}
	if opts.ResolvePath == nil {
		return nil, fmt.Errorf("parity: ResolvePath is required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	if opts.BaselineSource == "" {
		opts.BaselineSource = "go-vuln-db,osv"
	}
	if opts.FullSource == "" {
		opts.FullSource = "go-vuln-db,osv,ghsa"
	}

	rep := &Report{GeneratedFrom: fmt.Sprintf("commit0-analyzer=%s corpus=%d baseline=%q full=%q", filepath.Base(opts.Commit0Binary), len(Corpus()), opts.BaselineSource, opts.FullSource)}
	skipped := map[string]string{}

	for _, entry := range Corpus() {
		path, err := opts.ResolvePath(entry)
		if err != nil {
			rep.Assertions = append(rep.Assertions, Assertion{
				Name:   "resolve/" + entry.Name,
				Passed: false,
				Detail: err.Error(),
			})
			continue
		}

		lang := opts.Language[entry.Language]

		commit0Out, commit0Code, err := runCommit0(ctx, opts, path, opts.FullSource, lang, false)
		if err != nil {
			rep.Assertions = append(rep.Assertions, Assertion{
				Name:   "commit0-analyzer-scan/" + entry.Name,
				Passed: false,
				Detail: fmt.Sprintf("commit0-analyzer scan failed (exit %d): %v", commit0Code, err),
			})
			continue
		}
		commit0Findings, perr := ParseCommit0(commit0Out)
		if perr != nil {
			rep.Assertions = append(rep.Assertions, Assertion{
				Name:   "commit0-analyzer-parse/" + entry.Name,
				Passed: false,
				Detail: perr.Error(),
			})
			continue
		}

		// Coverage gain: measure the full source set against the 2-source baseline.
		baseOut, _, baseErr := runCommit0(ctx, opts, path, opts.BaselineSource, lang, false)
		if baseErr == nil {
			if baseFindings, bperr := ParseCommit0(baseOut); bperr == nil {
				rep.CoverageGains = append(rep.CoverageGains,
					ComputeCoverageGain(entry.Name, opts.BaselineSource, opts.FullSource, baseFindings, commit0Findings))
			}
		}

		// Determinism: a second identical run must be byte-identical.
		commit0Out2, _, _ := runCommit0(ctx, opts, path, opts.FullSource, lang, false)
		rep.Assertions = append(rep.Assertions, Assertion{
			Name:   "determinism/" + entry.Name,
			Passed: Deterministic(commit0Out, commit0Out2),
			Detail: "two identical runs byte-compared",
		})

		// Fail-closed: an injected source failure must never exit 0.
		_, failCode, _ := runCommit0(ctx, opts, path, opts.FullSource, lang, true)
		rep.Assertions = append(rep.Assertions, Assertion{
			Name:   "fail-closed/" + entry.Name,
			Passed: FailClosed(failCode),
			Detail: fmt.Sprintf("injected source failure exit code = %d (must be non-zero)", failCode),
		})

		// VEX flow: every COMPLETE, proven NOT_REACHABLE finding must surface as a
		// not_affected VEX status — the empirical "known-unreachable CVE ⇒ VEX
		// not_affected" non-negotiable.
		vexOut, vexErr := runCommit0VEX(ctx, opts, path, opts.FullSource, lang)
		switch {
		case vexErr != nil:
			rep.Assertions = append(rep.Assertions, Assertion{
				Name:   "vex-not-affected/" + entry.Name,
				Passed: false,
				Detail: "commit0-analyzer --vex run failed: " + vexErr.Error(),
			})
		default:
			statuses, perr := ParseCommit0VEX(vexOut)
			if perr != nil {
				rep.Assertions = append(rep.Assertions, Assertion{
					Name:   "vex-not-affected/" + entry.Name,
					Passed: false,
					Detail: perr.Error(),
				})
			} else {
				ok, detail := VEXForUnreachable(commit0Findings, statuses)
				rep.Assertions = append(rep.Assertions, Assertion{
					Name:   "vex-not-affected/" + entry.Name,
					Passed: ok,
					Detail: detail,
				})
			}
		}

		// KEV flag + top risk tier: a corpus entry with a known-KEV dependency must
		// carry the KEV flag and the top fused-risk band — the empirical "known-KEV
		// dependency ⇒ KEV flag + top risk tier" non-negotiable.
		if entry.KnownKEVID != "" {
			ok, detail := KEVTopTier(commit0Findings, entry.KnownKEVID)
			rep.Assertions = append(rep.Assertions, Assertion{
				Name:   "kev-flag-top-tier/" + entry.Name,
				Passed: ok,
				Detail: detail,
			})
		}

		for _, compName := range entry.Comparators {
			comp, ok := ComparatorByName(compName)
			if !ok {
				continue
			}
			if !Available(comp.Binary) {
				skipped[compName] = "binary not on PATH (parity not claimed for this comparator)"
				continue
			}
			out, rerr := runComparator(ctx, opts, comp, path)
			if rerr != nil {
				// A comparator that is present but fails to run (incompatible CLI
				// version, timeout, no targets) is recorded as a skip, NOT a
				// soundness failure: parity against it simply was not measured. The
				// non-negotiable assertions are reserved for commit0-analyzer's own invariants.
				skipped[compName] = "could not run on " + entry.Name + ": " + rerr.Error()
				continue
			}
			others, perr := parseComparator(compName, out)
			if perr != nil {
				skipped[compName] = "output from " + entry.Name + " did not parse (version mismatch?): " + perr.Error()
				continue
			}
			rep.Comparisons = append(rep.Comparisons, Compare(entry.Name, compName, commit0Findings, others))
		}
	}

	for name, reason := range skipped {
		rep.SkippedComparators = append(rep.SkippedComparators, SkipNote{Comparator: name, Reason: reason})
	}
	rep.Sort()
	return rep, nil
}

// runCommit0 runs the commit0-analyzer binary in JSON mode and returns its stdout + exit code.
// The sources string selects the advisory --source set; language, when non-empty,
// narrows commit0-analyzer to one ecosystem. When injectFailure is set, it points the OSV
// source at an unreachable endpoint and forces an update, so a source-fetch
// failure is provoked deterministically.
func runCommit0(ctx context.Context, opts RunOptions, path, sources, language string, injectFailure bool) ([]byte, int, error) {
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	args := []string{"scan", path, "--format", "json"}
	if sources != "" {
		args = append(args, "--source", sources)
	}
	if language != "" {
		args = append(args, "--language", language)
	}
	cmd := exec.CommandContext(cctx, opts.Commit0Binary, args...)
	cmd.Env = os.Environ()
	if injectFailure {
		// An unroutable URL + forced update makes the source fetch fail; the scan
		// must then be incomplete (exit 3), never a silent clean exit 0.
		cmd.Args = append(cmd.Args, "--update")
		cmd.Env = append(cmd.Env,
			"COMMIT0_OSV_DB_URL=http://127.0.0.1:1/dead",
			"COMMIT0_VULN_DB_URL=http://127.0.0.1:1/dead",
		)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	err := cmd.Run()
	code := exitCode(err)
	// Exit 1/3 are expected policy outcomes, not invocation errors.
	if err != nil && code == -1 {
		return stdout.Bytes(), code, fmt.Errorf("run commit0-analyzer: %w", err)
	}
	return stdout.Bytes(), code, nil
}

// runCommit0VEX runs the commit0-analyzer binary and captures its OpenVEX document. The VEX
// output is written to a temp file (--vex-out) so it is never interleaved with the
// JSON stdout, then read back. The full source set and the same ecosystem
// narrowing as the primary scan are used so the VEX statuses correspond to the
// findings cross-checked by VEXForUnreachable.
func runCommit0VEX(ctx context.Context, opts RunOptions, path, sources, language string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	tmp, err := os.CreateTemp("", "commit0-analyzer-vex-*.openvex.json")
	if err != nil {
		return nil, fmt.Errorf("create vex temp file: %w", err)
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)

	args := []string{"scan", path, "--format", "json", "--vex", "openvex", "--vex-out", tmpName}
	if sources != "" {
		args = append(args, "--source", sources)
	}
	if language != "" {
		args = append(args, "--language", language)
	}
	cmd := exec.CommandContext(cctx, opts.Commit0Binary, args...)
	cmd.Env = os.Environ()
	cmd.Stdout = nil
	cmd.Stderr = nil
	// Exit 1/3 are expected policy outcomes (findings / incomplete), not failures:
	// the VEX document is still written. Only a non-process failure is fatal here.
	if rerr := cmd.Run(); rerr != nil && exitCode(rerr) == -1 {
		return nil, fmt.Errorf("run commit0-analyzer --vex: %w", rerr)
	}
	data, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, fmt.Errorf("read vex output: %w", err)
	}
	return data, nil
}

// runComparator runs an external comparator and returns its stdout.
func runComparator(ctx context.Context, opts RunOptions, comp Comparator, path string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	args := append(append([]string{}, comp.JSONArgs...), path)
	cmd := exec.CommandContext(cctx, comp.Binary, args...)
	cmd.Env = os.Environ()
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		// Comparators conventionally exit non-zero when vulnerabilities are found;
		// treat output presence as success and only fail on truly empty output.
		if strings.TrimSpace(stdout.String()) == "" {
			return nil, fmt.Errorf("run %s: %w", comp.Name, err)
		}
	}
	return stdout.Bytes(), nil
}

// parseComparator dispatches to the right parser for a comparator name.
func parseComparator(name string, data []byte) ([]Finding, error) {
	switch name {
	case ToolOSVScanner:
		return ParseOSVScanner(data)
	case ToolGrype:
		return ParseGrype(data)
	case ToolTrivy:
		return ParseTrivy(data)
	case ToolGovulncheck:
		return ParseGovulncheck(data)
	default:
		return nil, fmt.Errorf("unknown comparator %q", name)
	}
}

// exitCode extracts the process exit code from an exec error, or 0 on success,
// or -1 when the failure is not a clean process exit (e.g. binary not found).
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
