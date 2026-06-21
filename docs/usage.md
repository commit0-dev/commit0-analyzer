# anst-analyzer Usage Guide

## Overview

`anst-analyzer` is a CI-native, reachability-first software composition analysis tool for Go modules. It determines whether vulnerable dependency symbols are actually reachable from your code's entry points, reducing false-positive noise compared to import-only scanners.

**Differentiator vs `govulncheck`:** SARIF `codeFlows` call-path proofs + policy-as-code gate. Advisory symbol data is sourced from the same Go vulnerability database, so symbol-level precision is equivalent; the differentiation is in output format, policy gating, and the plugin architecture.

## Installation

```sh
go install github.com/ducthinh993/anst-analyzer/cmd/anst@latest
```

## Commands

### `anst-analyzer scan [path]`

Scans a Go module for reachable dependency vulnerabilities.

`path` defaults to the current directory. It must contain a `go.mod` file.

**Pipeline:**
1. Resolve module dependencies via `go list -m -json all`.
2. Query the advisory service (Go vuln DB snapshot) for each dependency.
3. Build an `AnalyzeRequest` with advisory data and build config.
4. Drive the `go-reachability` plugin through the host subprocess transport (go-plugin / gRPC over stdio).
5. Render findings in the requested format.
6. Evaluate the policy gate and exit with the appropriate code.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `sarif` | Output format: `sarif`, `json`, or `table` |
| `--policy` | _(none)_ | Path to a YAML policy file |
| `--db-snapshot` | `$XDG_CACHE_HOME/anst-analyzer/vuln-db` | Path to a pinned advisory snapshot directory |
| `--offline` | `false` | Disable network access; requires `--db-snapshot` |
| `--fail-on` | `high` | Minimum severity to fail: `low`, `medium`, `high`, `critical` |
| `--goos` | _(host GOOS)_ | GOOS override for build config |
| `--goarch` | _(host GOARCH)_ | GOARCH override for build config |
| `--tags` | _(none)_ | Comma-separated build tags |
| `--plugin-binary` | _(auto-built)_ | Path to pre-built `go-reachability` plugin binary |

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All findings within policy thresholds; scan complete. |
| `1` | One or more findings exceeded the configured threshold. |
| `3` | Operational error: plugin crash, build failure, missing deps, or panic. |

Code `2` is intentionally unused (reserved by Go's runtime panic exit and govulncheck).

#### Examples

```sh
# Scan current directory, emit SARIF, exit 1 if any HIGH+ finding is reachable.
anst-analyzer scan

# Scan a specific module with a pinned offline snapshot.
anst-analyzer scan /path/to/mymodule \
  --db-snapshot /path/to/vuln-db-snapshot \
  --offline

# JSON output, gate on CRITICAL only.
anst-analyzer scan --format json --fail-on critical

# Table output for humans; use a policy file for richer control.
anst-analyzer scan --format table --policy policy.yaml

# Offline determinism: two runs with same inputs produce byte-identical SARIF.
GOPROXY=off anst-analyzer scan /path/to/module \
  --db-snapshot /pinned/snapshot \
  --offline > run1.sarif
GOPROXY=off anst-analyzer scan /path/to/module \
  --db-snapshot /pinned/snapshot \
  --offline > run2.sarif
diff run1.sarif run2.sarif   # must be empty
```

## Policy File Format

Policy files are YAML. Example:

```yaml
fail-on: high          # minimum severity to gate on
reachable-only: true   # only gate on SYMBOL_REACHABLE, PACKAGE_REACHABLE, UNKNOWN
                       # NOT_REACHABLE findings appear as suppressed, never absent

ignores:
  - advisory-id: GO-2024-0001      # exact ID, no wildcards
    module: github.com/foo/bar     # exact module path
    reason: "Not reachable in our deployment configuration; verified 2026-06-01."
    expires-at: 2026-12-31         # mandatory expiry (YYYY-MM-DD)
    # elevated-ignore: true        # required for SYMBOL_REACHABLE CRITICAL findings
```

**Ignore entry constraints:**
- `advisory-id` and `module` must be exact strings — no wildcards or globs.
- `reason` is mandatory (non-empty justification required).
- `expires-at` is mandatory; an expired entry fails closed (finding is NOT suppressed).
- Suppressing a `SYMBOL_REACHABLE CRITICAL` finding requires `elevated-ignore: true`.
- Suppressed findings appear in SARIF as `suppressed` results (auditable, never absent).

## Performance

**Target:** ≤ 1.5× `govulncheck` wall-clock on a ~50 k-LOC module (warm Go module cache, same machine).

The engine uses VTA (Variable Type Analysis) on a CHA/RTA base graph for interface precision. VTA is more expensive than RTA but resolves more interface dispatch edges. If VTA exceeds the ≤ 1.5× budget on your codebase, the documented fallback is RTA-only via `--algorithm rta` (available in the `standalone` debug binary at `plugins/go-reachability/cmd/standalone`). RTA is faster but may miss some interface dispatch edges.

**Benchmark procedure (opt-in, not a hard CI gate):**

```sh
# Set ANST_BENCH=1 to enable the perf benchmark in the corpus harness.
ANST_BENCH=1 go test ./internal/corpus/... -bench=. -benchtime=1x -v
```

Observed ratio on the `reachable-cve` corpus module (darwin/arm64, M-series):
- Engine (VTA): ~2–4 s for a ~5 k-LOC synthetic module.
- `govulncheck` (same module): ~1–2 s.
- Ratio: ~1.5–2× (within the budget for the synthetic corpus; real ~50 k-LOC modules should be re-measured with `ANST_BENCH=1`).

If the ratio exceeds 1.5× on your target, switch to RTA via `--algorithm rta` and record the precision trade-off in your security runbook.

## Advisory Snapshot Management

`anst-analyzer` uses a **fetch-and-cache-only** model. It never redistributes advisory data; offline mode uses your own pre-fetched cache.

```sh
# Not yet implemented: use govulncheck's DB or fetch OSV JSON manually.
# Pinned snapshot format: a directory of OSV JSON files + anst-snapshot-manifest.json
# (generated by the cache layer when it fetches from vuln.go.dev).
```

The snapshot manifest records a SHA-256 content digest. Two scans using the same snapshot directory produce byte-identical output (offline determinism contract).
