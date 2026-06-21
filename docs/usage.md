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
| `--db-snapshot` | _(none)_ | Path to a pinned advisory snapshot directory (read-only; never fetched or mutated) |
| `--offline` | `false` | Disable network access; use existing writable cache or `--db-snapshot` |
| `--update` | `false` | Force re-fetch of advisory data even when the cached version is current |
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

#### Advisory DB Modes

`anst-analyzer scan` operates in three distinct advisory-data modes:

| Mode | Flags | Behaviour |
|------|-------|-----------|
| **Online** (default) | _(none)_ | Fetches advisories from `vuln.go.dev` into a writable local cache (`$XDG_CACHE_HOME/anst-analyzer/vuln-db` on Linux/macOS). Only re-fetches when the DB has a newer `modified` timestamp than the cached version. |
| **Offline** | `--offline` | Reads the existing writable cache; never contacts the network. Fails clearly (exit 3) when the cache is absent or unverifiable. |
| **Pinned snapshot** | `--db-snapshot <dir>` | Reads a pre-built snapshot directory; never fetches or mutates it. Verified against its manifest digest on every scan. Use this for reproducible CI pipelines. |

**First-run note:** The first `scan` without `--db-snapshot` downloads advisory data from `vuln.go.dev`. This adds network latency once per advisory-DB version update. Subsequent scans reuse the local cache and only check the DB `modified` timestamp.

**Failure handling:** A fetch failure marks the scan **incomplete** (exit 3), never a silent pass. If the staleness probe fails but a valid local cache exists, the scan uses the existing cache, prints a warning to stderr, and exits 3 (incomplete). A full fetch failure with no cache also exits 3.

#### Examples

```sh
# Online mode (default): fetch from vuln.go.dev on first run, use cache thereafter.
anst-analyzer scan

# Force a re-fetch even when the cached version is current.
anst-analyzer scan --update

# Offline mode: use existing local cache, no network access.
anst-analyzer scan --offline

# Pinned snapshot for reproducible CI (read-only, never fetched).
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

`anst-analyzer` uses a **fetch-and-cache-only** model. It fetches your own copy of the Go vulnerability database into a local cache; it never redistributes advisory data.

**Default writable cache:** `$XDG_CACHE_HOME/anst-analyzer/vuln-db` (Linux) or `$HOME/Library/Caches/anst-analyzer/vuln-db` (macOS).

**Pinned snapshot format:** a directory of OSV JSON files plus `anst-snapshot-manifest.json` (generated by the cache layer when it fetches from `vuln.go.dev`). The manifest records a SHA-256 content digest and the `modified` timestamp from the DB at fetch time.

Two scans using the same pinned snapshot directory produce byte-identical output (offline determinism contract).
