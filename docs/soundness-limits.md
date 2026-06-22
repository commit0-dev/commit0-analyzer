# anst-analyzer Soundness Limits

This document honestly describes what `anst-analyzer` can and cannot determine. Understanding these limits helps you interpret findings and set appropriate policy thresholds.

## The Core Invariant: `unknown ≠ safe`

A finding with confidence `UNKNOWN` means the analyzer **could not determine reachability** — not that the symbol is safe. `UNKNOWN` findings are always surfaced to the user and always count toward the policy gate (unless `reachable-only: true` is combined with a narrow `fail-on` threshold, but even then `UNKNOWN` is counted, not suppressed).

Only `CONFIDENCE_NOT_REACHABLE` findings may be excluded from gate counts.

## What Causes `CONFIDENCE_UNKNOWN`

### 1. Build configuration mismatch (GOOS / GOARCH / build tags)

`go/packages` loads packages for a specific `(GOOS, GOARCH, tags)` triple. If a vulnerable call site is gated behind a build constraint that does not match the scan configuration, the file is excluded from the build graph and the engine cannot trace a call path.

**Result:** `CONFIDENCE_UNKNOWN` — the engine cannot prove the path is absent on the target platform, only that it is absent on the scanned configuration.

**Implication:** Scanning with `--goos linux` on a codebase that runs on `linux` is necessary to find linux-specific reachable paths. Scanning with the wrong `GOOS` never produces `NOT_REACHABLE` for a genuinely gated path.

### 2. Reflection and dynamic dispatch

Go's `reflect` package and runtime-generated function values break the static call graph. The VTA call-graph algorithm has no edges for:
- `reflect.Value.Call` / `reflect.Value.CallSlice`
- `reflect.Method` invocations
- `plugin.Plugin.Lookup` (Go plugin system)
- Function values passed as `interface{}` and invoked via reflection

If the engine detects that a vulnerable symbol's address is taken **and** a reflect invocation is reachable, it conservatively emits `CONFIDENCE_UNKNOWN`.

**Result:** `CONFIDENCE_UNKNOWN` — the engine cannot confirm or deny the path exists at runtime.

### 3. cgo and external C symbols

`go/packages` with `TypecheckCgo: false` (the default) skips cgo elaboration. If a dependency requires cgo and the build environment lacks the C toolchain or CGO_ENABLED=0, the package may be `IllTyped` and the engine cannot build its SSA representation.

**Result:** `CONFIDENCE_UNKNOWN` — the advisory finding is kept (fail-closed), never silently dropped.

### 4. Non-compiling or broken modules

If the target module or a dependency fails to type-check (`IllTyped` in `go/packages`), the engine cannot reason about that package's call graph.

**Triggers:**
- A `replace` directive pointing to a non-existent path.
- Missing dependencies when running with `GOPROXY=off` and an incomplete module cache.
- Syntax or type errors in the module.

**Result:** `CONFIDENCE_UNKNOWN` for all advisories affecting the broken dependency. The error is surfaced in the finding's `properties.build_error` field and printed to stderr.

### 5. Unresolved advisory symbols

The Go vulnerability database sometimes records symbols that do not exist in the affected version (renamed, unexported, or generated). If the symbol cannot be located in the SSA program, the engine emits `CONFIDENCE_UNKNOWN` rather than claiming the path is absent.

## What the Engine **Can** Determine

| Confidence | Meaning | When produced |
|---|---|---|
| `SYMBOL_REACHABLE` | A concrete call-graph path from an entry point to the vulnerable symbol was found. | Static call graph has a path via VTA (with CHA/RTA base). |
| `PACKAGE_REACHABLE` | The vulnerable package is imported and reachable, but symbol-level confirmation is unavailable. | Advisory has no symbol-level data (`SymbolLevel=false`). |
| `NOT_REACHABLE` | No call path from any entry point to the vulnerable symbol was found in the static call graph. | BFS from all roots found no edge to the symbol, no reflection detected, no build mismatch. |
| `UNKNOWN` | Reachability could not be determined. See above. | Any of the cases above. |

## Advisory Data Scope

`anst-analyzer` queries two advisory sources by default (configurable via `--source`):

| Source | Coverage | Symbol-level data |
|---|---|---|
| `go-vuln-db` (`vuln.go.dev`) | Go modules | Yes — the primary source for symbol-level precision. |
| `osv` (`osv.dev` offline bundle) | Go + npm/JS (+ future: PyPI, Cargo, …) | No — package-level only. |

**Honest Go-coverage note:** OSV.dev's "Go" ecosystem dataset is the same underlying data as `vuln.go.dev` (OSV feeds the Go vuln DB). For Go modules, OSV adds **near-zero additional advisory coverage** — the merge layer collapses OSV entries back onto existing Go-DB symbol-level advisories. This is by design and expected. OSV is enabled by default because it exercises the multi-source dedup/merge path and makes adding non-Go ecosystems cheap later. The value is **architectural**, not coverage-based.

**Only the Go vuln DB carries symbol-level data.** OSV Go entries are package-level (`SymbolLevel=false`). When the same advisory appears in both sources, the Go-DB (symbol-level) representative is kept and OSV is attributed in `Sources`. No precision is ever invented: merging never fabricates symbol data from a package-level entry.

**Multi-source dedup:** The same CVE appearing from Go-DB + OSV collapses to one merged advisory via alias matching (`{ID} ∪ Aliases` set intersection). The merged advisory carries `Sources: ["go-vuln-db", "osv.dev"]` for auditability. Output is deterministic (stable-sorted by advisory ID).

**Implication for Go:** `anst-analyzer` and `govulncheck` use the same advisory symbol data. The differentiation is SARIF `codeFlows`, policy-as-code gating, and the plugin architecture — not symbol resolution precision.

**For JS/TS:** the OSV npm bundle is the only advisory source. No symbol-level data is available for npm (OSV npm entries are package-level only). The JS plugin narrows findings by building an import-reachability graph, so findings are NOT_REACHABLE for packages that are installed but never imported from a reachable entry point.

### Live fetch and caching

`anst-analyzer scan` fetches advisory data from all enabled sources on first run and caches them locally. Each source is refreshed independently before the per-dependency query loop. Use `--update` to force a re-fetch of all enabled sources.

**Failure handling at the fetch boundary:** A Go vuln DB fetch failure with no usable cache exits 3 (never a silent clean pass). An OSV bundle fetch failure (secondary source — for either Go or npm) emits a warning to stderr, marks the scan **incomplete** (exit 3), but does not abort — remaining-source findings still gate. If the staleness probe for Go-DB fails but a valid local cache exists, the scan uses the existing cache, prints a warning, and exits 3 (incomplete). See `docs/usage.md` for the advisory-data modes and `--source` details.

## Entry-Point Detection

### Go

| Module type | Detected entry points |
|---|---|
| `main` package | `main.main`, `init` functions, test functions (when `Tests=true` in load config) |
| Library (no `main`) | All exported functions and methods, `init` functions |

If no entry points are detected (e.g. an empty package), the engine emits `CONFIDENCE_UNKNOWN` for all advisories.

### JavaScript / TypeScript

The JS plugin builds a package-level import graph from the project's lockfile and source files. Entry points are:

- Files declared as `"main"` or `"exports"` in `package.json`
- Files in `src/`, `lib/`, or the package root that are not inside `node_modules/`

A dependency is `PACKAGE_REACHABLE` if there is a static import path from any entry-point file to the package's primary export. Dynamic `require()` calls, `eval`, and variable-module-name imports cannot be statically traced — these produce `CONFIDENCE_UNKNOWN` for any advisory affecting that package.

**Workspace (monorepo) attribution:** In an npm/Yarn/pnpm workspace, each workspace package is analyzed independently using only that workspace's entrypoints and declared deps. A dep that is declared in a workspace's `package.json` (including hoisted deps) but not imported from that workspace's entrypoints emits `NOT_REACHABLE` for that workspace. `NOT_REACHABLE` findings are included in JSON output (`--format json`) and in the audit trail; they are **suppressed** (but auditable) in SARIF output per the SARIF suppression spec — they do not appear as active results in SARIF. If a dep appears in the root `node_modules/` but is not declared in the workspace's own `package.json`, it is a **phantom dependency** and is tagged `phantom (undeclared)` in the finding.

**Ceiling:** The JS plugin currently operates at package-level reachability. Symbol-level (`SYMBOL_REACHABLE`) findings require Jelly enrichment, which is a fast-follow. Until Jelly enrichment is enabled, the maximum confidence for JS findings is `PACKAGE_REACHABLE`.

## Performance Budget

Target: **≤ 1.5× `govulncheck`** wall-clock on a ~50 k-LOC module (warm module cache, same machine).

VTA (Variable Type Analysis) is more expensive than CHA or RTA but provides better precision for interface dispatch. If VTA exceeds the budget, fall back to RTA via the `--algorithm rta` flag (available in the `standalone` binary) and document the precision trade-off. RTA may miss some interface-dispatch reachable paths and produce more `NOT_REACHABLE` results.

## License Note (AGPL-3.0)

`anst-analyzer` is licensed under AGPL-3.0. This precludes embedding the core engine as a library in proprietary closed-source tools without releasing the embedding application's source. For CLI / CI use this is not a concern. Contact the project maintainers if library embedding in a proprietary context is a requirement.
