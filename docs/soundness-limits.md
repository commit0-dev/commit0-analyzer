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

## Advisory Data Scope (MVP)

Advisory data comes exclusively from the **Go vulnerability database** (`vuln.go.dev`). Only the Go vuln DB reliably carries symbol-level data. OSV.dev and GHSA are roadmap items that add CVE *coverage* (more advisories), not symbol *precision* (the same symbols, from a different source).

**Implication:** `anst-analyzer` and `govulncheck` use the same advisory symbol data for Go modules. The differentiation is SARIF `codeFlows`, policy-as-code gating, and the plugin architecture — not symbol resolution precision.

## Entry-Point Detection

| Module type | Detected entry points |
|---|---|
| `main` package | `main.main`, `init` functions, test functions (when `Tests=true` in load config) |
| Library (no `main`) | All exported functions and methods, `init` functions |

If no entry points are detected (e.g. an empty package), the engine emits `CONFIDENCE_UNKNOWN` for all advisories.

## Performance Budget

Target: **≤ 1.5× `govulncheck`** wall-clock on a ~50 k-LOC module (warm module cache, same machine).

VTA (Variable Type Analysis) is more expensive than CHA or RTA but provides better precision for interface dispatch. If VTA exceeds the budget, fall back to RTA via the `--algorithm rta` flag (available in the `standalone` binary) and document the precision trade-off. RTA may miss some interface-dispatch reachable paths and produce more `NOT_REACHABLE` results.

## License Note (AGPL-3.0)

`anst-analyzer` is licensed under AGPL-3.0. This precludes embedding the core engine as a library in proprietary closed-source tools without releasing the embedding application's source. For CLI / CI use this is not a concern. Contact the project maintainers if library embedding in a proprietary context is a requirement.
