# anst-analyzer

An OSS, CI-native, reachability-first software composition analysis (SCA) tool. It analyzes Go modules and JavaScript/TypeScript packages, lists dependency CVEs, marks each one **reachable**, **not reachable**, or **unknown**, then emits SARIF 2.1, JSON, or a human-readable table and exits non-zero when a policy threshold is crossed.

The key differentiator vs `govulncheck` / `npm audit`: SARIF `codeFlows` call-path proofs, a policy-as-code gate, and a multi-language architecture (Go + npm/JS/TS today; PyPI, Cargo on the roadmap).

## How it works

```
Project root (Go module, npm workspace, or both)
   └─> Advisory resolver (Go vuln DB + OSV.dev offline bundle, --source selectable)
          └─> AnalyzeRequest (root + entrypoints + advisories + ecosystem config)
                 ├─> go-reachability plugin  (go/ssa + VTA call graph; import-level fallback on unsupported generics)
                 └─> js-reachability plugin  (demand-driven call graph into dependency source;
                 │                            symbol-level via advisory fix-patch extraction)
                        └─> Findings (streamed, confidence-tiered, source-attributed)
                               └─> Renderers (SARIF 2.1 / JSON / table)
                                      └─> Policy gate (exit 0 / 1 / 3)
```

Plugins run as child processes communicating via gRPC over stdio (hashicorp/go-plugin pattern). The plugin contract is defined in `proto/anst/v1/plugin.proto`.

## Build

```sh
# Prerequisites: Go 1.26+, Bun (https://bun.sh), buf 1.71+
make build            # go build + build-js-plugin
make build-js-plugin  # compile JS plugin binary + napi sidecar (requires Bun)
make generate         # regenerate proto stubs (buf generate)
make test             # go test ./... + vitest (if Node present)
make vet              # go vet ./...
make lint             # golangci-lint run (falls back to go vet if not installed)
```

## Quick start

```sh
go install github.com/ducthinh993/anst-analyzer/cmd/anst@latest

# Scan a Go module
anst scan /path/to/go-module

# Scan an npm workspace (requires JS plugin to be built)
anst scan /path/to/npm-project --language js

# Auto-detect (polyglot: runs both plugins if both go.mod and package.json are present)
anst scan /path/to/monorepo --language auto
```

## Supported ecosystems

| Ecosystem | Package managers | Reachability ceiling | Advisory source |
|-----------|-----------------|----------------------|-----------------|
| **Go** | Go modules (`go.mod`) | Symbol-level (VTA call graph); degrades to import-level on generic-heavy code (an x/tools limitation) | Go vuln DB + OSV.dev |
| **JavaScript / TypeScript** | npm, Yarn, pnpm (workspaces) | Into-dependency call graph (direct + transitive); symbol-level via advisory fix patches (`--symbols`) | OSV.dev npm bundle |

Findings cover the full installed closure (direct **and** transitive). Vulnerabilities reachable only through a `devDependency` subtree are tagged `dev_only` and reported without failing the gate; runtime-reachable findings gate. Add `--symbols` to resolve the vulnerable exported symbols a fix patch touched (fetched from the advisory's fix commit, cached, offline-degrading) and emit `SYMBOL_REACHABLE` with a SARIF code path.

**npm confidence tiers for JS/TS:**

| Confidence | Meaning |
|---|---|
| `PACKAGE_REACHABLE` | The vulnerable package is imported and reachable from an entry point. |
| `SYMBOL_REACHABLE` | A concrete call path to the vulnerable export was found (via advisory fix-patch symbol extraction, `--symbols`). |
| `NOT_REACHABLE` | The package is installed but no import path reaches it. |
| `UNKNOWN` | Dynamic `require()`, `eval`, or incomplete graph — reachability indeterminate. |

**Phantom dependency:** A package installed (hoisted from a workspace root) but not declared in a workspace's own `package.json` is tagged `phantom (undeclared)` in the finding. Phantom reachable vulnerabilities gate identically to explicit deps.

## Repository layout

```
cmd/anst/               CLI entry point
internal/
  host/                 Plugin host (subprocess lifecycle, gRPC handshake, crash isolation)
  advisory/             Advisory resolution (Go vuln DB + OSV multi-source merge)
  render/               Output renderers: SARIF 2.1, JSON, table (language-agnostic)
  policy/               Policy-as-code gate and exit-code contract (language-agnostic)
  cli/                  Scan command, ecosystem detection, plugin wiring
  advisory/symbolindex/ Lazy symbol-DB index keyed by advisory fix refs (--symbols)
  advisory/ghfetch/     GitHub fix-commit fetch (diff + post-fix file content, cached)
  advisory/symbolextract/ Bridge to the plugin's vulnerable-symbol extractor
  telemetry/            Env-gated host phase timing (ANST_DEBUG / ANST_TELEMETRY)
plugins/
  go-reachability/      Go reachability plugin (go/ssa + VTA; import-level degrade on generics)
    testdata/mods/      Hermetic Go fixture modules (integration tests)
  js-reachability/      JS/TS reachability plugin (TypeScript + Bun + napi sidecar)
    src/parse/          Crash-safe parser: child-process worker pool (oxc isolation)
    src/telemetry.ts    Env-gated plugin telemetry
    testdata/projects/  npm/yarn/pnpm fixture projects (generated by build-fixtures.mjs,
    │                   regenerated per test run; node_modules + lockfiles gitignored)
    dist/               Compiled binary + oxc-binding/ napi sidecar (gitignored; built via make)
pkg/contract/           Versioned gRPC plugin contract wrappers and helpers
  anstv1/               Generated protobuf/gRPC Go stubs (committed)
proto/anst/v1/          Canonical plugin.proto source
testdata/
  corpus/               Go reachability corpus fixtures (precision/recall harness)
  js/                   JS/TS fixtures: empty-pkg, polyglot, monorepo-dogfood
  acceptance/           Large real-repo acceptance scratch (gitignored)
```

## Large repositories

Both plugins are hardened for very large real-world repos. The npm plugin isolates the
oxc parser in a child-process worker pool — a native parser crash on a dependency bundle
degrades that file to an `UNKNOWN` boundary and respawns the worker instead of killing the
scan — and collapses and memoizes the transitive-closure work so memory stays flat. The Go
plugin recovers the x/tools method-set panic on generic-heavy code and falls back to sound
import-level reachability. With telemetry (`ANST_DEBUG=1`) you can see per-phase timing.
Reference scans: Renovate (~8.5k reachable files) and istio (~325 Go deps) both complete in
well under two minutes.

## Confidence tiers (all languages)

| Confidence | Meaning | Gate-eligible? |
|---|---|---|
| `SYMBOL_REACHABLE` | Concrete call path found to the vulnerable symbol | Yes |
| `PACKAGE_REACHABLE` | Vulnerable package imported and reachable; symbol unconfirmed | Yes |
| `NOT_REACHABLE` | No call-graph path found (graph is complete) | No (suppressed) |
| `UNKNOWN` | Reachability undetermined (dynamic code, eval, reflection, …) | Yes |

**`unknown ≠ safe`.** An `UNKNOWN` finding is always surfaced. Only `NOT_REACHABLE` findings may be suppressed by the policy gate.

## JS plugin distribution

The JS plugin ships as two files (both required):

- `plugins/js-reachability/dist/anst-js-reachability` — main binary (compiled by Bun)
- `plugins/js-reachability/dist/oxc-binding/parser.<GOOS>-<GOARCH>.node` — napi sidecar

Both files are SHA-256-pinned in the plugin manifest. The host validates hashes on every launch unless `--skip-hash-check` is set (development only). The sidecar uses Go naming (`darwin-arm64`, `linux-amd64`) rather than Node platform naming (`darwin-arm64`, `linux-x64`) — the Makefile handles the rename during build.

Full five-target sidecar builds (linux-x64, darwin-arm64, linux-arm64, darwin-x64, windows-x64) happen in the release CI matrix. Local development builds only the host-native sidecar via `make build-js-plugin`.

## Plugin protocol

The plugin contract is `v0-PROVISIONAL`. Compatibility rule: `host.major == plugin.major && host.minor >= plugin.minor`.

See `proto/anst/v1/plugin.proto` for the full contract with SARIF mapping notes and stream framing documentation.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

AGPL-3.0 protects the roadmap server/dashboard surface from closed SaaS forks. Note: this precludes embedding the core engine as a library in proprietary tools.
