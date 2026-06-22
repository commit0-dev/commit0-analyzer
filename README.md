# anst-analyzer

An OSS, CI-native, reachability-first software composition analysis (SCA) tool. It analyzes Go modules and JavaScript/TypeScript packages, lists dependency CVEs, marks each one **reachable**, **not reachable**, or **unknown**, then emits SARIF 2.1, JSON, or a human-readable table and exits non-zero when a policy threshold is crossed.

The key differentiator vs `govulncheck` / `npm audit`: SARIF `codeFlows` call-path proofs, a policy-as-code gate, and an architecture built for multi-language (Go + JS/TS today; npm, PyPI, Cargo on the roadmap).

## How it works

```
Project root (Go module, npm workspace, or both)
   └─> Advisory resolver (Go vuln DB + OSV.dev offline bundle)
          └─> AnalyzeRequest (root + entrypoints + advisories + ecosystem config)
                 ├─> go-reachability plugin  (go/ssa + VTA call graph)
                 └─> js-reachability plugin  (AST import-graph + optional Jelly symbol enrichment)
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
| **Go** | Go modules (`go.mod`) | Symbol-level (VTA call graph) | Go vuln DB + OSV.dev |
| **JavaScript / TypeScript** | npm, Yarn, pnpm (workspaces) | Package-level import graph (symbol enrichment is fast-follow via Jelly) | OSV.dev npm bundle |

**npm confidence tiers for JS/TS:**

| Confidence | Meaning |
|---|---|
| `PACKAGE_REACHABLE` | The vulnerable package is imported and reachable from an entry point. |
| `SYMBOL_REACHABLE` | A concrete call path to the vulnerable export was found (Jelly-enriched). |
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
plugins/
  go-reachability/      Go reachability analyzer plugin (go/ssa + VTA)
  js-reachability/      JS/TS reachability plugin (TypeScript + Bun + napi sidecar)
    dist/               Compiled binary + oxc-binding/ napi sidecar (gitignored; built via make)
pkg/contract/           Versioned gRPC plugin contract wrappers and helpers
  anstv1/               Generated protobuf/gRPC Go stubs (committed)
proto/anst/v1/          Canonical plugin.proto source
testdata/
  corpus/               Go reachability corpus fixtures (precision/recall harness)
  js/                   JS/TS fixtures: empty-pkg, polyglot, monorepo-dogfood
```

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
