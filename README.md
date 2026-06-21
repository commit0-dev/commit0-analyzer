# anst-analyzer

**Status: MVP in progress (Phase 1 — plugin contract & scaffold)**

An OSS, CI-native, reachability-first Go software composition analysis (SCA) security analyzer. Given a Go module, it lists dependency CVEs and marks each one **reachable** (with a concrete call path), **not reachable**, or **unknown** — then emits SARIF 2.1, JSON, or a human-readable table and exits non-zero when a policy threshold is crossed.

The key differentiator vs `govulncheck`: SARIF `codeFlows` call-path proofs, a policy-as-code gate, and an architecture built to grow into multi-pillar (SAST, Secrets) and multi-language analysis.

## How it works

```
Go module
   └─> Advisory resolver (Go vuln DB)
          └─> AnalyzeRequest (module root + entrypoints + advisories + build config)
                 └─> Go reachability plugin (go/ssa + VTA call graph)
                        └─> Findings (streamed, with ReachabilityPath)
                               └─> Renderers (SARIF / JSON / table)
                                      └─> Policy gate (exit 0/1/3)
```

Plugins run as child processes communicating via gRPC over stdio (hashicorp/go-plugin pattern). The plugin contract is defined in `proto/anst/v1/plugin.proto` and is versioned from v0.

## Build

```sh
# Prerequisites: Go 1.26+, buf 1.71+
make build        # go build ./...
make generate     # regenerate proto stubs (buf generate)
make test         # go test ./...
make vet          # go vet ./...
make lint         # golangci-lint run (falls back to go vet if not installed)
```

## Quick start (MVP — not yet complete)

```sh
go install github.com/ducthinh993/anst-analyzer/cmd/anst@latest
anst scan ./...
```

## Repository layout

```
cmd/anst/               CLI entry point
internal/
  host/                 Plugin host (subprocess lifecycle, gRPC handshake)
  advisory/             Advisory resolution (Go vuln DB; MVP scope only)
  render/               Output renderers: SARIF 2.1, JSON, table
  policy/               Policy-as-code gate and exit-code contract
plugins/
  go-reachability/      Go reachability analyzer plugin (go/ssa + VTA)
pkg/contract/           Versioned gRPC plugin contract wrappers and helpers
  anstv1/               Generated protobuf/gRPC Go stubs (committed)
proto/anst/v1/          Canonical plugin.proto source
testdata/corpus/        Reachability corpus fixtures (precision/recall harness)
```

## Confidence tiers

| Confidence | Meaning | Suppressible? |
|---|---|---|
| `SYMBOL_REACHABLE` | Concrete call path found to the vulnerable symbol | No |
| `PACKAGE_REACHABLE` | Vulnerable package reachable; symbol unconfirmed | No |
| `NOT_REACHABLE` | No call-graph path found (graph is complete) | Yes (policy gate only) |
| `UNKNOWN` | Reachability undetermined (reflection, cgo, build-tag mismatch, …) | No |

**`unknown ≠ safe`.** An `UNKNOWN` finding is always surfaced. Only `NOT_REACHABLE` findings may be suppressed by the policy gate.

## Plugin protocol

The plugin contract is `v0-PROVISIONAL` (not frozen until Phase 2 confirms the transport). Compatibility rule: `host.major == plugin.major && host.minor >= plugin.minor`.

See `proto/anst/v1/plugin.proto` for the full contract with SARIF mapping notes and stream framing documentation.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

AGPL-3.0 protects the roadmap server/dashboard surface from closed SaaS forks. Note: this precludes embedding the core engine as a library in proprietary tools.
