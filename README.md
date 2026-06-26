# anst-analyzer

An OSS, CI-native, reachability-first software composition analysis (SCA) tool. It analyzes Go modules, JavaScript/TypeScript packages, Rust crates, Python projects, JVM (Java/Kotlin/Scala), .NET, PHP, Ruby, Elixir, and Dart applications, lists dependency CVEs, marks each one **reachable**, **not reachable**, or **unknown**, then emits SARIF 2.1, JSON, or a human-readable table and exits non-zero when a policy threshold is crossed.

The key differentiator vs `govulncheck` / `npm audit`: SARIF `codeFlows` call-path proofs, a policy-as-code gate, and a ten-ecosystem architecture (Go, JS/TS, Rust, Python, JVM, .NET, PHP, Ruby, Elixir, Dart).

## How it works

```
Project root (Go, JS/TS, Rust, Python, Java, .NET, PHP, Ruby, Elixir, Dart — auto-detected or --language selectable)
   └─> Advisory resolver (Go vuln DB + OSV.dev offline bundle, --source selectable)
          └─> AnalyzeRequest (root + entrypoints + advisories + ecosystem config)
                 ├─> go-reachability plugin          (go/ssa + VTA call graph; import-level fallback on unsupported generics)
                 ├─> js-reachability plugin          (call graph into dependency source; symbol-level via fix patches)
                 ├─> rust-reachability plugin        (cargo metadata + RustSec; package-level reachability)
                 ├─> python-reachability plugin      (ast-driven call graph; lockfile-static resolver; positive-reachability model)
                 └─> Lane-A lockfile resolvers       (Maven/Gradle, NuGet, Composer, RubyGems, Hex, Pub; host-side, lockfile-static, package-level)
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

# That's the whole interface: point it at any project. anst auto-detects
# every ecosystem present (Go, JS/TS, Rust, Python, JVM, .NET, PHP, Ruby, Elixir, Dart) and scans them all —
# no language flag, the same as npm audit / trivy / osv-scanner.
anst scan /path/to/project

# Polyglot monorepo? Every detected ecosystem is scanned in one run.
anst scan /path/to/monorepo

# Optional: narrow to one ecosystem for speed. --language defaults to auto;
# you never need to pass it.
anst scan /path/to/project --language rust
```

## Supported ecosystems

| Ecosystem | Package managers | Reachability ceiling | Advisory source |
|-----------|-----------------|----------------------|-----------------|
| **Go** | Go modules (`go.mod`) | Symbol-level (VTA call graph); degrades to import-level on generic-heavy code (an x/tools limitation) | Go vuln DB + OSV.dev |
| **JavaScript / TypeScript** | npm, Yarn, pnpm (workspaces) | Into-dependency call graph (direct + transitive); symbol-level via advisory fix patches (`--symbols`) | OSV.dev npm bundle |
| **Rust** | Cargo (`Cargo.toml`) | Package-level (no static call graph); symbol hints from RustSec | OSV.dev crates.io + RustSec |
| **Python** | Lockfile-static: uv.lock, poetry.lock, requirements.txt, pyproject.toml | Call-graph-driven positive reachability (sound under dynamism); symbol-level via `--symbols` | OSV.dev PyPI |
| **JVM (Java / Kotlin / Scala)** | Maven (`pom.xml`), Gradle (`gradle.lockfile`, `build.gradle[.kts]`) | Package-level (lockfile-static, no symbol-level data); plain `pom.xml` scans declared direct deps (incomplete without transitive closure) | OSV.dev Maven |
| **.NET** | NuGet (`packages.lock.json`, `project.assets.json`, `.csproj` for declared deps) | Package-level (lockfile-static, no symbol-level data); `.csproj` only is incomplete without `dotnet restore` | OSV.dev NuGet |
| **PHP** | Composer (`composer.lock`) | Package-level (lockfile-static, no symbol-level data) | OSV.dev Packagist |
| **Ruby** | Bundler (`Gemfile.lock`) | Package-level (lockfile-static, no symbol-level data; `Gemfile` is never evaluated) | OSV.dev RubyGems |
| **Elixir / Erlang** | Hex (`mix.lock`, `rebar.lock`) | Package-level (lockfile-static, no symbol-level data; `mix.exs` is never evaluated); unparseable lockfile is marked incomplete | OSV.dev Hex |
| **Dart / Flutter** | Pub (`pubspec.lock`) | Package-level (lockfile-static, no symbol-level data); advisory volume currently thin | OSV.dev Pub |

Findings cover the full installed closure (direct **and** transitive). Add `--symbols` to resolve the vulnerable exported symbols a fix patch touched (fetched from the advisory's fix commit, cached, offline-degrading) and emit `SYMBOL_REACHABLE` with a SARIF code path. Symbol-level enrichment is available for Go, JS/TS, and Python only.

**JS/TS dependency types:** Vulnerabilities reachable only through a `devDependency` subtree are tagged `dev_only` and reported without failing the gate; runtime-reachable findings gate.

**JVM dependency types:** Vulnerabilities tagged as provided scope or test scope (Maven `<scope>`) or test/annotation configurations (Gradle) are marked as `dev` and reported without failing the gate by default.

**.NET dependency types:** Vulnerabilities where the package is marked `<PrivateAssets>All</PrivateAssets>` in `.csproj` are marked as `dev` and reported without failing the gate by default.

**PHP dependency types:** Vulnerabilities in the `require-dev` section of `composer.lock` are marked as `dev` and reported without failing the gate by default.

**Ruby dependency types:** Vulnerabilities in development/test groups from `Gemfile.lock` are marked as `dev` and reported without failing the gate by default.

**Elixir dependency types:** Vulnerabilities in the dev group from `mix.lock` are marked as `dev` and reported without failing the gate by default.

**Python dependency types:** Each finding is tagged `dep_type` = runtime | optional-extra | dev | test | docs (from the manifest). Non-runtime findings do not fail the gate by default; use `--gate-on` to customize this behavior.

**Phantom dependency (JS/TS):** A package installed (hoisted from a workspace root) but not declared in a workspace's own `package.json` is tagged `phantom (undeclared)` in the finding. Phantom reachable vulnerabilities gate identically to explicit deps.

## Python value-prop: Positive reachability model

On dynamic languages like Python, sound **negative** reachability (`NOT_REACHABLE` suppression) is mostly impossible — config-driven `importlib.import_module()` can load arbitrary packages. `anst-analyzer` inverts the model: focus on what you **provably use**, segment by dependency type, and accept that a hyper-dynamic app yields `UNKNOWN` by design (correct, not a limitation).

**Positive reachability is sound under dynamism:** `SYMBOL_REACHABLE` and `PACKAGE_REACHABLE` findings are always sound lower bounds on actual use. **Negative reachability is not:** `NOT_REACHABLE` on a dynamic app is a false negative, so it is never surfaced for gate purposes (only auditable in SARIF).

**Dependency-type segmentation:** Python findings include `dep_type` (runtime, optional-extra, dev, test, docs). By default, non-runtime findings do not gate; use `--gate-on reachable` to suppress `UNKNOWN` on non-runtime deps, or `--gate-on all` to gate every non-NOT_REACHABLE finding.

**Scan completeness:** An incomplete scan (e.g., a call-graph analysis unable to fully trace a hyper-dynamic app) exits 3, never 0. Exit 0 always means "scan completed + policy clean," never "scan incomplete + assumed safe."

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
  rust-reachability/    Rust reachability plugin (cargo metadata + RustSec advisory fetch)
    testdata/crates/    Hermetic Cargo fixture crates (integration tests)
  python-reachability/  Python reachability plugin (ast-driven call graph; lockfile-static)
    testdata/projects/  Python project fixtures with lockfiles (integration tests)
pkg/contract/           Versioned gRPC plugin contract wrappers and helpers
  anstv1/               Generated protobuf/gRPC Go stubs (committed)
proto/anst/v1/          Canonical plugin.proto source
testdata/
  corpus/               Go reachability corpus fixtures (precision/recall harness)
  js/                   JS/TS fixtures: empty-pkg, polyglot, monorepo-dogfood
  acceptance/           Large real-repo acceptance scratch (gitignored)
```

## Large repositories

All plugins are hardened for very large real-world repos. The JS plugin isolates the oxc parser in a child-process worker pool — a native parser crash on a dependency bundle degrades that file to an `UNKNOWN` boundary and respawns the worker instead of killing the scan — and collapses and memoizes the transitive-closure work so memory stays flat. The Go plugin recovers the x/tools method-set panic on generic-heavy code and falls back to sound import-level reachability. The Python plugin uses a ProcessPool with file-size and long-line guards to safely sandbox AST parsing. With telemetry (`ANST_DEBUG=1`) you can see per-phase timing. Reference scans: Renovate (~8.5k reachable files), ripgrep (61 Rust crates), and istio (~325 Go deps) all complete in well under two minutes.

## Confidence tiers (all languages)

| Confidence | Meaning | Gate-eligible? |
|---|---|---|
| `SYMBOL_REACHABLE` | Concrete call path found to the vulnerable symbol (Go, JS, Python with `--symbols`) | Yes |
| `PACKAGE_REACHABLE` | Vulnerable package imported and reachable; symbol unconfirmed | Yes |
| `NOT_REACHABLE` | No call-graph path found (graph is complete) | No (suppressed) |
| `UNKNOWN` | Reachability undetermined (dynamic code, incomplete analysis, reflection, build mismatch, …) | Yes |

**Core invariant: `unknown ≠ safe`.** An `UNKNOWN` finding is always surfaced and always counts toward the gate (unless narrowed by `--gate-on` on Python non-runtime deps). Only `NOT_REACHABLE` findings may be suppressed by the policy gate.

For dynamic languages (Python, etc.), `UNKNOWN` is common and correct — it means the tool completed its analysis but cannot prove reachability under dynamism. Exit 3 signals this incomplete-but-analyzed state; exit 0 always means "complete analysis + policy clean."

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
