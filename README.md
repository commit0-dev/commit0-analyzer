# commit0-analyzer

**Stop drowning in dependency-CVE noise. Ship the ones that can actually hurt you.**

`commit0-analyzer` is an open-source, CI-native security scanner that answers the question every other SCA tool leaves open: **is this vulnerability actually reachable in my code?** It traces a real call path from your application into the vulnerable function, so a CVE in a package you import but never exercise is *proven* harmless instead of cluttering your dashboard — across **eleven language ecosystems**, from one zero-config command.

> Most scanners list every CVE in your lockfile and leave you to triage hundreds of findings by hand. commit0-analyzer tells you which ones are reachable, scores them by real-world exploitability, and emits machine-readable **VEX** so the rest stop nagging you and your downstream tools.

---

## Why commit0-analyzer

- 🎯 **Reachability, with proof.** Every finding is `reachable`, `not reachable`, or `unknown` — and "reachable" comes with a SARIF `codeFlows` call-path you can audit. No black-box verdicts.
- 🔕 **Noise reduction you can trust.** A vulnerable dependency that's never reached is suppressed as VEX `not_affected` — but *only* when it's provably unreachable. We never guess "safe."
- 🧠 **Multi-source advisory intelligence.** Go vuln DB + OSV.dev + GitHub (GHSA) + GitLab (gemnasium-db), merged and deduplicated, then enriched with CVSS, **CISA KEV** (known-exploited), **EPSS** (exploit probability), and CWE — fused into one explainable risk score.
- ⚡ **Deepest analysis by default, zero setup.** Point it at a repo; it auto-installs dependencies (with install scripts disabled) and runs full reachability automatically. Both steps are opt-out.
- 🌐 **One tool, eleven ecosystems.** Go, JS/TS, Rust, Python, JVM, .NET, PHP, Ruby, Elixir, Dart, Swift — polyglot monorepos scanned in a single run.
- 🚦 **A policy gate built for CI.** Fail the build on what matters (`--gate-on kev,epss>=0.5,risk>=70`), with a hard rule: **`unknown ≠ safe`.**
- 📤 **Speaks every standard.** SARIF 2.1 (GitHub code scanning), JSON, a human table, and VEX in **OpenVEX, CycloneDX, and CSAF**.

---

## Quick start

```sh
go install github.com/commit0-dev/commit0-analyzer/cmd/commit0-analyzer@latest

# Point it at any project — every ecosystem present is auto-detected and scanned.
anst scan /path/to/project
```

That's the whole interface. By default anst installs the project's dependencies (scripts disabled, so it never runs untrusted package code) and performs call-graph reachability, giving you real results with no flags.

```sh
# Fast, no-side-effects pass (skip install + reachability → package-level matches):
anst scan . --skip-deps-install --skip-reachability-analysis

# CI: SARIF for GitHub code scanning + a VEX document for downstream tools:
anst scan . --format sarif --vex openvex --vex-out anst.vex.json

# Gate on exploit-in-the-wild signals, not just severity:
anst scan . --gate-on reachable+unknown,kev,epss>=0.5
```

> **JS/TS reachability** uses a small native plugin compiled with [Bun](https://bun.sh); install Bun for call-graph analysis of npm/Yarn/pnpm projects (everything else runs from the single Go binary).

---

## See it work

Two vulnerable packages, same project — one imported, one not:

```jsonc
// minimist is parsed in code → reachable → you must act
{ "module": "minimist", "confidence": "PACKAGE_REACHABLE", "cvss": "9.8",
  "risk": { "score": 88.2, "tier": "high" },
  "vex": "affected", "action": "Update minimist to 1.2.6 or later." }

// lodash is installed but never imported → provably safe → suppressed
{ "module": "lodash", "confidence": "NOT_REACHABLE", "cvss": "9.1",
  "risk": { "score": 0.0, "tier": "none" },
  "vex": "not_affected", "justification": "vulnerable_code_not_in_execute_path" }
```

The first fails your gate with a fix to apply; the second drops off your queue with an auditable reason. That's the difference between a list of CVEs and a list of *decisions*.

---

## Supported ecosystems

| Ecosystem | Package managers | Reachability |
|---|---|---|
| **Go** | Go modules | Symbol-level (VTA call graph) |
| **JavaScript / TypeScript** | npm, Yarn, pnpm (workspaces) | Into-dependency call graph; symbol-level via `--symbols` |
| **Python** | uv, Poetry, pip, pyproject | Call-graph "positive reachability" (sound under dynamism) |
| **Rust** | Cargo | Package-level + RustSec symbol hints |
| **JVM** (Java/Kotlin/Scala) | Maven, Gradle | Package-level (lockfile-static) |
| **.NET** | NuGet | Package-level (lockfile-static) |
| **PHP** | Composer | Package-level (lockfile-static) |
| **Ruby** | Bundler | Package-level (lockfile-static) |
| **Elixir / Erlang** | Hex, Rebar | Package-level (lockfile-static) |
| **Dart / Flutter** | Pub | Package-level (lockfile-static) |
| **Swift** | SwiftPM | Package-level (lockfile-static) |

Findings cover the **full installed closure** — direct *and* transitive. Dependency types (`dev`, `test`, `optional`, …) are detected per ecosystem and don't fail the gate by default.

---

## Advisory intelligence

anst merges several advisory databases and deduplicates by CVE/GHSA alias, so one vulnerability becomes one finding that credits every source:

| Source | Default | Role |
|---|---|---|
| Go vuln DB · OSV.dev · GitHub (GHSA) · GitLab (gemnasium-db) | **on** | Vulnerability matching across all ecosystems |
| CISA **KEV** · **CWE** | **on** | Known-exploited flag + weakness class (cheap, always enriched) |
| FIRST **EPSS** · **NVD** (CVSS/CWE) | opt-in | Exploit-probability + authoritative CVSS, via `--source epss,nvd` |

Every finding gets a deterministic **0–100 risk score** (also emitted as SARIF `rank`) fusing *reachability × CVSS × KEV × EPSS* — a reachable, known-exploited CVE rises to the top; an unreachable one drops to zero.

> GitLab's database defaults to the **MIT-licensed community mirror** (`gitlab-org/advisories-community`) so anst stays fully open-source; point `ANST_GITLAB_DB_URL` at the upstream gemnasium-db if you're entitled to it.

---

## Outputs & CI

- **SARIF 2.1** — upload to GitHub code scanning; reachable findings carry call-path proofs and a `rank`.
- **VEX** — `--vex openvex|cyclonedx|csaf|all`. Proven-unreachable → `not_affected`; reachable → `affected` + remediation; anything unproven → `under_investigation` (**never** falsely `not_affected`).
- **JSON / table** — for pipelines and humans.
- **Exit codes** — `0` clean · `1` policy violation · `3` incomplete/operational error. An incomplete scan is **never** a silent pass.

```yaml
# GitHub Actions
- run: anst scan . --format sarif > anst.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: anst.sarif }
```

---

## How it differs

| | commit0-analyzer | osv-scanner / grype / trivy | govulncheck |
|---|---|---|---|
| Reachability analysis | ✅ call-path proof | ❌ lockfile-only | ✅ (Go only) |
| Ecosystems | 11 | many | Go only |
| VEX output (`not_affected`) | ✅ proof-backed | partial / none | ❌ |
| KEV + EPSS + risk scoring | ✅ built-in | varies | ❌ |
| `unknown ≠ safe` guarantee | ✅ | n/a | ✅ |

commit0-analyzer aims to combine govulncheck-class reachability with osv-scanner-class breadth — and add the exploit-intelligence and VEX layer on top.

---

## The promise: `unknown ≠ safe`

A scanner that quietly downgrades uncertainty to "safe" is worse than no scanner. commit0-analyzer never does:

- Reachability it can't prove is `UNKNOWN` and **counts toward the gate** — not silently dropped.
- A vulnerability is suppressed (`not_affected`) **only** when the vulnerable code is provably unreachable with a complete analysis.
- A failed advisory fetch, an unresolved dependency, or a crashed analysis exits `3` — never `0`.
- Auto-install runs with **lifecycle scripts disabled** — scanning your project never executes its untrusted install code.

For the full soundness model, coverage measurements, and known limits, see [`docs/soundness-limits.md`](docs/soundness-limits.md). For every flag and environment variable, see [`docs/usage.md`](docs/usage.md).

---

## Project status

commit0-analyzer is under active development; the plugin protocol is `v0-PROVISIONAL`. Architecture, the plugin contract (`proto/commit0/v1/plugin.proto`), and contribution guidelines live in [`docs/`](docs/). Issues and PRs welcome.

## License

[GNU AGPL-3.0](LICENSE). The copyleft keeps the engine and its platform surface open; it precludes embedding the core as a library in closed-source products.
