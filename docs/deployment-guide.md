# Deployment Guide

Practical install, build, and CI-integration reference. For every CLI flag
and environment variable, see [`docs/usage.md`](./usage.md). For soundness
guarantees around exit codes, see
[`docs/soundness-limits.md`](./soundness-limits.md).

## Install

```sh
go install github.com/commit0-dev/commit0-analyzer/cmd/commit0-analyzer@latest
```

There is currently no binary release workflow — `go install` (which requires
a local Go 1.26+ toolchain) is the only supported install path. See
[`docs/project-roadmap.md`](./project-roadmap.md) for the planned binary
release item.

## Build from source

```sh
git clone https://github.com/commit0-dev/commit0-analyzer.git
cd commit0-analyzer
make build     # go build ./... + JS plugin build via Bun
```

Requirements:

- **Go 1.26+** (matches `go.mod`).
- **[Bun](https://bun.sh)** — required to build the JS/TS reachability
  plugin. `make build` warns and skips the JS plugin step if Bun is absent
  from `PATH`; the Go binary itself still builds. Without the JS plugin
  binary, JS/TS ecosystem scans fall back to a build-on-demand step at scan
  time (also requiring Bun) or must be pointed at a prebuilt binary via
  `--js-plugin-binary`.
- CGO is **not** required to build `commit0-analyzer` itself.

Other useful targets:

```sh
make test      # go test ./... + JS plugin vitest (Node-gated)
make lint      # golangci-lint v2 (falls back to go vet if not installed)
make generate  # regenerate protobuf/gRPC stubs — only needed if proto/*.proto changed
make hooks     # install lefthook git hooks (run once after clone, for contributors)
```

## CI integration

### GitHub Actions — SARIF upload

```yaml
- name: Scan
  run: commit0-analyzer scan . --format sarif > commit0-analyzer.sarif
  continue-on-error: true   # capture the exit code below instead of failing the step
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: commit0-analyzer.sarif
```

### Exit-code handling

`commit0-analyzer scan` uses a three-way exit-code contract:

| Exit | Meaning | CI action |
|---|---|---|
| `0` | Scan completed; every finding is within policy. | Proceed. |
| `1` | Policy gate violation — one or more findings exceeded the configured threshold. | Fail the build/PR check. |
| `3` | Incomplete or operational error (plugin crash, missing deps, advisory fetch failure). | Fail the build/PR check — an incomplete scan must never be treated as passing. |

Exit `2` is intentionally unused. A minimal gate step:

```yaml
- name: Scan and gate
  run: |
    commit0-analyzer scan . --format sarif --fail-on high > commit0-analyzer.sarif
    status=$?
    if [ "$status" -ne 0 ]; then
      echo "commit0-analyzer scan failed (exit $status) — see SARIF/VEX output for details"
      exit "$status"
    fi
```

Do not swallow a non-zero exit code and continue the pipeline — exit `3`
means the scan could not prove the project is clean, which is by design
never conflated with exit `0`.

## Offline / air-gapped operation

`commit0-analyzer` supports fully network-free scans for reproducible or
air-gapped CI:

- **`--offline`** — disables network access entirely; reads from the
  existing writable cache or a pinned `--db-snapshot`. Never installs
  dependencies.
- **`--db-snapshot <dir>`** — pins the Go vulnerability database to a
  pre-built, read-only, manifest-verified snapshot directory. Two scans
  against the same snapshot produce byte-identical output.

Full snapshot format, cache directory locations, and the online/offline/
pinned-snapshot mode matrix are documented in
[`docs/usage.md`](./usage.md#advisory-db-modes) and
[`docs/usage.md`](./usage.md#advisory-snapshot-management) — this guide does
not duplicate that reference.

## Environment variables

Every advisory-source URL override, telemetry toggle, and cache-location
variable (`COMMIT0_VULN_DB_URL`, `COMMIT0_OSV_DB_URL`,
`COMMIT0_GITLAB_DB_URL`, `COMMIT0_NVD_API_URL`, `COMMIT0_EPSS_API_URL`,
`COMMIT0_EPSS_CSV_URL`, `GITHUB_TOKEN`, `COMMIT0_DEBUG`,
`COMMIT0_TELEMETRY`, `COMMIT0_BENCH`, and others) is documented with its
exact behavior in the **Environment variables** list under
[`docs/usage.md`](./usage.md#advisory-sources) (Advisory Sources section).
Treat that list as the single source of truth rather than duplicating it
here.

## License note for deployment

`commit0-analyzer` is AGPL-3.0. Running it as a CLI tool inside your own CI
pipeline — the only deployment model this guide covers — is not a licensing
concern; the copyleft implications are about embedding the engine as a
library inside a proprietary product. See
[`docs/soundness-limits.md`](./soundness-limits.md#license-note-agpl-30) for
the full note.
