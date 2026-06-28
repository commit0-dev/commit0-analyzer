# Phase 01 – Code Rename Execution Report

**Branch:** `chore/rename-commit0-analyzer`
**Commits:** `5902f7c`, `55d8b46`, `bb72d6c`, `117bb06`
**Date:** 2026-06-28

---

## Summary

Phase 1 is fully complete. All tests pass. No residual `anst`/`ANST_`/`ducthinh993` references remain in source, docs, or config outside testdata.

---

## Sweeps Executed

### Phase 1 sweeps (commit 5902f7c)

Five ordered token sweeps ran on tracked in-scope files (excluding `testdata/`, `plans/`, `node_modules/`, `dist/`, `src/gen/`, `pkg/contract/anstv1/`):

1. **Go module path** — `github.com/ducthinh993/anst-analyzer` → `github.com/commit0-dev/commit0-analyzer`
2. **Magic cookie + XDG cache dir + VEX strings** — `anst-analyzer` → `commit0-analyzer`
3. **Proto package** — `anst.v1` → `commit0.v1`
4. **buf module opts** — `anstv1` → `commit0v1`
5. **Camel-case identifier** — `AnstAnalyzer` → `Commit0Analyzer`

Two additional sweeps were required beyond the five:

- **TS gen import paths** — `gen/anst/v1` → `gen/commit0/v1`
- **cmd path in tests** — `cmd/anst` → `cmd/commit0-analyzer`

### Phase 1 completion sweeps (commit 55d8b46)

6. **Env-var prefix** — `ANST_` → `COMMIT0_` (119 occurrences across 19 files). Covers: `COMMIT0_PLUGIN_MAGIC_COOKIE`, `COMMIT0_CARGO_OFFLINE`, `COMMIT0_DEBUG`, `COMMIT0_TELEMETRY`, `COMMIT0_OSV_DB_URL`, `COMMIT0_VULN_DB_URL`, `COMMIT0_GHSA_GRAPHQL_URL`, `COMMIT0_GITLAB_DB_URL`, `COMMIT0_NVD_API_URL`, `COMMIT0_KEV_URL`, `COMMIT0_EPSS_API_URL`, `COMMIT0_EPSS_CSV_URL`, `COMMIT0_SNAPSHOT_STALENESS`, `COMMIT0_BENCH`, and parity harness vars.

7. **Bare-word brand rename** — `\banst\b` → `commit0-analyzer` across all prose, comments, strings, cache filenames, and temp file prefixes. 203 occurrences across 36+ files. Two regressions required fixes (see below).

---

## Directory Renames (`git mv`)

| Old | New |
|-----|-----|
| `proto/anst/v1/plugin.proto` | `proto/commit0/v1/plugin.proto` |
| `cmd/anst/` | `cmd/commit0-analyzer/` |
| `pkg/contract/anstv1/` | `pkg/contract/commit0v1/` |

Plugin binaries (`plugins/*/dist/anst-*`) were not git-tracked (dist/ gitignore). Renamed in-place with `mv`.

---

## Stub Regeneration

```
cd plugins/js-reachability && npm install
cd /repo && make generate
rm -rf plugins/js-reachability/src/gen/anst
```

Generated outputs:
- `pkg/contract/commit0v1/plugin.pb.go` — `package commit0v1`
- `pkg/contract/commit0v1/plugin_grpc.pb.go`
- `plugins/js-reachability/src/gen/commit0/v1/plugin.ts`

---

## Bun Installation and JS Plugin Recompile

Bun v1.3.14 installed via official installer to `~/.bun/bin/bun`.

```
PATH="$HOME/.bun/bin:$PATH" make build-js-plugin
```

Result: `plugins/js-reachability/dist/commit0-js-reachability` rebuilt from source. Now serves:
- gRPC service `commit0.v1.Analyzer`
- Magic cookie key `COMMIT0_PLUGIN_MAGIC_COOKIE`
- Magic cookie value `commit0-analyzer-v0-plugin`

`pkg/plugin/handshake.go` updated: `MagicCookieKey = "COMMIT0_PLUGIN_MAGIC_COOKIE"` and `MagicCookieValue = "commit0-analyzer-v0-plugin"` (TODO holdover comment removed).

---

## Plugin Binary Rebuilds

| Plugin | Method | Result |
|--------|--------|--------|
| js-reachability | `make build-js-plugin` (bun) | Rebuilt: `commit0.v1.Analyzer`, new cookie |
| rust-reachability | `go build -o dist/commit0-rust-reachability ./plugins/rust-reachability/` | Rebuilt |
| python-reachability | `go build -o dist/commit0-python-reachability ./plugins/python-reachability/` | Rebuilt |

All plugins are in the same Go module (`github.com/commit0-dev/commit0-analyzer`); no separate build steps needed beyond `go build`.

---

## Regressions Fixed

### 1. Hyphen-in-Go-identifier (parity package)

The bare-word sweep replaced Go variable/parameter `anst` with `commit0-analyzer`, which contains a hyphen — invalid in Go identifiers. Files affected: `compare.go`, `compare_test.go`, `assert_test.go`, `report_test.go`.

Fix: renamed those specific parameters/variables to `commit0Analyzer` (camelCase). Comments and string literals that legitimately contain `commit0-analyzer` were preserved.

### 2. Testdata fixture file references

The sweep renamed string literals `"anst.json"` → `"commit0-analyzer.json"` and `"anst-openvex.json"` → `"commit0-analyzer-openvex.json"` inside `readFixture(t, ...)` calls. The actual testdata files (`testdata/anst.json`, `testdata/anst-openvex.json`) were correctly NOT renamed. This caused the tests to look for non-existent files.

Fix: reverted those specific string literals to reference the original filenames.

### 3. Testdata snapshot manifest filename

The `ManifestFilename` constant changed from `"anst-snapshot-manifest.json"` to `"commit0-analyzer-snapshot-manifest.json"`. The integration test fixture at `testdata/corpus/db-snapshot/anst-snapshot-manifest.json` was NOT renamed by the sweep (testdata exclusion). This caused 3 Go integration tests to fail with exit=3 instead of exit=1 because the snapshot was treated as unpopulated.

Fix: renamed `testdata/corpus/db-snapshot/anst-snapshot-manifest.json` → `commit0-analyzer-snapshot-manifest.json`. This is the project's own integration test fixture (not vendored repo content), so renaming it to match the code is correct.

---

## Golden File Updates (Phase 1)

Golden files in `internal/vex/testdata/` and `internal/render/testdata/` are project-owned expected-output fixtures and were updated:

- `internal/vex/testdata/openvex.golden.json` — `author`, `@id` updated
- `internal/vex/testdata/cyclonedx.golden.json` — `name` updated
- `internal/vex/testdata/csaf.golden.json` — `name`, `namespace`, `title`, `id` updated; regenerated with `-update` flag
- `internal/render/testdata/sarif_symbol_reachable.golden.json` — `name`, `informationUri` updated
- `internal/render/testdata/sarif_mixed.golden.json` — same

---

## Build and Test Results

### `go build ./...`
SUCCESS

### `go vet ./...`
SUCCESS (no findings)

### `go test ./...`
**1841 tests PASS, 0 FAIL** (25 packages)

Previously 10 failing tests (`TestScan*`/`TestEcosystem*` in `internal/cli/`) are now all GREEN after:
- JS plugin recompile resolves gRPC service name mismatch (`commit0.v1.Analyzer` now consistent host↔plugin)
- Manifest filename rename resolves snapshot lookup failure in 3 integration tests

### `npx vitest run` (plugins/js-reachability)
**449 tests PASS, 0 FAIL**

(Pre-existing OXC worker crash flakiness was 0–3 failures per run in Phase 1; this run: 0.)

---

## Residual Scan Result

Command per spec:
```
git grep -nE 'ducthinh993|anst-analyzer|anst\.v1|anstv1|anst-[a-z]*-reachability|ANST_|\banst\b' \
  -- ':!testdata' ':!plans'
```

**Result: 1 match** — `internal/advisory/parity/testdata/anst-openvex.json:4`

This file is inside `testdata/` and must not be touched. Content (`"author": "anst-analyzer"`) is intentional fixture data. This match is acceptable per the exclusion rule.

**Zero matches outside testdata.**

---

---

## Mixed-Case Anst Identifier Cleanup (commit 117bb06)

A follow-up sweep inside `internal/advisory/parity/` completed after the initial residual scan, renaming all remaining mixed-case `Anst` Go identifiers:

| Old | New |
|-----|-----|
| `ParseAnst` | `ParseCommit0` |
| `ParseAnstVEX` | `ParseCommit0VEX` |
| `ToolAnst` | `ToolCommit0` |
| `DeltaAnstUnique` | `DeltaCommit0Unique` |
| `AnstCount` / `"anst_count"` | `Commit0Count` / `"commit0_count"` |
| `AnstUnique` / `"anst_unique"` | `Commit0Unique` / `"commit0_unique"` |
| `classifyAgainstAnst` | `classifyAgainstCommit0` |
| `matchedAnst` / `anstIdx` | `matchedCommit0` / `commit0Idx` |
| `AnstBinary` | `Commit0Binary` |
| `runAnst` / `runAnstVEX` | `runCommit0` / `runCommit0VEX` |
| `anstFindings` / `anstOut` / `anstCode` / `anstOut2` | `commit0Findings` / `commit0Out` / `commit0Code` / `commit0Out2` |
| All `TestParseAnst*` functions | `TestParseCommit0*` |

Testdata files renamed:
- `testdata/anst.json` → `testdata/commit0.json`
- `testdata/anst-openvex.json` → `testdata/commit0-openvex.json`

Fixture content updated: `"author"` and `"@id"` fields reflect `commit0-analyzer` / `commit0.dev`.

All 50 parity tests pass. Full suite 1841/1841.

---

## Final Residual Scan Result

Command:
```
git grep -niE 'anst' -- ':!testdata/acceptance/repos' ':!*/dist/*' | grep -viE 'constant|instance|substan|distance'
```

**Result after commit 117bb06:**

Zero project-owned matches. The only remaining grep hits are:
- `internal/host/client.go` etc.: `anstplugin` import alias — outside `internal/advisory/parity/` scope, deliberately kept as an alias for the hashicorp plugin package. Not a brand reference.
- `release-manifest.json`: false positives from `tanstack` (case-insensitive match).

**Zero semantic `anst` references remain in project source.**

---

## Conclusion

Phase 1 is fully complete. 209 files changed across 4 commits on `chore/rename-commit0-analyzer`. All 1841 Go tests pass. All 449 vitest tests pass. Residual scan is zero in project-owned source.
