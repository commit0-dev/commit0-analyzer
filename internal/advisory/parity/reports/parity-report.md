# Advisory parity report

Generated from: anst=anst corpus=4 baseline="go-vuln-db,osv" full="go-vuln-db,osv,ghsa"

## Coverage summary

| Corpus | Comparator | Shared | Sound suppression | Unknown surfaced | Misses (FN) | anst-unique |
|---|---|---|---|---|---|---|

## False negatives (misses)

None — anst carried a record for every comparator finding.

## Coverage gain over the 2-source baseline

Measured advisory-coverage delta of the full source set over the Go-DB + OSV baseline.

| Corpus | Baseline | Full | Baseline findings | Full findings | New findings |
|---|---|---|---|---|---|
| commit0-analyzer | go-vuln-db,osv | go-vuln-db,osv,ghsa | 47 | 47 | 0 |
| litellm | go-vuln-db,osv | go-vuln-db,osv,ghsa | 93 | 93 | 0 |
| log4shell-maven | go-vuln-db,osv | go-vuln-db,osv,ghsa | 0 | 0 | 0 |
| npm-monorepo | go-vuln-db,osv | go-vuln-db,osv,ghsa | 234 | 234 | 0 |

## Skipped comparators

- govulncheck: could not run on commit0-analyzer: run govulncheck: exit status 1
- grype: binary not on PATH (parity not claimed for this comparator)
- osv-scanner: could not run on npm-monorepo: run osv-scanner: exit status 1
- trivy: binary not on PATH (parity not claimed for this comparator)

## Empirical non-negotiables

- [PASS] determinism/commit0-analyzer: two identical runs byte-compared
- [PASS] determinism/litellm: two identical runs byte-compared
- [PASS] determinism/log4shell-maven: two identical runs byte-compared
- [PASS] determinism/npm-monorepo: two identical runs byte-compared
- [PASS] fail-closed/commit0-analyzer: injected source failure exit code = 3 (must be non-zero)
- [PASS] fail-closed/litellm: injected source failure exit code = 3 (must be non-zero)
- [PASS] fail-closed/log4shell-maven: injected source failure exit code = 3 (must be non-zero)
- [PASS] fail-closed/npm-monorepo: injected source failure exit code = 3 (must be non-zero)
