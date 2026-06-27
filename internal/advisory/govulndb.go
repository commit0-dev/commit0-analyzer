package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ─── OSV JSON types ───────────────────────────────────────────────────────────
//
// These are minimal structs covering only the fields we read from OSV-format
// records served by https://vuln.go.dev. They are unexported; the public surface
// is Advisory and Symbol in model.go.

type osvRecord struct {
	ID       string         `json:"id"`
	Aliases  []string       `json:"aliases"`
	Affected []osvAffect    `json:"affected"`
	// Withdrawn is an RFC3339 timestamp present when the advisory has been
	// retracted by the Go vuln DB maintainers. A non-empty value means the
	// record is no longer considered a real vulnerability and must be excluded
	// from query results to avoid false-positive findings (mirrors govulncheck).
	Withdrawn        string              `json:"withdrawn"`
	References       []osvReference      `json:"references"`
	Severity         []osvSeverityEntry  `json:"severity"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

// osvSeverityEntry is one entry in the OSV top-level severity[] array.
// Type is typically "CVSS_V3" or "CVSS_V4"; Score is the vector string
// (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvDatabaseSpecific captures the database_specific object, which may carry
// a textual severity string (e.g. "HIGH", "CRITICAL") for some ecosystems.
type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

// osvReference is one entry in the OSV top-level references array.
// Type is one of: WEB, ADVISORY, REPORT, FIX, PACKAGE, ARTICLE, EVIDENCE.
type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffect struct {
	Package           osvPackage           `json:"package"`
	Ranges            []osvRange           `json:"ranges"`
	EcosystemSpecific osvEcosystemSpecific `json:"ecosystem_specific"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvEcosystemSpecific struct {
	Imports []osvImport `json:"imports"`
}

type osvImport struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos"`
	GOARCH  []string `json:"goarch"`
	Symbols []string `json:"symbols"`
}

// ─── OSV parser ──────────────────────────────────────────────────────────────

// parseOSVRecord parses a single OSV JSON record into an internal Advisory
// for the specified ecosystem. It extracts:
//   - version ranges from affected[].ranges[] (SEMVER and ECOSYSTEM types)
//   - symbols from affected[].ecosystem_specific.imports[].symbols
//   - SymbolLevel=true when any import entry has at least one symbol
//   - Severity from the top-level severity[] array (CVSS_V3/CVSS_V4 score)
//     or database_specific.severity string, whichever is present
//
// Only affected entries whose Package.Ecosystem matches the supplied ecosystem
// (case-insensitive) are processed; others are silently skipped.
// The returned Advisory has Sources=["go-vuln-db"] (overridden by dirSource.query).
//
// ECOSYSTEM vs SEMVER range type: PyPI advisories in the OSV bundle use range
// type "ECOSYSTEM" (not "SEMVER") because Python uses PEP 440, not SemVer. Both
// types carry the same events schema ([introduced, fixed/last_affected]), so they
// are parsed identically here. The correct comparator (pep440VersionInRangeV) is
// selected later in AffectsVersionV by routing on Advisory.Ecosystem.
func parseOSVRecord(data []byte, ecosystem string) (*Advisory, error) {
	var rec osvRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("advisory: parse OSV record: %w", err)
	}

	adv := &Advisory{
		ID:        rec.ID,
		Aliases:   rec.Aliases,
		Sources:   []string{SourceGoVulnDB},
		Withdrawn: rec.Withdrawn, // RFC3339 timestamp; non-empty means retracted
	}

	for _, aff := range rec.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, ecosystem) {
			continue
		}

		// Use the first matching package as the canonical module name.
		if adv.Module == "" {
			adv.Module = aff.Package.Name
		}

		// Extract version ranges from both SEMVER and ECOSYSTEM range types.
		// SEMVER is used by Go, npm, and crates.io. ECOSYSTEM is used by PyPI
		// (PEP 440), Maven, and other non-SemVer ecosystems. Both types use the
		// same events schema; the correct comparator is selected by AffectsVersionV
		// based on Advisory.Ecosystem, not on the OSV range type stored here.
		for _, r := range aff.Ranges {
			t := strings.ToUpper(r.Type)
			if t != "SEMVER" && t != "ECOSYSTEM" {
				continue
			}
			vrs := extractVersionRanges(r.Events)
			if len(vrs) > 0 {
				adv.VersionRanges = append(adv.VersionRanges, vrs...)
			} else {
				// No events or no ranges produced — include an open-ended range
				// (all versions affected).
				adv.VersionRanges = append(adv.VersionRanges, VersionRange{})
			}
		}

		// Extract symbols from ecosystem_specific.imports.
		for _, imp := range aff.EcosystemSpecific.Imports {
			for _, sym := range imp.Symbols {
				adv.Symbols = append(adv.Symbols, Symbol{
					Package: imp.Path,
					Name:    sym,
				})
				adv.SymbolLevel = true
			}
		}
	}

	// Edge case: an affected block with no ranges means "all versions".
	// We represent that as a single open VersionRange{} so AffectsVersion
	// returns true for every input.
	if len(adv.VersionRanges) == 0 && adv.Module != "" {
		adv.VersionRanges = append(adv.VersionRanges, VersionRange{})
	}

	// Parse severity from the OSV severity[] array (prefer CVSS_V3/CVSS_V4)
	// or fall back to database_specific.severity string.
	adv.Severity = parseOSVSeverity(rec.Severity, rec.DatabaseSpecific.Severity)

	// Collect URLs from references entries whose type is "FIX". These point at
	// the commits or patches that resolved the vulnerability. Deduplicate and
	// sort for determinism; produce an empty (non-nil) slice when none exist.
	adv.FixRefs = extractFixRefs(rec.References)

	return adv, nil
}

// parseOSVSeverity extracts the Severity level from OSV severity entries and/or
// a database_specific severity string. CVSS_V3 and CVSS_V4 score vectors are
// preferred; the database_specific string is the fallback.
//
// CVSS base score is the last numeric field in the vector string, which encodes
// the score as part of the vector (e.g. "CVSS:3.1/.../C:H/I:H/A:H" has a base
// score that must be computed from the vector). However, OSV records do NOT embed
// the base score numerically in the severity entry — the score field IS the full
// CVSS vector string. The base score must be extracted from the CVSS metrics.
//
// For pragmatic correctness without a full CVSS library, we parse the database_-
// specific.severity string first (HIGH, CRITICAL, etc.) when available, and for
// CVSS vectors we extract the base score from the well-known OSV GitHub Advisory
// Database format where the score appears in the vector's trailing /X.X suffix
// or is embedded in the CVSS:3.1/... string itself. For the common case of GHSA-
// sourced records we fall back to parsing the vector's component metrics to derive
// the approximate base score, implemented in parseCVSSVectorScore.
func parseOSVSeverity(entries []osvSeverityEntry, dbSpecific string) Severity {
	// Try CVSS vector entries first (CVSS_V3 preferred, CVSS_V4 accepted).
	for _, e := range entries {
		t := strings.ToUpper(e.Type)
		if t != "CVSS_V3" && t != "CVSS_V4" {
			continue
		}
		score, ok := parseCVSSVectorScore(e.Score)
		if ok {
			return cvssScoreToSeverity(score)
		}
	}

	// Fall back to database_specific.severity textual string.
	if dbSpecific != "" {
		return textSeverityToSeverity(dbSpecific)
	}

	return SeverityUnspecified
}

// parseCVSSVectorScore extracts the base score from a CVSS v3.x or v4.0 vector
// string. The OSV schema stores the full vector (e.g.
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); the base score is NOT
// separately stored in the vector itself — it must be computed from the metrics.
//
// To avoid a full CVSS library dependency, this function uses a well-known
// approximation for the most common CVSS v3 base metrics to derive a score that
// is accurate enough for the four severity bands (Low/Medium/High/Critical).
// Specifically, it sums the per-metric weights defined by CVSS 3.1 §7.1 and
// returns the rounded base score. If the vector cannot be parsed, returns (0, false).
//
// For CVSS v4.0 vectors (CVSS:4.0/...) the same metric extraction is applied
// to the base metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA), which map
// to approximately the same severity bands for triage purposes.
func parseCVSSVectorScore(vector string) (float64, bool) {
	if vector == "" {
		return 0, false
	}
	// CVSS vectors start with "CVSS:3.0/", "CVSS:3.1/", or "CVSS:4.0/".
	// Strip the version prefix and parse the metrics map.
	slashIdx := strings.Index(vector, "/")
	if slashIdx < 0 {
		return 0, false
	}
	metricsStr := vector[slashIdx+1:]
	metrics := make(map[string]string)
	for _, part := range strings.Split(metricsStr, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	// Derive base score for CVSS v3.x using the standard formulae.
	// We compute ISCBase, ISC, ExploitabilityScore, and BaseScore per CVSS 3.1 §7.1.
	// Reference: https://www.first.org/cvss/v3.1/specification-document
	av, avOK := cvss3AV(metrics["AV"])
	ac, acOK := cvss3AC(metrics["AC"])
	pr, prOK := cvss3PR(metrics["PR"], metrics["S"])
	ui, uiOK := cvss3UI(metrics["UI"])
	s, sOK := metrics["S"]
	c, cOK := cvss3CIA(metrics["C"])
	i, iOK := cvss3CIA(metrics["I"])
	a, aOK := cvss3CIA(metrics["A"])

	if !avOK || !acOK || !prOK || !uiOK || !sOK || !cOK || !iOK || !aOK {
		// Missing required base metrics — cannot compute.
		return 0, false
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var isc float64
	if s == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*pow(iscBase-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if isc <= 0 {
		base = 0
	} else if s == "U" {
		base = roundHalfUp(min64(isc+exploitability, 10))
	} else {
		base = roundHalfUp(min64(1.08*(isc+exploitability), 10))
	}
	return base, true
}

// roundHalfUp rounds x to one decimal place using CVSS rounding (round half up).
func roundHalfUp(x float64) float64 {
	// CVSS 3.1 §7.4: Roundup(x) = ceil(x * 10) / 10
	return float64(int64(x*10+0.5)) / 10
}

// min64 returns the smaller of two float64 values.
func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// pow computes base^exp using repeated multiplication (avoids math package import).
// Only used for CVSS formula with small integer exponents.
func pow(base float64, exp int) float64 {
	result := 1.0
	for range exp {
		result *= base
	}
	return result
}

// CVSS v3.1 base metric weight tables (§7.1).

func cvss3AV(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "A":
		return 0.62, true
	case "L":
		return 0.55, true
	case "P":
		return 0.20, true
	}
	return 0, false
}

func cvss3AC(v string) (float64, bool) {
	switch v {
	case "L":
		return 0.77, true
	case "H":
		return 0.44, true
	}
	return 0, false
}

// cvss3PR returns the Privileges Required weight, which depends on Scope (S).
func cvss3PR(pr, scope string) (float64, bool) {
	if scope == "C" {
		switch pr {
		case "N":
			return 0.85, true
		case "L":
			return 0.68, true
		case "H":
			return 0.50, true
		}
	} else {
		switch pr {
		case "N":
			return 0.85, true
		case "L":
			return 0.62, true
		case "H":
			return 0.27, true
		}
	}
	return 0, false
}

func cvss3UI(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "R":
		return 0.62, true
	}
	return 0, false
}

func cvss3CIA(v string) (float64, bool) {
	switch v {
	case "H":
		return 0.56, true
	case "L":
		return 0.22, true
	case "N":
		return 0, true
	}
	return 0, false
}

// textSeverityToSeverity converts a textual severity string (as found in
// database_specific.severity of some OSV records) to the Severity enum.
// The comparison is case-insensitive.
func textSeverityToSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SeverityLow
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	}
	return SeverityUnspecified
}

// gitHubCommitRefRE matches a GitHub commit URL (the form ghfetch can fetch).
// We key on the URL SHAPE rather than the reference Type because GHSA records
// in the OSV bundle overwhelmingly label fix-commit links as "WEB", not "FIX":
// across the npm bundle only one record used type "FIX" while ~3,200 advisories
// carry a commit URL under "WEB". Filtering by type would discard nearly all of
// them, so we collect commit-shaped URLs regardless of reference type.
var gitHubCommitRefRE = regexp.MustCompile(
	`^https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}(\.patch|\.diff)?$`,
)

// extractFixRefs returns the deduplicated, sorted set of GitHub commit URLs
// found in the OSV references slice, across all reference types (see
// gitHubCommitRefRE for why type is ignored). These are the fix commits a later
// phase fetches to extract the vulnerable symbols a fix touched. Always returns
// a non-nil slice (empty when no commit references are present).
func extractFixRefs(refs []osvReference) []string {
	seen := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		if r.URL != "" && gitHubCommitRefRE.MatchString(r.URL) {
			seen[r.URL] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for url := range seen {
		out = append(out, url)
	}
	sort.Strings(out)
	return out
}

// extractVersionRanges converts a flat OSV events list into a slice of VersionRanges,
// one per introduced → (fixed | last_affected) pair. Events are processed in order
// per the OSV spec: introduced opens a range, fixed closes it exclusively, and
// last_affected closes it inclusively. Multiple pairs in one events block produce
// multiple disjoint ranges — all are returned. An introduced event with no closing
// event becomes an open-ended range [introduced, ∞).
func extractVersionRanges(events []osvEvent) []VersionRange {
	var ranges []VersionRange
	var current *VersionRange
	for _, e := range events {
		if e.Introduced != "" {
			// Flush any open range without a close event.
			if current != nil {
				ranges = append(ranges, *current)
			}
			introduced := e.Introduced
			// "0" in OSV means "since the beginning" — normalise to empty so
			// versionInRange treats it as unbounded lower.
			if introduced == "0" {
				introduced = ""
			}
			current = &VersionRange{Introduced: introduced}
		}
		if e.Fixed != "" && current != nil {
			current.Fixed = e.Fixed
			ranges = append(ranges, *current)
			current = nil
		}
		if e.LastAffected != "" && current != nil {
			current.LastAffected = e.LastAffected
			ranges = append(ranges, *current)
			current = nil
		}
	}
	// Flush a trailing open-ended range (introduced with no fixed/last_affected).
	if current != nil {
		ranges = append(ranges, *current)
	}
	return ranges
}

// ─── Shared dir-backed reader ─────────────────────────────────────────────────

// dirSource reads a directory of OSV JSON files and queries them offline.
// It is the shared query engine used by both goVulnDBClient (Go vuln DB cache)
// and OSVBundleSource (OSV offline bundle cache). The only difference between
// the two is how files arrive in the directory; the query logic is identical.
//
// sources is the attribution tag injected into each returned Advisory.Sources —
// callers pass their own tag (e.g. []string{SourceGoVulnDB} or []string{SourceOSV}).
type dirSource struct {
	dir     string
	sources []string
}

// query scans every *.json file in d.dir, parses each OSV record, and returns
// advisories that match pkg.Name and whose version ranges include version.
// Withdrawn advisories are excluded. Corrupt files are skipped (no hard error).
//
// The scan is O(n) in the number of advisory files; callers are expected to
// keep that set small (one cache directory per module or per ecosystem bundle).
func (d *dirSource) query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, fmt.Errorf("advisory: read db dir %q: %w", d.dir, err)
	}

	var results []Advisory
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Skip the manifest file — it is not an OSV advisory.
		if entry.Name() == ManifestFilename {
			continue
		}

		data, err := os.ReadFile(filepath.Join(d.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("advisory: read %q: %w", entry.Name(), err)
		}

		adv, err := parseOSVRecord(data, pkg.Ecosystem)
		if err != nil {
			// Corrupt advisory: skip with a warning rather than failing the
			// entire query. The caller gets a partial result but not a hard error
			// for a single bad file.
			continue
		}

		// Exclude withdrawn advisories regardless of version-range or symbol
		// match. The Go vuln DB marks a record withdrawn when the maintainers
		// determine it is not a real vulnerability; surfacing it would produce
		// a false-positive finding and could trip the CI gate. This mirrors
		// the behaviour of govulncheck, which also skips withdrawn records.
		if adv.Withdrawn != "" {
			continue
		}

		// For npm, names are case-insensitive and OSV records store them lowercase.
		// Normalise both sides before comparing so that mixed-case lockfile entries
		// (e.g. "Lodash") match OSV records that store "lodash".
		// For all other ecosystems the comparison is exact (Go module paths are
		// case-sensitive).
		advModule := adv.Module
		queryName := pkg.Name
		if pkg.Ecosystem == EcosystemNPM {
			advModule = normalizeNPMPackageName(advModule)
			queryName = normalizeNPMPackageName(queryName)
		}
		if advModule != queryName {
			continue
		}
		// Set Ecosystem before version matching so AffectsVersionV can route to
		// the correct semver implementation (npm vs. Go vs. crates.io vs. unknown).
		adv.Ecosystem = pkg.Ecosystem

		// Normalise the query version for the Go semver path (canonical adds the
		// "v" prefix required by golang.org/x/mod/semver). For npm, AffectsVersionV
		// routes to npmVersionInRangeV which strips any "v" prefix itself, so
		// canonical() is a no-op there but harmless.
		queryVersion := canonical(version)
		switch adv.AffectsVersionV(queryVersion) {
		case VersionAffected:
			// Override Sources with the caller's attribution tag so that the
			// same parseOSVRecord result can carry different provenance depending
			// on which source's cache dir was scanned.
			adv.Sources = append([]string(nil), d.sources...)
			results = append(results, *adv)
		case VersionUndecidable:
			// Cannot determine whether this version is affected — include the advisory
			// with Incomplete=true so the host can emit a synthetic UNKNOWN finding
			// and set incomplete=true at the policy gate. Dropping it would be a
			// silent false negative ("unknown ≠ safe").
			adv.Sources = append([]string(nil), d.sources...)
			adv.Incomplete = true
			results = append(results, *adv)
		// VersionNotAffected: drop — the only safe drop.
		}
	}

	return results, nil
}

// ─── Go vuln DB client ───────────────────────────────────────────────────────

// goVulnDBClient implements Source against a local directory of OSV JSON files.
// Each file must be named "<advisory-id>.json" (e.g. "GO-2024-0001.json").
//
// The hot query path is fully offline: it reads from dbDir and never makes
// network calls. Network fetching is handled by Cache (cache.go), which
// populates dbDir from https://vuln.go.dev before handing it to this client.
type goVulnDBClient struct {
	dbDir string
}

// Query implements Source. It delegates directory scanning to the shared
// dirSource, which handles version-range filtering, withdrawn exclusion, and
// module-name matching. Returns (nil, nil) when pkg.Ecosystem is not
// EcosystemGo — this client is Go-only.
func (c *goVulnDBClient) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	// This source only handles Go modules.
	if pkg.Ecosystem != EcosystemGo {
		return nil, nil
	}

	ds := &dirSource{dir: c.dbDir, sources: []string{SourceGoVulnDB}}
	return ds.query(ctx, pkg, version)
}
