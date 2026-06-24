package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Withdrawn  string         `json:"withdrawn"`
	References []osvReference `json:"references"`
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
//   - version ranges from affected[].ranges[] (SEMVER type only)
//   - symbols from affected[].ecosystem_specific.imports[].symbols
//   - SymbolLevel=true when any import entry has at least one symbol
//
// Only affected entries whose Package.Ecosystem matches the supplied ecosystem
// (case-insensitive) are processed; others are silently skipped.
// The returned Advisory has Sources=["go-vuln-db"] (overridden by dirSource.query).
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

		// Use the first Go ecosystem package as the canonical module.
		if adv.Module == "" {
			adv.Module = aff.Package.Name
		}

		// Extract SEMVER ranges.
		for _, r := range aff.Ranges {
			if !strings.EqualFold(r.Type, "semver") {
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

	// Collect URLs from references entries whose type is "FIX". These point at
	// the commits or patches that resolved the vulnerability. Deduplicate and
	// sort for determinism; produce an empty (non-nil) slice when none exist.
	adv.FixRefs = extractFixRefs(rec.References)

	return adv, nil
}

// extractFixRefs returns the deduplicated, sorted set of URLs from the OSV
// references slice whose Type field equals "FIX" (case-insensitive).
// Always returns a non-nil slice (empty when no FIX references are present).
func extractFixRefs(refs []osvReference) []string {
	seen := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "FIX") && r.URL != "" {
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
		// Set Ecosystem before version matching so AffectsVersion can route to
		// the correct semver implementation (npm vs. Go).
		adv.Ecosystem = pkg.Ecosystem

		// Normalise the query version for the Go semver path (canonical adds the
		// "v" prefix required by golang.org/x/mod/semver). For npm, AffectsVersion
		// routes to npmVersionInRange which strips any "v" prefix itself, so
		// canonical() is a no-op there but harmless.
		queryVersion := canonical(version)
		if adv.AffectsVersion(queryVersion) {
			// Override Sources with the caller's attribution tag so that the
			// same parseOSVRecord result can carry different provenance depending
			// on which source's cache dir was scanned.
			adv.Sources = append([]string(nil), d.sources...)
			results = append(results, *adv)
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
