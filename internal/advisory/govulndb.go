package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ─── OSV JSON types ───────────────────────────────────────────────────────────
//
// These are minimal structs covering only the fields we read from OSV-format
// records served by https://vuln.go.dev. They are unexported; the public surface
// is Advisory and Symbol in model.go.

type osvRecord struct {
	ID       string      `json:"id"`
	Aliases  []string    `json:"aliases"`
	Affected []osvAffect `json:"affected"`
	// Withdrawn is an RFC3339 timestamp present when the advisory has been
	// retracted by the Go vuln DB maintainers. A non-empty value means the
	// record is no longer considered a real vulnerability and must be excluded
	// from query results to avoid false-positive findings (mirrors govulncheck).
	Withdrawn string `json:"withdrawn"`
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
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
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

// parseOSVRecord parses a single OSV JSON record into an internal Advisory.
// It extracts:
//   - version ranges from affected[].ranges[] (SEMVER type only)
//   - symbols from affected[].ecosystem_specific.imports[].symbols
//   - SymbolLevel=true when any import entry has at least one symbol
//
// The returned Advisory has Sources=["go-vuln-db"].
// Only "Go" ecosystem entries are processed; others are silently skipped.
func parseOSVRecord(data []byte) (*Advisory, error) {
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
		if !strings.EqualFold(aff.Package.Ecosystem, "go") {
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
			vr := extractVersionRange(r.Events)
			if vr.Introduced != "" || vr.Fixed != "" {
				adv.VersionRanges = append(adv.VersionRanges, vr)
			} else {
				// At least one event existed but produced no useful range
				// — include an open-ended range (all versions affected).
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

	return adv, nil
}

// extractVersionRange converts a flat OSV events list into a single VersionRange.
// OSV interleaves introduced/fixed events; we take the last introduced and last
// fixed we encounter (MVP: single contiguous range per SEMVER block).
func extractVersionRange(events []osvEvent) VersionRange {
	var vr VersionRange
	for _, e := range events {
		if e.Introduced != "" {
			// "0" in OSV means "since the beginning" — normalise to empty so our
			// versionInRange treats it as unbounded lower.
			if e.Introduced == "0" {
				vr.Introduced = ""
			} else {
				vr.Introduced = e.Introduced
			}
		}
		if e.Fixed != "" {
			vr.Fixed = e.Fixed
		}
	}
	return vr
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

// Query implements Source. It scans every OSV file in dbDir, parses it, and
// returns advisories that match pkg.Name and whose version ranges include version.
// The scan is O(n) in the number of advisory files; the cache layer is expected
// to keep that set small (one directory per module, or a pre-filtered index).
//
// Returns (nil, nil) when pkg.Ecosystem is not EcosystemGo — this client is
// Go-only and silently passes on other ecosystems so a compose layer can route.
func (c *goVulnDBClient) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	// This source only handles Go modules.
	if pkg.Ecosystem != EcosystemGo {
		return nil, nil
	}

	entries, err := os.ReadDir(c.dbDir)
	if err != nil {
		return nil, fmt.Errorf("advisory: read db dir %q: %w", c.dbDir, err)
	}

	var results []Advisory
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Skip the manifest file.
		if entry.Name() == ManifestFilename {
			continue
		}

		data, err := os.ReadFile(filepath.Join(c.dbDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("advisory: read %q: %w", entry.Name(), err)
		}

		adv, err := parseOSVRecord(data)
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

		if adv.Module != pkg.Name {
			continue
		}
		if adv.AffectsVersion(version) {
			adv.Ecosystem = pkg.Ecosystem
			results = append(results, *adv)
		}
	}

	return results, nil
}
