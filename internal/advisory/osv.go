package advisory

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SourceOSV is the source attribution tag for the OSV.dev vulnerability database.
const SourceOSV = "osv.dev"

// OSV offline bundle URL template:
//
//	GET https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip
//
// Reference: https://google.github.io/osv-scanner/usage/offline-mode/
const osvDefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Zip-bomb guards. These apply per-file, per-entry-count, and in aggregate
// across the entire extracted bundle. Bundle sizes vary widely by ecosystem:
// the Go bundle is ~20 MiB, but the npm bundle is ~333 MiB uncompressed across
// ~221k advisory files. The caps below accommodate the largest current
// ecosystem with headroom while still bounding a decompression bomb.
const (
	// maxPerFileBytes is the maximum uncompressed size of a single zip entry.
	// 10 MiB — no individual OSV record should approach this.
	maxPerFileBytes = 10 << 20 // 10 MiB

	// maxTotalExtractedBytes is the maximum total uncompressed size across all
	// accepted entries in one bundle. 1 GiB — comfortably above the npm bundle
	// (~333 MiB) with room to grow; entries are streamed to disk, not buffered
	// in memory, so this bounds disk use, not RAM.
	maxTotalExtractedBytes = 1 << 30 // 1 GiB

	// maxEntries bounds the number of accepted entries — a complementary defense
	// against archives padded with a huge count of tiny files. The npm bundle has
	// ~221k entries today; cap well above that to allow growth.
	maxEntries = 4 << 20 // 4,194,304
)

// ─── Functional options ───────────────────────────────────────────────────────

// osvOption is a functional option for NewOSVBundleSource.
type osvOption func(*OSVBundleSource)

// ─── OSVBundleSource ─────────────────────────────────────────────────────────

// OSVBundleSource implements Source against the OSV offline bundle model.
// It downloads <BaseURL>/<ecosystem>/all.zip, safe-extracts the OSV JSON records
// into <cacheDir>/<ecosystem>/, and queries them fully offline via the shared
// dirSource. The manifest is written last so a crash mid-extraction leaves no
// valid manifest, forcing a re-fetch on the next Refresh.
//
// Thread safety: Refresh and Query are safe to call from multiple goroutines —
// Refresh acquires a directory lock (flock) and Query is read-only after
// extraction. Concurrent Refresh calls for the same ecosystem will serialise via
// the lock; concurrent Query calls are always safe.
type OSVBundleSource struct {
	// BaseURL is the root URL of the OSV GCS bucket (no trailing slash).
	// Defaults to "https://osv-vulnerabilities.storage.googleapis.com".
	BaseURL string
	// HTTP is the client used for bundle downloads. A 60-second timeout is set
	// by default to accommodate large initial downloads (Go bundle ~50 MiB
	// compressed); callers may inject a shorter-timeout client for tests.
	HTTP *http.Client
	// ForceUpdate, when true, causes Refresh to re-download the bundle even
	// when the server responds 304 Not Modified (mirrors Cache.ForceUpdate).
	ForceUpdate bool
	// StalenessWarning is unused by OSVBundleSource (bundles are refreshed
	// explicitly via Refresh); retained for API symmetry with CacheConfig.
	StalenessWarning time.Duration

	// cacheDir is the root directory under which per-ecosystem subdirectories
	// are created. Never mutated after construction.
	cacheDir string

	// maxTotalExtracted and maxExtractEntries are the aggregate zip-bomb caps
	// applied during extraction. They default to maxTotalExtractedBytes and
	// maxEntries; tests inject small values to exercise the guards without
	// gigabyte fixtures.
	maxTotalExtracted int64
	maxExtractEntries int64

	// indexMu guards indexes, a per-ecosystem-directory cache of the advisory
	// index. A large bundle (npm has ~221k records) is parsed once into a
	// name-keyed index so each package query is a map lookup rather than a full
	// directory rescan. The cache lives for the source's lifetime (one scan).
	indexMu sync.Mutex
	indexes map[string]*advisoryIndex
}

// NewOSVBundleSource returns an OSVBundleSource that caches bundles under
// cacheDir. Apply functional options to override the default BaseURL,
// HTTP client, or ForceUpdate flag.
func NewOSVBundleSource(cacheDir string, opts ...osvOption) *OSVBundleSource {
	s := &OSVBundleSource{
		BaseURL:           osvDefaultBaseURL,
		HTTP:              &http.Client{Timeout: 60 * time.Second},
		cacheDir:          cacheDir,
		maxTotalExtracted: maxTotalExtractedBytes,
		maxExtractEntries: maxEntries,
		indexes:           make(map[string]*advisoryIndex),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ecoDir returns the per-ecosystem cache directory path.
func (s *OSVBundleSource) ecoDir(ecosystem string) string {
	return filepath.Join(s.cacheDir, ecosystem)
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

// Refresh ensures the local cache for ecosystem is populated and up-to-date.
// It performs a conditional GET (If-None-Match with the stored ETag) when a
// prior manifest exists, skipping extraction when the server responds 304.
//
// Failure semantics ("unknown ≠ safe"):
//   - Any HTTP non-200/non-304 status, network error, read error, zip-safety
//     violation, or extraction error is a hard error.
//   - On any error, the manifest is NOT written, so verifyManifest will fail on
//     the next Query call, forcing a re-fetch.
//   - The manifest is written LAST after all entries are extracted, so a crash
//     mid-extraction is detected by the missing manifest on the next call.
func (s *OSVBundleSource) Refresh(ctx context.Context, ecosystem string) error {
	dir := s.ecoDir(ecosystem)

	// Create the ecosystem directory before locking (lockDir needs to open a
	// file inside it).
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("advisory: osv: create cache dir %q: %w", dir, err)
	}

	// Acquire cross-process directory lock for the duration of Refresh.
	unlock, err := lockDir(dir)
	if err != nil {
		return fmt.Errorf("advisory: osv: lock cache dir %q: %w", dir, err)
	}
	defer unlock()

	// Read the stored ETag from the manifest (if any) to use in a conditional GET.
	storedETag := s.readStoredETag(dir)

	// Decide whether to skip the download entirely.
	if !s.ForceUpdate && storedETag != "" {
		// We have a prior ETag — issue a conditional GET.
		fresh, err := s.isNotModified(ctx, ecosystem, storedETag)
		if err != nil {
			return err
		}
		if fresh {
			// 304 Not Modified — bundle is still current, nothing to do.
			return nil
		}
	}

	// Download the bundle (either first fetch, ForceUpdate, or ETag mismatch).
	zipData, newETag, err := s.downloadBundle(ctx, ecosystem)
	if err != nil {
		return err
	}

	// Safe-extract the zip into the ecosystem directory.
	// Any safety violation → hard error, no manifest written.
	if err := safeExtractZip(zipData, dir, s.maxTotalExtracted, s.maxExtractEntries); err != nil {
		return fmt.Errorf("advisory: osv: extract %s/all.zip: %w", ecosystem, err)
	}

	// Build the version stamp: prefer the response ETag; fall back to timestamp.
	version := newETag
	if version == "" {
		version = time.Now().UTC().Format(time.RFC3339)
	}

	// Write manifest LAST so a crash between extraction and here leaves the dir
	// without a valid manifest, triggering a re-fetch on the next Refresh.
	if err := writeManifestToDir(dir, version); err != nil {
		return fmt.Errorf("advisory: osv: write manifest for %s: %w", ecosystem, err)
	}

	return nil
}

// readStoredETag returns the DBSourceVersion from the ecosystem's manifest, which
// stores the last-seen ETag. Returns "" when no valid manifest exists.
func (s *OSVBundleSource) readStoredETag(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFilename))
	if err != nil {
		return ""
	}
	var m SnapshotManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	// DBSourceVersion holds either an ETag or an RFC3339 timestamp.
	// Treat it as an ETag only when it looks like one (starts with `"`).
	if strings.HasPrefix(m.DBSourceVersion, `"`) {
		return m.DBSourceVersion
	}
	return ""
}

// isNotModified issues a conditional GET with If-None-Match and returns true
// when the server responds 304 Not Modified.
func (s *OSVBundleSource) isNotModified(ctx context.Context, ecosystem, etag string) (bool, error) {
	url := s.BaseURL + "/" + ecosystem + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("advisory: osv: build request for %s: %w", url, err)
	}
	req.Header.Set("If-None-Match", etag)

	resp, err := s.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("advisory: osv: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return true, nil
	case http.StatusOK:
		// Caller should do a full download; signal not-modified=false.
		return false, nil
	default:
		return false, fmt.Errorf("advisory: osv: GET %s: unexpected status %d", url, resp.StatusCode)
	}
}

// downloadBundle downloads <BaseURL>/<ecosystem>/all.zip and returns the raw
// zip bytes plus the response ETag (which may be empty).
// A non-200 status is a hard error.
func (s *OSVBundleSource) downloadBundle(ctx context.Context, ecosystem string) ([]byte, string, error) {
	url := s.BaseURL + "/" + ecosystem + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("advisory: osv: build request for %s: %w", url, err)
	}

	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("advisory: osv: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("advisory: osv: GET %s: unexpected status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("advisory: osv: read body from %s: %w", url, err)
	}

	return data, resp.Header.Get("ETag"), nil
}

// ─── Zip safe-extraction ──────────────────────────────────────────────────────

// safeExtractZip extracts OSV JSON files from zipData into destDir.
//
// Safety invariants enforced (zip-bomb + path-traversal guards):
//   - Entries with path separators that traverse outside destDir ("..") → hard error.
//   - Entries with absolute paths (starting with "/") → hard error.
//   - Only "*.json" entries are extracted; directories and other types are skipped.
//   - Per-file uncompressed size > maxPerFileBytes → hard error.
//   - Total uncompressed bytes across all accepted entries > maxTotalExtractedBytes → hard error.
//
// Each accepted entry is written via atomicWrite so that concurrent readers
// never observe a partially-written file.
func safeExtractZip(zipData []byte, destDir string, maxTotal, maxEntriesLimit int64) error {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	var totalExtracted int64
	var entryCount int64

	for _, f := range r.File {
		name := f.Name

		// Skip directories — we only want JSON files.
		if f.FileInfo().IsDir() {
			continue
		}

		// Guard: only accept *.json entries.
		if !strings.HasSuffix(name, ".json") {
			continue
		}

		// Guard: bound the number of accepted entries.
		entryCount++
		if entryCount > maxEntriesLimit {
			return fmt.Errorf(
				"zip-bomb guard: entry count exceeds %d limit",
				maxEntriesLimit,
			)
		}

		// Guard: reject absolute paths (e.g. "/etc/evil.json").
		if filepath.IsAbs(name) {
			return fmt.Errorf("path safety violation: absolute path in zip entry %q", name)
		}

		// Guard: reject path traversal sequences (e.g. "../escaped.json").
		// Clean the path and check it doesn't escape the root.
		cleaned := filepath.Clean(name)
		if strings.HasPrefix(cleaned, "..") {
			return fmt.Errorf("path safety violation: traversal in zip entry %q", name)
		}
		// Also check for leading separator after cleaning (belt-and-suspenders).
		if filepath.IsAbs(cleaned) {
			return fmt.Errorf("path safety violation: absolute cleaned path for zip entry %q", name)
		}

		// Guard: per-file size cap.
		if f.UncompressedSize64 > maxPerFileBytes {
			return fmt.Errorf(
				"zip-bomb guard: entry %q uncompressed size %d exceeds %d byte limit",
				name, f.UncompressedSize64, maxPerFileBytes,
			)
		}

		// Open the entry and read up to maxPerFileBytes+1 bytes so we detect
		// entries that lie about their uncompressed size.
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxPerFileBytes+1))
		_ = rc.Close()
		if err != nil {
			return fmt.Errorf("read zip entry %q: %w", name, err)
		}
		if int64(len(data)) > maxPerFileBytes {
			return fmt.Errorf(
				"zip-bomb guard: entry %q actual content exceeds %d byte per-file limit",
				name, maxPerFileBytes,
			)
		}

		// Guard: aggregate total size cap.
		totalExtracted += int64(len(data))
		if totalExtracted > maxTotal {
			return fmt.Errorf(
				"zip-bomb guard: total extracted size exceeds %d byte limit",
				maxTotal,
			)
		}

		// Use only the base filename — discard any subdirectory component in the
		// zip entry name so all files land flat in destDir. fsync=false: a bundle
		// has up to ~221k entries, so we skip per-file fsync and flush the whole
		// batch once via syncDir below. Crash-safety is preserved because the
		// caller writes the validating manifest only after this returns.
		dest := filepath.Join(destDir, filepath.Base(cleaned))
		if err := atomicWrite(dest, data, false); err != nil {
			return fmt.Errorf("write entry %q: %w", name, err)
		}
	}

	// Flush all the batched renames to stable storage once, before the caller
	// writes the manifest that marks this cache valid.
	if err := syncDir(destDir); err != nil {
		return err
	}

	return nil
}

// ─── Query ────────────────────────────────────────────────────────────────────

// Query returns advisories from the OSV bundle cache for pkg at version.
// It delegates to the shared dirSource over <cacheDir>/<pkg.Ecosystem>/.
//
// If the ecosystem cache directory does not exist (i.e. Refresh has not been
// called for this ecosystem), Query returns (nil, nil) — not an error. The
// caller is responsible for calling Refresh before the first Query.
//
// Returned advisories have Sources=["osv.dev"] and Ecosystem=pkg.Ecosystem.
// Withdrawn advisories are excluded (inherited from parseOSVRecord via dirSource).
func (s *OSVBundleSource) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	dir := s.ecoDir(pkg.Ecosystem)

	// If the ecosystem directory doesn't exist, return empty, nil.
	// This is the "not yet refreshed" state, not an error.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	idx, err := s.indexFor(ctx, dir, pkg.Ecosystem)
	if err != nil {
		return nil, err
	}
	return idx.lookup(pkg, version, []string{SourceOSV}), nil
}

// indexFor returns the advisory index for an ecosystem cache directory, building
// and caching it on first use. The lock serialises concurrent first-builders;
// after the index exists, lookups are read-only.
func (s *OSVBundleSource) indexFor(ctx context.Context, dir, ecosystem string) (*advisoryIndex, error) {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if idx, ok := s.indexes[dir]; ok {
		return idx, nil
	}
	idx, err := buildAdvisoryIndex(ctx, dir, ecosystem)
	if err != nil {
		return nil, err
	}
	s.indexes[dir] = idx
	return idx, nil
}

// advisoryIndex groups parsed, non-withdrawn advisories by their per-ecosystem
// normalized module name. It makes a per-package query a map lookup instead of
// a full directory rescan — essential for the npm bundle (~221k records), which
// the scan-every-file path of dirSource.query is too slow for.
type advisoryIndex struct {
	byName map[string][]Advisory
}

// buildAdvisoryIndex parses every *.json advisory in dir once and groups them by
// normalized module name. Unlike dirSource.query, it creates one Advisory per
// affected package entry rather than merging all entries in a record into one.
// This prevents cross-package range pollution in multi-package OSV records (e.g.
// a single GHSA affecting langsmith, langchain-classic, and langchain with
// different fixed bounds must not add the langchain-classic range to langsmith).
//
// For entries with no SEMVER/ECOSYSTEM ranges but an explicit versions[] list,
// the versions list is stored on Advisory.Versions for exact-membership matching.
// For entries with only GIT ranges, the advisory is stored with empty VersionRanges
// and empty Versions so AffectsVersionV returns VersionUndecidable (forwarded with
// Incomplete=true — unknown ≠ safe).
func buildAdvisoryIndex(ctx context.Context, dir, ecosystem string) (*advisoryIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("advisory: index db dir %q: %w", dir, err)
	}
	idx := &advisoryIndex{byName: make(map[string][]Advisory)}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == ManifestFilename {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("advisory: read %q: %w", entry.Name(), err)
		}
		advs, err := parseOSVRecordPerPackage(data, ecosystem)
		if err != nil {
			// Corrupt advisory: skip with no hard error (matches dirSource.query).
			continue
		}
		for i := range advs {
			if advs[i].Withdrawn != "" {
				continue
			}
			key := advs[i].Module
			if ecosystem == EcosystemNPM {
				key = normalizeNPMPackageName(key)
			}
			idx.byName[key] = append(idx.byName[key], advs[i])
		}
	}
	return idx, nil
}

// osvAffectWithVersions extends the package-internal osvAffect type with the
// OSV affected[].versions field, which lists specific enumerated versions.
// The govulndb.go osvAffect type does not include this field because the Go
// vuln DB does not use it; it is present in PyPI/npm/malware OSV records.
type osvAffectWithVersions struct {
	Package           osvPackage           `json:"package"`
	Ranges            []osvRange           `json:"ranges"`
	Versions          []string             `json:"versions"`
	EcosystemSpecific osvEcosystemSpecific `json:"ecosystem_specific"`
}

// osvRecordWithVersions mirrors osvRecord but uses osvAffectWithVersions so
// the per-entry versions[] list is captured during JSON decoding.
type osvRecordWithVersions struct {
	ID               string                  `json:"id"`
	Aliases          []string                `json:"aliases"`
	Affected         []osvAffectWithVersions `json:"affected"`
	Withdrawn        string                  `json:"withdrawn"`
	References       []osvReference          `json:"references"`
	Severity         []osvSeverityEntry      `json:"severity"`
	DatabaseSpecific osvDatabaseSpecific     `json:"database_specific"`
}

// parseOSVRecordPerPackage parses a single OSV JSON record and returns one
// Advisory per affected package entry that matches the supplied ecosystem.
// This is the index-builder's replacement for parseOSVRecord: it avoids
// merging ranges from multiple packages in the same record into a single
// advisory, which would cause false positives when packages have different
// fixed bounds.
//
// Per-entry semantics:
//   - SEMVER/ECOSYSTEM range events → VersionRanges (same as parseOSVRecord).
//   - versions[] with no SEMVER/ECOSYSTEM ranges → Advisory.Versions (for exact
//     membership matching in AffectsVersionV).
//   - GIT-only ranges → both VersionRanges and Versions are empty, so
//     AffectsVersionV returns VersionUndecidable (forwarded as Incomplete=true).
//   - Severity, FixRefs, Withdrawn, Aliases, Sources are inherited from the
//     top-level record and shared across all per-package advisories.
func parseOSVRecordPerPackage(data []byte, ecosystem string) ([]Advisory, error) {
	var rec osvRecordWithVersions
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("advisory: parse OSV record: %w", err)
	}

	// Top-level fields shared by all per-package advisories in this record.
	severity := parseOSVSeverity(rec.Severity, rec.DatabaseSpecific.Severity)
	fixRefs := extractFixRefs(rec.References)

	var result []Advisory
	for _, aff := range rec.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, ecosystem) {
			continue
		}

		adv := Advisory{
			ID:        rec.ID,
			Aliases:   rec.Aliases,
			Sources:   []string{SourceGoVulnDB},
			Withdrawn: rec.Withdrawn,
			Severity:  severity,
			FixRefs:   fixRefs,
			Module:    aff.Package.Name,
		}

		// Collect SEMVER/ECOSYSTEM ranges only — skip GIT and other types.
		// Track whether any GIT (or other non-version) ranges are present: their
		// bounds are git commit hashes, not versions, so they cannot be compared
		// with PEP 440 or semver — the advisory must remain Undecidable.
		hasNonVersionRanges := false
		for _, r := range aff.Ranges {
			t := strings.ToUpper(r.Type)
			switch t {
			case "SEMVER", "ECOSYSTEM":
				vrs := extractVersionRanges(r.Events)
				if len(vrs) > 0 {
					adv.VersionRanges = append(adv.VersionRanges, vrs...)
				} else {
					// Range block present but produced no events — open-ended range
					// (all versions in range).
					adv.VersionRanges = append(adv.VersionRanges, VersionRange{})
				}
			default:
				// GIT or other non-version range type — bounds are commit hashes,
				// not parseable as versions. Mark the entry as having non-version ranges
				// so we do not fall back to the versions[] list as authoritative.
				hasNonVersionRanges = true
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

		// When there are no SEMVER/ECOSYSTEM ranges, decide how to handle the entry:
		//   (a) No ranges of any kind → versions-only entry (e.g. MAL-2026-2144):
		//       store the versions[] list for exact-membership matching.
		//   (b) GIT-only ranges → commit-hash bounds cannot be compared with versions;
		//       leave VersionRanges and Versions empty so AffectsVersionV returns
		//       VersionUndecidable (forwarded as Incomplete=true). Do NOT use the
		//       versions[] list as a substitute: it may be incomplete, and
		//       "unknown ≠ safe" — we must not drop the advisory for unlisted versions.
		if len(adv.VersionRanges) == 0 && !hasNonVersionRanges && len(aff.Versions) > 0 {
			adv.Versions = append([]string(nil), aff.Versions...)
		}
		// If VersionRanges is still empty (GIT-only or no ranges at all with no
		// versions list), AffectsVersionV will return VersionUndecidable — forwarded
		// as Incomplete=true.

		result = append(result, adv)
	}

	if len(result) == 0 {
		// No matching ecosystem entries in this record.
		return nil, fmt.Errorf("advisory: no %s entries in record %s", ecosystem, rec.ID)
	}
	return result, nil
}

// lookup returns advisories for pkg whose version ranges include version,
// stamped with the given source attribution. It reproduces the match logic of
// dirSource.query (name normalization, canonical version, AffectsVersion) on the
// pre-grouped index.
func (idx *advisoryIndex) lookup(pkg Package, version string, sources []string) []Advisory {
	queryName := pkg.Name
	if pkg.Ecosystem == EcosystemNPM {
		queryName = normalizeNPMPackageName(queryName)
	}
	candidates := idx.byName[queryName]
	if len(candidates) == 0 {
		return nil
	}
	// canonical adds the "v" prefix required by the Go semver path; npmVersionInRangeV
	// strips it again, so this is harmless for npm but required for Go.
	queryVersion := canonical(version)
	var results []Advisory
	for i := range candidates {
		// Copy so the cached index is never mutated by per-query stamping.
		adv := candidates[i]
		// Set Ecosystem before version matching so AffectsVersionV routes to the
		// correct semver implementation (npm vs. Go vs. crates.io vs. unknown).
		adv.Ecosystem = pkg.Ecosystem
		switch adv.AffectsVersionV(queryVersion) {
		case VersionAffected:
			adv.Sources = append([]string(nil), sources...)
			results = append(results, adv)
		case VersionUndecidable:
			// Cannot determine whether this version is affected — include the advisory
			// with Incomplete=true so the host can emit a synthetic UNKNOWN finding
			// and set incomplete=true at the policy gate. Dropping it would be a
			// silent false negative ("unknown ≠ safe").
			adv.Sources = append([]string(nil), sources...)
			adv.Incomplete = true
			results = append(results, adv)
		// VersionNotAffected: drop — the only safe drop.
		}
	}
	return results
}

// ─── Version normalisation ────────────────────────────────────────────────────

// normalizeNPMPackageName converts an npm package name to the lowercase canonical
// form used in OSV records. The npm registry treats names as case-insensitive and
// stores them in lowercase; OSV npm records follow the same convention.
//
// Scoped packages (@scope/name) are preserved with the "@" prefix and "/" separator,
// both components lowercased. Unscoped names are simply lowercased.
//
// Examples:
//
//	"Lodash"           → "lodash"
//	"@Scope/Example"   → "@scope/example"
//	""                 → ""
func normalizeNPMPackageName(name string) string {
	return strings.ToLower(name)
}

// normalizeOSVVersion converts a version string into the form used in OSV records
// for the given ecosystem.
//
// Go-specific: OSV Go records store versions WITHOUT the "v" prefix that Go
// module versions carry. E.g. the Go module version "v1.2.3" appears in the OSV
// affected.ranges events as "1.2.3". The semver.go canonical() helper already
// strips the leading "v" in reverse (it adds "v" to bare strings), so callers of
// AffectsVersion always pass the canonical v-prefixed form and canonical() handles
// the other direction. This function is the public entry point for the
// normalisation, used for documentation, testing, and any future ecosystem routing.
//
// Non-Go ecosystems: the version is returned unchanged (we don't know their
// conventions; adding logic for ecosystems not yet implemented would be YAGNI).
func normalizeOSVVersion(ecosystem, version string) string {
	if ecosystem != EcosystemGo {
		return version
	}
	// Strip the leading "v" if present — OSV Go records use bare semver.
	return strings.TrimPrefix(version, "v")
}
