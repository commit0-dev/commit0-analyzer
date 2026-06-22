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

// Zip-bomb guards. These apply per-file and in aggregate across the entire
// extracted bundle. OSV ecosystem bundles are typically tens of MiB uncompressed
// (the Go bundle is ~20 MiB); these caps are generous while still protecting
// against malicious or corrupted archives.
const (
	// maxPerFileBytes is the maximum uncompressed size of a single zip entry.
	// 10 MiB — no individual OSV record should approach this.
	maxPerFileBytes = 10 << 20 // 10 MiB

	// maxTotalExtractedBytes is the maximum total uncompressed size across all
	// accepted entries in one bundle. 50 MiB — generous for any current ecosystem.
	maxTotalExtractedBytes = 50 << 20 // 50 MiB
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
}

// NewOSVBundleSource returns an OSVBundleSource that caches bundles under
// cacheDir. Apply functional options to override the default BaseURL,
// HTTP client, or ForceUpdate flag.
func NewOSVBundleSource(cacheDir string, opts ...osvOption) *OSVBundleSource {
	s := &OSVBundleSource{
		BaseURL:  osvDefaultBaseURL,
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		cacheDir: cacheDir,
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
	if err := safeExtractZip(zipData, dir); err != nil {
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
func safeExtractZip(zipData []byte, destDir string) error {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	var totalExtracted int64

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
		if totalExtracted > maxTotalExtractedBytes {
			return fmt.Errorf(
				"zip-bomb guard: total extracted size exceeds %d byte limit",
				maxTotalExtractedBytes,
			)
		}

		// Use only the base filename — discard any subdirectory component in the
		// zip entry name so all files land flat in destDir.
		dest := filepath.Join(destDir, filepath.Base(cleaned))
		if err := atomicWrite(dest, data); err != nil {
			return fmt.Errorf("write entry %q: %w", name, err)
		}
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

	ds := &dirSource{dir: dir, sources: []string{SourceOSV}}
	return ds.query(ctx, pkg, version)
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
