package advisory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/singleflight"
)

// ManifestFilename is the well-known name for the snapshot manifest file inside
// a snapshot directory.
const ManifestFilename = "commit0-analyzer-snapshot-manifest.json"

// DefaultStalenessWarning is the default threshold after which a snapshot is
// considered stale. 7 days matches typical Go vuln DB update cadence.
const DefaultStalenessWarning = 7 * 24 * time.Hour

// ─── Snapshot manifest ────────────────────────────────────────────────────────

// SnapshotManifest is the on-disk provenance record for a pinned snapshot.
// It is written alongside the OSV JSON files and verified on every load.
type SnapshotManifest struct {
	// ContentDigest is a SHA-256 hex digest of the sorted concatenation of all
	// OSV JSON file contents in the snapshot directory (excluding this manifest).
	ContentDigest string `json:"content_digest"`
	// BuildTimestamp is when this snapshot was created / last fetched.
	BuildTimestamp time.Time `json:"build_timestamp"`
	// DBSourceVersion is an opaque version string from the upstream DB
	// (e.g. the modified timestamp of the latest entry fetched).
	DBSourceVersion string `json:"db_source_version"`
}

// buildManifest computes a SnapshotManifest for the OSV files in dir.
// The digest is SHA-256 over the sorted file contents (filename + content).
func buildManifest(dir string) (SnapshotManifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("advisory: buildManifest: read dir %q: %w", dir, err)
	}

	// Collect filenames (sorted for determinism).
	var names []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == ManifestFilename {
			continue
		}
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return SnapshotManifest{}, fmt.Errorf("advisory: buildManifest: read %q: %w", name, err)
		}
		// Include filename in the hash so renames are detected.
		_, _ = fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}

	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	return SnapshotManifest{
		ContentDigest:  digest,
		BuildTimestamp: time.Now().UTC(),
	}, nil
}

// verifyManifest reads the manifest from dir and checks the content digest.
// Returns an error if the manifest is missing, unreadable, or the digest
// does not match the current directory contents.
func verifyManifest(dir string) (SnapshotManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFilename))
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("advisory: snapshot manifest missing in %q: %w", dir, err)
	}

	var m SnapshotManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return SnapshotManifest{}, fmt.Errorf("advisory: snapshot manifest corrupt in %q: %w", dir, err)
	}

	// Recompute the digest from disk and compare.
	computed, err := buildManifest(dir)
	if err != nil {
		return SnapshotManifest{}, err
	}

	if m.ContentDigest != computed.ContentDigest {
		return SnapshotManifest{}, fmt.Errorf(
			"advisory: snapshot digest mismatch in %q: stored=%s computed=%s — "+
				"snapshot may have been mutated; re-fetch to restore reproducibility",
			dir, m.ContentDigest, computed.ContentDigest,
		)
	}

	return m, nil
}

// ─── Staleness warning ────────────────────────────────────────────────────────

// StalenessWarningError is returned (wrapping the fetched advisories) when a
// snapshot is older than the configured staleness threshold. It is a WARNING,
// not a fatal error: callers should surface the warning AND use the advisories.
//
// The "unknown ≠ safe" invariant requires warnings to be surfaced, never
// silently swallowed. Callers must use errors.As to extract the advisories.
type StalenessWarningError struct {
	Warning    string
	Age        time.Duration
	Threshold  time.Duration
	Advisories []Advisory
}

func (e *StalenessWarningError) Error() string {
	return e.Warning
}

// ─── Probe-failure fallback warning ──────────────────────────────────────────

// RefreshFallbackWarning is returned by Refresh when the live-DB staleness probe
// (GET /index/db.json) fails BUT a valid local cache already exists.
//
// "unknown ≠ safe" applies here: the caller MUST surface this warning AND mark
// the scan incomplete — the cached data may be stale. The scan result must never
// appear as a clean pass when live freshness could not be confirmed.
//
// Contrast with a hard error: if the cache is also missing or unverifiable,
// Refresh returns a plain error (not RefreshFallbackWarning) and the scan must
// abort with exit 3 rather than producing results at all.
type RefreshFallbackWarning struct {
	// Warning is a human-readable description of the degraded state.
	Warning string
	// ProbeErr is the underlying error from the staleness-probe fetch.
	ProbeErr error
}

func (e *RefreshFallbackWarning) Error() string {
	return e.Warning
}

func (e *RefreshFallbackWarning) Unwrap() error {
	return e.ProbeErr
}

// ─── Cache config ─────────────────────────────────────────────────────────────

// CacheConfig holds configuration for a Cache instance.
type CacheConfig struct {
	// Dir is the working cache directory for on-disk caching of fetched advisories.
	Dir string
	// SnapshotPin, if non-empty, pins queries to a pre-fetched snapshot directory
	// rather than fetching from the network. Verified against the manifest digest.
	// A pinned snapshot is read-only and never fetched or mutated; Refresh is a
	// no-op when SnapshotPin is set.
	SnapshotPin string
	// Offline, if true, disables all network access. Requires SnapshotPin or a
	// pre-populated Dir. Returns a clear error when the snapshot is missing.
	// Refresh is a no-op when Offline is true.
	Offline bool
	// StalenessWarning is the age threshold past which a staleness warning is
	// surfaced. Zero uses DefaultStalenessWarning.
	StalenessWarning time.Duration
	// Fetcher is the network client used to populate the writable Dir.
	// Only consulted by Refresh; Get/Query are always network-free.
	// Nil means online fetch is unavailable (equivalent to Offline for Refresh).
	Fetcher *Fetcher
	// ForceUpdate, if true, causes Refresh to re-fetch even when the cached
	// DBSourceVersion already matches the live DB modified timestamp.
	ForceUpdate bool
}

// ─── Cache ────────────────────────────────────────────────────────────────────

// Cache is a concurrency-safe, on-disk advisory cache with snapshot pinning,
// content-digest verification, and staleness warnings.
//
// Concurrency guarantees:
//   - Per-key singleflight: only one goroutine fetches/reads a given key at a time.
//   - Atomic file writes: temp-file → fsync → rename to prevent torn reads.
//   - Cross-process file lock (flock LOCK_EX) on the cache directory lock file
//     to prevent concurrent processes from writing the same key simultaneously.
type Cache struct {
	cfg CacheConfig
	sf  singleflight.Group
}

// NewCache constructs a Cache with the given configuration.
func NewCache(cfg CacheConfig) *Cache {
	if cfg.StalenessWarning == 0 {
		cfg.StalenessWarning = DefaultStalenessWarning
	}
	return &Cache{cfg: cfg}
}

// Get returns advisories for pkg@version. It honours the following precedence:
//  1. If SnapshotPin is set, query that snapshot directory (after digest verification).
//  2. Otherwise, if Offline is true, query Dir (must be pre-populated).
//  3. Otherwise, fetch from the network into Dir, then query.
//
// A *StalenessWarningError is returned alongside advisories when the snapshot
// is older than the staleness threshold. Callers must handle this non-nil error
// and still use the embedded advisories.
func (c *Cache) Get(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	key := pkg.Ecosystem + ":" + pkg.Name + "@" + version

	type result struct {
		advs []Advisory
		err  error
	}

	// singleflight deduplicates concurrent requests for the same key in-process.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		advs, err := c.get(ctx, pkg, version)
		return result{advs: advs, err: err}, nil
	})
	if err != nil {
		return nil, err
	}

	res := v.(result)
	return res.advs, res.err
}

// get is the unsynchronised inner implementation called by Get via singleflight.
func (c *Cache) get(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	snapshotDir := c.cfg.SnapshotPin
	if snapshotDir == "" {
		snapshotDir = c.cfg.Dir
	}

	if snapshotDir == "" {
		return nil, fmt.Errorf("advisory: no cache directory or snapshot configured")
	}

	// In offline mode, the snapshot directory must exist.
	if c.cfg.Offline {
		if _, err := os.Stat(snapshotDir); err != nil {
			return nil, fmt.Errorf("advisory: offline mode requires a pre-fetched snapshot at %q: %w (snapshot missing)", snapshotDir, err)
		}
	}

	// Acquire a cross-process exclusive lock on the directory before reading,
	// so a concurrent process writing to the same snapshot does not produce
	// a torn read.
	unlock, err := lockDir(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("advisory: lock snapshot dir: %w", err)
	}
	defer unlock()

	// Verify the snapshot manifest (digest + presence).
	manifest, err := verifyManifest(snapshotDir)
	if err != nil {
		return nil, err
	}

	// Query the Go vuln DB client over the verified snapshot directory.
	client := &goVulnDBClient{dbDir: snapshotDir}
	advs, err := client.Query(ctx, pkg, version)
	if err != nil {
		return nil, err
	}

	// Stamp provenance onto each advisory.
	age := time.Since(manifest.BuildTimestamp)
	for i := range advs {
		advs[i].SnapshotDigest = manifest.ContentDigest
		advs[i].DBSourceVersion = manifest.DBSourceVersion
		advs[i].SnapshotAge = age.Round(time.Minute).String()
	}

	// Staleness check: surface a warning if the snapshot is too old.
	// unknown ≠ safe — the warning MUST be returned, not swallowed.
	if age > c.cfg.StalenessWarning {
		warn := fmt.Sprintf(
			"advisory: snapshot in %q is %s old (threshold %s); "+
				"vulnerability data may be incomplete — re-fetch to ensure coverage",
			snapshotDir,
			age.Round(time.Hour).String(),
			c.cfg.StalenessWarning.String(),
		)
		return nil, &StalenessWarningError{
			Warning:    warn,
			Age:        age,
			Threshold:  c.cfg.StalenessWarning,
			Advisories: advs,
		}
	}

	return advs, nil
}

// Query implements Source by delegating to Get. It allows Cache to be used
// directly as a Source in a MultiSource composition without a wrapper type.
// The method signature matches Source.Query exactly.
func (c *Cache) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	return c.Get(ctx, pkg, version)
}

// ─── Online refresh ───────────────────────────────────────────────────────────

// Refresh ensures the writable cache Dir is populated and up-to-date for the
// given set of module paths. It is called once before the per-dep Get loop so
// that Get/Query remain network-free.
//
// Refresh is a no-op when:
//   - SnapshotPin is set (pins are read-only and never fetched).
//   - Offline is true (network access is explicitly disabled).
//   - No Fetcher is configured.
//
// Staleness check: Refresh fetches /index/db.json to read the live DB modified
// timestamp and compares it to the cached manifest's DBSourceVersion. A fetch
// is performed when:
//   - The cache Dir is missing or empty (no manifest).
//   - The cached DBSourceVersion is strictly older than the live modified.
//   - ForceUpdate is true (always re-fetch regardless of version match).
//
// On a fetch error, Refresh returns a hard error without modifying the manifest
// (unknown ≠ safe: a failed fetch must never leave the cache appearing clean).
func (c *Cache) Refresh(ctx context.Context, modules []string) error {
	// No-op conditions: pin, offline, or no fetcher.
	if c.cfg.SnapshotPin != "" || c.cfg.Offline || c.cfg.Fetcher == nil {
		return nil
	}
	if c.cfg.Dir == "" {
		return fmt.Errorf("advisory: Refresh requires Dir to be set")
	}

	// Acquire the dir lock for the whole refresh to prevent concurrent processes
	// from racing on the same cache directory.
	//
	// We must create the dir before locking because lockDir opens a file inside it.
	if err := os.MkdirAll(c.cfg.Dir, 0o755); err != nil {
		return fmt.Errorf("advisory: create cache dir %q: %w", c.cfg.Dir, err)
	}

	unlock, err := lockDir(c.cfg.Dir)
	if err != nil {
		return fmt.Errorf("advisory: lock cache dir: %w", err)
	}
	defer unlock()

	// Determine whether a fetch is needed.
	// shouldFetch returns a RefreshFallbackWarning (not a hard error) when the
	// staleness probe fails but a valid local cache already exists. In that case
	// we surface the warning so the caller can mark the scan incomplete.
	needFetch, fallback, err := c.shouldFetch(ctx)
	if err != nil {
		return err
	}
	if fallback != nil {
		// Probe failed + valid cache exists: degrade gracefully.
		// Return the warning so the CLI can print it and set incomplete=true.
		return fallback
	}
	if !needFetch {
		return nil
	}

	// Perform the fetch into the writable Dir. FetchModules writes OSV files
	// atomically but does NOT write the manifest — that is our job below.
	dbModified, err := c.cfg.Fetcher.FetchModules(ctx, modules, c.cfg.Dir)
	if err != nil {
		return fmt.Errorf("advisory: fetch modules: %w", err)
	}

	// Write the manifest last — only after all OSV files are in place.
	// This ensures a crash between FetchModules and writeManifest leaves the
	// dir in a state where verifyManifest will fail (missing manifest), so the
	// next Refresh detects the incomplete state and re-fetches.
	if err := writeManifestToDir(c.cfg.Dir, dbModified); err != nil {
		return fmt.Errorf("advisory: write manifest: %w", err)
	}

	return nil
}

// shouldFetch checks the live DB modified timestamp and the cached manifest to
// decide whether a fetch is required. It returns (needFetch, fallbackWarning, error).
//
// Returns (true, nil, nil) when:
//   - ForceUpdate is set, OR
//   - The cache Dir is missing / has no valid manifest, OR
//   - The live db modified is strictly newer than the cached DBSourceVersion.
//
// Returns (false, nil, nil) when the cache already carries the current DB version.
//
// Returns (false, *RefreshFallbackWarning, nil) when the staleness probe fails BUT
// a valid local cache exists — the caller should use the existing cache and mark
// the scan incomplete (unknown ≠ safe: freshness unconfirmed).
//
// Returns (false, nil, error) when the probe fails AND the cache is also missing
// or corrupt — the caller should abort (no usable data at all).
func (c *Cache) shouldFetch(ctx context.Context) (needFetch bool, fallback *RefreshFallbackWarning, err error) {
	if c.cfg.ForceUpdate {
		return true, nil, nil
	}

	// Check whether a valid local cache exists before hitting the network.
	// If the manifest is missing or corrupt, we have no fallback.
	cached, manifestErr := verifyManifest(c.cfg.Dir)
	if manifestErr != nil {
		// No usable cache — we must fetch (and errors later will be hard errors).
		return true, nil, nil
	}
	if cached.DBSourceVersion == "" {
		// Cache exists but has no version recorded — force a refresh.
		return true, nil, nil
	}

	// Fetch the live DB modified timestamp to compare.
	liveModified, probeErr := c.cfg.Fetcher.fetchDBModified(ctx)
	if probeErr != nil {
		// Probe failed but we have a verified local cache. Fall back gracefully:
		// the caller should use the existing cache and mark the scan incomplete
		// so the result is never silently treated as a clean pass.
		warn := fmt.Sprintf(
			"advisory: could not check live DB freshness (%v); using existing cache in %q — "+
				"scan is marked incomplete because advisory data may be stale",
			probeErr, c.cfg.Dir,
		)
		return false, &RefreshFallbackWarning{Warning: warn, ProbeErr: probeErr}, nil
	}

	// Compare as strings: vuln.go.dev uses RFC3339 with fixed-width zero-padded
	// fields, so lexicographic ordering equals chronological ordering.
	if liveModified > cached.DBSourceVersion {
		return true, nil, nil
	}
	return false, nil, nil
}

// ─── Manifest write helper ────────────────────────────────────────────────────

// writeManifestToDir computes the content digest for the OSV files in destDir,
// sets DBSourceVersion=dbModified and BuildTimestamp=now, then atomically writes
// the manifest to filepath.Join(destDir, ManifestFilename).
func writeManifestToDir(destDir, dbModified string) error {
	m, err := buildManifest(destDir)
	if err != nil {
		return err
	}
	m.DBSourceVersion = dbModified
	m.BuildTimestamp = time.Now().UTC()

	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("advisory: marshal manifest: %w", err)
	}
	return atomicWrite(filepath.Join(destDir, ManifestFilename), data, true)
}

// ─── Atomic file write ────────────────────────────────────────────────────────

// atomicWrite writes data to path using a temp-file → fsync → rename sequence.
// This guarantees that a concurrent reader of path never observes a partial write:
// either the old file or the new file, never a torn intermediate state.
//
// The temp file is created in the same directory as path so that the rename is
// guaranteed to be on the same filesystem (rename across filesystems is not atomic).
// When fsync is true the temp file is flushed to stable storage before the
// rename, guaranteeing durability of this individual file. Bulk writers that
// produce many files (e.g. OSV bundle extraction of ~221k entries) pass
// fsync=false to avoid one fsync per file — a dominant cost — and instead flush
// once via syncDir after the batch, before the validating manifest is written.
func atomicWrite(path string, data []byte, fsync bool) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".commit0-analyzer-tmp-*")
	if err != nil {
		return fmt.Errorf("advisory: atomicWrite: create temp file: %w", err)
	}
	tmpName := tmp.Name()

	// Clean up the temp file on any error path.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("advisory: atomicWrite: write %q: %w", path, err)
	}

	// fsync ensures the data reaches stable storage before the rename makes it
	// visible. Without this, a crash between rename and flush could corrupt the
	// file even though the rename succeeded.
	if fsync {
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("advisory: atomicWrite: sync %q: %w", path, err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("advisory: atomicWrite: close %q: %w", path, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("advisory: atomicWrite: rename to %q: %w", path, err)
	}

	success = true
	return nil
}

// syncDir flushes a directory's metadata to stable storage, durably persisting
// the renames of files written into it. Used once after a bulk batch of
// fsync-free atomicWrite calls so the batch is durable before the manifest that
// validates it is written.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("advisory: syncDir: open %q: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("advisory: syncDir: sync %q: %w", dir, err)
	}
	return d.Close()
}

// ─── File locking ─────────────────────────────────────────────────────────────

// lockDir acquires an exclusive flock on a lock file inside dir and returns an
// unlock function. It blocks until the lock is available.
// This prevents cross-process torn writes to the same cache directory.
func lockDir(dir string) (unlock func(), err error) {
	lockPath := filepath.Join(dir, ".commit0-analyzer-cache.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", lockPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock %q: %w", lockPath, err)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

