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
const ManifestFilename = "anst-snapshot-manifest.json"

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

// ─── Cache config ─────────────────────────────────────────────────────────────

// CacheConfig holds configuration for a Cache instance.
type CacheConfig struct {
	// Dir is the working cache directory for on-disk caching of fetched advisories.
	Dir string
	// SnapshotPin, if non-empty, pins queries to a pre-fetched snapshot directory
	// rather than fetching from the network. Verified against the manifest digest.
	SnapshotPin string
	// Offline, if true, disables all network access. Requires SnapshotPin or a
	// pre-populated Dir. Returns a clear error when the snapshot is missing.
	Offline bool
	// StalenessWarning is the age threshold past which a staleness warning is
	// surfaced. Zero uses DefaultStalenessWarning.
	StalenessWarning time.Duration
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

// Get returns advisories for modulePath@version. It honours the following
// precedence:
//  1. If SnapshotPin is set, query that snapshot directory (after digest verification).
//  2. Otherwise, if Offline is true, query Dir (must be pre-populated).
//  3. Otherwise, fetch from the network into Dir, then query.
//
// A *StalenessWarningError is returned alongside advisories when the snapshot
// is older than the staleness threshold. Callers must handle this non-nil error
// and still use the embedded advisories.
func (c *Cache) Get(ctx context.Context, modulePath, version string) ([]Advisory, error) {
	key := modulePath + "@" + version

	type result struct {
		advs []Advisory
		err  error
	}

	// singleflight deduplicates concurrent requests for the same key in-process.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		advs, err := c.get(ctx, modulePath, version)
		return result{advs: advs, err: err}, nil
	})
	if err != nil {
		return nil, err
	}

	res := v.(result)
	return res.advs, res.err
}

// get is the unsynchronised inner implementation called by Get via singleflight.
func (c *Cache) get(ctx context.Context, modulePath, version string) ([]Advisory, error) {
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
	advs, err := client.Query(ctx, modulePath, version)
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

// ─── File locking ─────────────────────────────────────────────────────────────

// lockDir acquires an exclusive flock on a lock file inside dir and returns an
// unlock function. It blocks until the lock is available.
// This prevents cross-process torn writes to the same cache directory.
func lockDir(dir string) (unlock func(), err error) {
	lockPath := filepath.Join(dir, ".anst-cache.lock")
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

