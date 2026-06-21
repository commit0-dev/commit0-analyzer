package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestSnapshot writes a minimal snapshot directory (a set of OSV JSON files)
// into dir and returns a SnapshotManifest whose digest matches that content.
func buildTestSnapshot(t *testing.T, dir string, fixtures []string) SnapshotManifest {
	t.Helper()
	for _, name := range fixtures {
		data := loadFixture(t, name)
		err := os.WriteFile(filepath.Join(dir, name), data, 0o644)
		require.NoError(t, err)
	}
	manifest, err := buildManifest(dir)
	require.NoError(t, err)
	return manifest
}

// ─── Offline mode ────────────────────────────────────────────────────────────

// TestOfflineMode_PinnedSnapshot verifies that a cache loaded from a pinned
// snapshot dir returns identical results on two successive calls without any
// network activity.
func TestOfflineMode_PinnedSnapshot(t *testing.T) {
	snapshotDir := t.TempDir()
	fixtures := []string{"GO-2024-0001.json", "GO-2024-0002.json"}
	manifest := buildTestSnapshot(t, snapshotDir, fixtures)

	// Write the manifest alongside the snapshot.
	writeManifest(t, snapshotDir, manifest)

	cache := NewCache(CacheConfig{
		Dir:         snapshotDir,
		SnapshotPin: snapshotDir,
		Offline:     true,
	})

	ctx := context.Background()

	result1, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
	require.NoError(t, err)
	require.Len(t, result1, 1)

	result2, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
	require.NoError(t, err)

	// Results must be identical (deterministic).
	require.Equal(t, len(result1), len(result2))
	assert.Equal(t, result1[0].ID, result2[0].ID)
}

// TestOfflineMode_MissingSnapshot verifies that offline mode with a missing
// snapshot directory returns a clear error (unknown ≠ safe at the data boundary).
func TestOfflineMode_MissingSnapshot(t *testing.T) {
	cache := NewCache(CacheConfig{
		Dir:         "/nonexistent/path/that/does/not/exist",
		SnapshotPin: "/nonexistent/path/that/does/not/exist",
		Offline:     true,
	})

	ctx := context.Background()
	_, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
	require.Error(t, err, "offline mode with missing snapshot must error")
	assert.Contains(t, err.Error(), "snapshot", "error should mention snapshot")
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

// TestConcurrentReadersWriters verifies that N concurrent callers on the same
// cache key never observe a torn/partial write. The test is designed to expose
// both memory-level and file-level races; run with -race.
func TestConcurrentReadersWriters(t *testing.T) {
	snapshotDir := t.TempDir()
	fixtures := []string{"GO-2024-0001.json", "GO-2024-0002.json"}
	manifest := buildTestSnapshot(t, snapshotDir, fixtures)
	writeManifest(t, snapshotDir, manifest)

	cacheDir := t.TempDir()
	cache := NewCache(CacheConfig{
		Dir:         cacheDir,
		SnapshotPin: snapshotDir,
		Offline:     true,
	})

	const workers = 16
	var wg sync.WaitGroup
	var errCount atomic.Int64

	ctx := context.Background()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			advs, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
			if err != nil {
				errCount.Add(1)
				return
			}
			// Each result must be self-consistent: if any advisory is returned,
			// it must be complete (ID non-empty, Sources non-empty).
			for _, a := range advs {
				if a.ID == "" || len(a.Sources) == 0 {
					errCount.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(0), errCount.Load(), "concurrent readers/writers must not produce torn reads")
}

// ─── Snapshot provenance ─────────────────────────────────────────────────────

// TestSnapshotDigestMismatch verifies that loading a snapshot whose on-disk
// content digest does not match the manifest causes a hard error.
func TestSnapshotDigestMismatch(t *testing.T) {
	snapshotDir := t.TempDir()
	fixtures := []string{"GO-2024-0001.json"}
	manifest := buildTestSnapshot(t, snapshotDir, fixtures)

	// Tamper: alter the stored digest.
	manifest.ContentDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	writeManifest(t, snapshotDir, manifest)

	cache := NewCache(CacheConfig{
		Dir:         snapshotDir,
		SnapshotPin: snapshotDir,
		Offline:     true,
	})

	ctx := context.Background()
	_, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
	require.Error(t, err, "digest mismatch must be a hard error")
	assert.Contains(t, err.Error(), "digest", "error must mention digest mismatch")
}

// TestSnapshotStaleness verifies that a snapshot older than the staleness
// threshold causes a warning to be surfaced (not silently swallowed).
func TestSnapshotStaleness(t *testing.T) {
	snapshotDir := t.TempDir()
	fixtures := []string{"GO-2024-0001.json"}
	manifest := buildTestSnapshot(t, snapshotDir, fixtures)

	// Set the build timestamp far in the past.
	manifest.BuildTimestamp = time.Now().Add(-30 * 24 * time.Hour) // 30 days old
	writeManifest(t, snapshotDir, manifest)

	cache := NewCache(CacheConfig{
		Dir:              snapshotDir,
		SnapshotPin:      snapshotDir,
		Offline:          true,
		StalenessWarning: 7 * 24 * time.Hour, // warn after 7 days
	})

	ctx := context.Background()
	_, err := cache.Get(ctx, "github.com/example/vulnpkg", "v1.0.0")
	// A stale snapshot is a WARNING, not a fatal error — data is still returned.
	// But the warning must be surfaced via the cache's warning channel or the
	// returned error wrapper. We verify by checking the cache's last warning.
	// Implementation detail: Get returns a StalenessWarningError that wraps the
	// advisory slice AND the warning; callers must check errors.As.
	require.Error(t, err, "stale snapshot must surface a warning as an error value")
	var staleErr *StalenessWarningError
	require.ErrorAs(t, err, &staleErr, "error must be a *StalenessWarningError")
	assert.NotEmpty(t, staleErr.Warning, "warning message must not be empty")
	// The advisories must still be present (warn, do not block).
	assert.NotNil(t, staleErr.Advisories)
}

// ─── Snapshot manifest helpers used by tests ─────────────────────────────────

// writeManifest serialises m to the well-known manifest filename inside dir.
func writeManifest(t *testing.T, dir string, m SnapshotManifest) {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, ManifestFilename), data, 0o644)
	require.NoError(t, err)
}

// ─── TDD Group 4: Refresh then Get returns fetched advisories ─────────────────

// TestCacheRefresh_OnlineThenOffline verifies that:
//  1. Refresh(online) populates the writable Dir + writes a valid manifest.
//  2. A subsequent Get against the same Dir returns the fetched advisories.
//  3. A follow-up Get with Offline=true makes zero additional network calls.
func TestCacheRefresh_OnlineThenOffline(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")

	const dbModified = "2024-06-15T00:00:00Z"

	var networkCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		networkCalls.Add(1)
		switch r.URL.Path {
		case "/index/modules.json":
			json.NewEncoder(w).Encode([]modulesIndexEntry{ //nolint:errcheck
				{
					Path:  "github.com/example/vulnpkg",
					Vulns: []modulesVulnRef{{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"}},
				},
			})
		case "/index/db.json":
			w.Write([]byte(`{"modified":"` + dbModified + `"}`)) //nolint:errcheck
		case "/ID/GO-2024-0001.json":
			w.Write(idA) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}

	// --- online Refresh ---
	cache := NewCache(CacheConfig{
		Dir:         cacheDir,
		Fetcher:     f,
		ForceUpdate: false,
	})
	err := cache.Refresh(context.Background(), []string{"github.com/example/vulnpkg"})
	require.NoError(t, err)

	// Manifest must exist and be valid.
	manifest, err := verifyManifest(cacheDir)
	require.NoError(t, err, "manifest must be valid after Refresh")
	assert.Equal(t, dbModified, manifest.DBSourceVersion)

	// Get must return the fetched advisory.
	advs, err := cache.Get(context.Background(), "github.com/example/vulnpkg", "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs, 1)
	assert.Equal(t, "GO-2024-0001", advs[0].ID)

	callsAfterRefresh := networkCalls.Load()

	// --- offline Get against same populated dir ---
	offlineCache := NewCache(CacheConfig{
		Dir:     cacheDir,
		Offline: true,
	})
	advs2, err := offlineCache.Get(context.Background(), "github.com/example/vulnpkg", "v1.0.0")
	require.NoError(t, err)
	require.Len(t, advs2, 1)
	assert.Equal(t, "GO-2024-0001", advs2[0].ID)

	// Offline Get must not have made additional network calls.
	assert.Equal(t, callsAfterRefresh, networkCalls.Load(),
		"offline Get must make zero additional network calls")
}

// ─── TDD Group 5: SnapshotPin never fetched even with Fetcher configured ─────

// TestCacheRefresh_PinNeverFetched verifies that when SnapshotPin is set,
// Refresh does NOT call the network even if a Fetcher is configured and
// ForceUpdate is true. The pin dir's file mtimes must be unchanged.
func TestCacheRefresh_PinNeverFetched(t *testing.T) {
	// Build a pre-existing valid pin snapshot.
	pinDir := t.TempDir()
	fixtures := []string{"GO-2024-0001.json", "GO-2024-0002.json"}
	manifest := buildTestSnapshot(t, pinDir, fixtures)
	writeManifest(t, pinDir, manifest)

	// Record mtimes of files in pinDir before Refresh.
	mtimesBefore := map[string]time.Time{}
	entries, err := os.ReadDir(pinDir)
	require.NoError(t, err)
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		mtimesBefore[e.Name()] = info.ModTime()
	}

	var networkCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		networkCalls.Add(1)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	cache := NewCache(CacheConfig{
		SnapshotPin: pinDir,
		Fetcher:     f,
		ForceUpdate: true, // even ForceUpdate must not override pin
	})

	err = cache.Refresh(context.Background(), []string{"github.com/example/vulnpkg"})
	require.NoError(t, err, "Refresh on a pin must be a no-op, not an error")

	// No network calls.
	assert.Equal(t, int64(0), networkCalls.Load(),
		"Refresh must make zero network calls when SnapshotPin is set")

	// File mtimes must be unchanged.
	for name, before := range mtimesBefore {
		info, err := os.Stat(filepath.Join(pinDir, name))
		require.NoError(t, err)
		assert.Equal(t, before, info.ModTime(),
			"file %s mtime must not change when pin is set", name)
	}
}

// ─── TDD Group 6: Staleness + ForceUpdate refresh control ────────────────────

// TestCacheRefresh_StaleCache_Refetches verifies that when the cached
// DBSourceVersion is older than the live db modified, Refresh refetches.
func TestCacheRefresh_StaleCache_Refetches(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")

	const (
		cachedVersion = "2024-05-01T00:00:00Z" // old
		liveVersion   = "2024-06-15T00:00:00Z" // newer → stale
	)

	cacheDir := t.TempDir()

	// Pre-populate the cache with a stale manifest.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "GO-2024-0001.json"), idA, 0o644))
	staleManifest, err := buildManifest(cacheDir)
	require.NoError(t, err)
	staleManifest.DBSourceVersion = cachedVersion
	writeManifest(t, cacheDir, staleManifest)

	var indexFetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules.json":
			indexFetches.Add(1)
			json.NewEncoder(w).Encode([]modulesIndexEntry{ //nolint:errcheck
				{
					Path:  "github.com/example/vulnpkg",
					Vulns: []modulesVulnRef{{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"}},
				},
			})
		case "/index/db.json":
			w.Write([]byte(`{"modified":"` + liveVersion + `"}`)) //nolint:errcheck
		case "/ID/GO-2024-0001.json":
			w.Write(idA) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	cache := NewCache(CacheConfig{
		Dir:     cacheDir,
		Fetcher: f,
	})

	err = cache.Refresh(context.Background(), []string{"github.com/example/vulnpkg"})
	require.NoError(t, err)

	// Must have triggered a re-fetch.
	assert.GreaterOrEqual(t, indexFetches.Load(), int64(1),
		"stale cache must trigger a re-fetch")

	// Manifest must now carry the new version.
	m, err := verifyManifest(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, liveVersion, m.DBSourceVersion)
}

// TestCacheRefresh_ForceUpdate_AlwaysRefetches verifies that ForceUpdate=true
// triggers a re-fetch even when the cached version equals the live version.
func TestCacheRefresh_ForceUpdate_AlwaysRefetches(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")

	const sameVersion = "2024-06-15T00:00:00Z"

	cacheDir := t.TempDir()

	// Pre-populate with up-to-date manifest.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "GO-2024-0001.json"), idA, 0o644))
	freshManifest, err := buildManifest(cacheDir)
	require.NoError(t, err)
	freshManifest.DBSourceVersion = sameVersion
	writeManifest(t, cacheDir, freshManifest)

	var indexFetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules.json":
			indexFetches.Add(1)
			json.NewEncoder(w).Encode([]modulesIndexEntry{ //nolint:errcheck
				{
					Path:  "github.com/example/vulnpkg",
					Vulns: []modulesVulnRef{{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"}},
				},
			})
		case "/index/db.json":
			w.Write([]byte(`{"modified":"` + sameVersion + `"}`)) //nolint:errcheck
		case "/ID/GO-2024-0001.json":
			w.Write(idA) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	cache := NewCache(CacheConfig{
		Dir:         cacheDir,
		Fetcher:     f,
		ForceUpdate: true, // force even though version is current
	})

	err = cache.Refresh(context.Background(), []string{"github.com/example/vulnpkg"})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, indexFetches.Load(), int64(1),
		"ForceUpdate=true must trigger a re-fetch regardless of version match")
}

// TestCacheRefresh_FreshCache_SkipsRefetch verifies that a cache whose
// DBSourceVersion matches the live db modified does NOT re-fetch when
// ForceUpdate=false.
func TestCacheRefresh_FreshCache_SkipsRefetch(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")

	const sameVersion = "2024-06-15T00:00:00Z"

	cacheDir := t.TempDir()

	// Pre-populate with up-to-date manifest.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "GO-2024-0001.json"), idA, 0o644))
	freshManifest, err := buildManifest(cacheDir)
	require.NoError(t, err)
	freshManifest.DBSourceVersion = sameVersion
	writeManifest(t, cacheDir, freshManifest)

	var indexFetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/db.json":
			// db.json must be checked to determine staleness.
			w.Write([]byte(`{"modified":"` + sameVersion + `"}`)) //nolint:errcheck
		default:
			// Any modules.json or ID fetch would mean unnecessary work.
			indexFetches.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	cache := NewCache(CacheConfig{
		Dir:         cacheDir,
		Fetcher:     f,
		ForceUpdate: false,
	})

	err = cache.Refresh(context.Background(), []string{"github.com/example/vulnpkg"})
	require.NoError(t, err)

	assert.Equal(t, int64(0), indexFetches.Load(),
		"fresh cache with matching version must skip re-fetch")
}
