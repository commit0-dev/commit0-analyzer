package advisory

import (
	"context"
	"encoding/json"
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
