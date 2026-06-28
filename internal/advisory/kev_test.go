package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newKEVServer serves the KEV catalog fixture once, counting requests so the
// staleness short-circuit can be asserted.
func newKEVServer(t *testing.T, body []byte, hits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func loadKEVFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "kev", "known_exploited_sample.json"))
	require.NoError(t, err)
	return b
}

// TestKEVEnricher_ListedCVEFilled verifies a catalogued CVE gets Listed=true,
// the due date, and the ransomware flag; a non-catalogued CVE is left untouched.
func TestKEVEnricher_ListedCVEFilled(t *testing.T) {
	t.Parallel()
	srv := newKEVServer(t, loadKEVFixture(t), nil)
	k := &KEVEnricher{URL: srv.URL, HTTP: srv.Client(), CacheDir: t.TempDir()}

	advs := []Advisory{
		advWithCVE("GHSA-log4j", "CVE-2021-44228"),
		advWithCVE("GHSA-widget", "CVE-2023-1111"),
		advWithCVE("GHSA-clean", "CVE-2099-9999"),
	}
	require.NoError(t, k.Enrich(context.Background(), advs))

	require.NotNil(t, advs[0].KEV)
	assert.True(t, advs[0].KEV.Listed)
	assert.Equal(t, "2021-12-10", advs[0].KEV.DateAdded)
	assert.Equal(t, "2021-12-24", advs[0].KEV.DueDate)
	assert.True(t, advs[0].KEV.KnownRansomware, "Known ransomware flag must parse true")

	require.NotNil(t, advs[1].KEV)
	assert.True(t, advs[1].KEV.Listed)
	assert.False(t, advs[1].KEV.KnownRansomware, "Unknown ransomware flag must parse false")

	// Non-catalogued CVE: untouched (missing ≠ safe; carried by incomplete flag).
	assert.Nil(t, advs[2].KEV)
}

// TestKEVEnricher_NoCVEsIsNoop verifies advisories without CVEs are a no-op.
func TestKEVEnricher_NoCVEsIsNoop(t *testing.T) {
	t.Parallel()
	k := &KEVEnricher{URL: "http://127.0.0.1:0", HTTP: http.DefaultClient, CacheDir: t.TempDir()}
	advs := []Advisory{{ID: "GO-2024-0001"}}
	require.NoError(t, k.Enrich(context.Background(), advs))
	assert.Nil(t, advs[0].KEV)
}

// TestKEVEnricher_FetchFailureIsIncomplete verifies a fetch failure with no cache
// reports an error (unknown ≠ safe).
func TestKEVEnricher_FetchFailureIsIncomplete(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	k := &KEVEnricher{URL: srv.URL, HTTP: srv.Client(), CacheDir: t.TempDir()}
	advs := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
	err := k.Enrich(context.Background(), advs)
	require.Error(t, err)
	assert.Nil(t, advs[0].KEV)
}

// TestKEVEnricher_OfflineUsesCache verifies offline mode reads a pre-populated
// cache without any network access.
func TestKEVEnricher_OfflineUsesCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cisa_known_exploited_vulnerabilities.json")
	require.NoError(t, os.WriteFile(cachePath, loadKEVFixture(t), 0o644))
	(&docCache{cachePath: cachePath}).writeMeta(docMeta{FetchedAt: time.Now()})

	k := &KEVEnricher{Offline: true, CacheDir: dir, Now: fixedClock(time.Now())}
	advs := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
	require.NoError(t, k.Enrich(context.Background(), advs))
	require.NotNil(t, advs[0].KEV)
	assert.True(t, advs[0].KEV.Listed)
}

// TestKEVEnricher_OfflineNoCacheIsIncomplete verifies offline with no cache fails
// closed.
func TestKEVEnricher_OfflineNoCacheIsIncomplete(t *testing.T) {
	t.Parallel()
	k := &KEVEnricher{Offline: true, CacheDir: t.TempDir(), Now: fixedClock(time.Now())}
	advs := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
	require.Error(t, k.Enrich(context.Background(), advs))
	assert.Nil(t, advs[0].KEV)
}

// TestKEVEnricher_FreshCacheSkipsNetwork verifies a fresh cache short-circuits
// the network entirely (the staleness window honours the injected clock).
func TestKEVEnricher_FreshCacheSkipsNetwork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hits := 0
	srv := newKEVServer(t, loadKEVFixture(t), &hits)

	now := time.Now()
	// Prime the cache with one online fetch.
	k := &KEVEnricher{URL: srv.URL, HTTP: srv.Client(), CacheDir: dir, Now: fixedClock(now)}
	advs := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
	require.NoError(t, k.Enrich(context.Background(), advs))
	require.Equal(t, 1, hits)

	// A second run within MaxAge must not hit the network again.
	advs2 := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
	require.NoError(t, k.Enrich(context.Background(), advs2))
	assert.Equal(t, 1, hits, "fresh cache must skip the network")
	require.NotNil(t, advs2[0].KEV)
}

// TestKEVEnricher_Deterministic verifies identical inputs produce identical
// output across runs.
func TestKEVEnricher_Deterministic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cisa_known_exploited_vulnerabilities.json")
	require.NoError(t, os.WriteFile(cachePath, loadKEVFixture(t), 0o644))
	(&docCache{cachePath: cachePath}).writeMeta(docMeta{FetchedAt: time.Now()})

	run := func() *KEVEntry {
		k := &KEVEnricher{Offline: true, CacheDir: dir, Now: fixedClock(time.Now())}
		advs := []Advisory{advWithCVE("GHSA-log4j", "CVE-2021-44228")}
		require.NoError(t, k.Enrich(context.Background(), advs))
		return advs[0].KEV
	}
	assert.Equal(t, run(), run())
}
