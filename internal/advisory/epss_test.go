package advisory

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClock returns a deterministic Now func for staleness control.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// newEPSSAPIServer serves the FIRST.org EPSS query API for the given scores.
// Only CVEs present in scores are returned, mirroring the real API.
func newEPSSAPIServer(t *testing.T, scores map[string]struct{ epss, pct, date string }) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		var b bytes.Buffer
		b.WriteString(`{"status":"OK","data":[`)
		first := true
		for _, cve := range splitCSVParam(q) {
			s, ok := scores[cve]
			if !ok {
				continue
			}
			if !first {
				b.WriteString(",")
			}
			first = false
			b.WriteString(`{"cve":"` + cve + `","epss":"` + s.epss + `","percentile":"` + s.pct + `","date":"` + s.date + `"}`)
		}
		b.WriteString(`]}`)
		_, _ = w.Write(b.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func splitCSVParam(s string) []string {
	var out []string
	for _, p := range bytes.Split([]byte(s), []byte(",")) {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}

// gzipCSVToCache writes the uncompressed CSV bytes to a gzip file at the EPSS
// cache path inside dir, plus a fresh meta sidecar, simulating a populated cache.
func gzipCSVToCache(t *testing.T, dir string, csv []byte, fetchedAt time.Time) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "epss_scores-current.csv.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(csv)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))

	meta := docMeta{FetchedAt: fetchedAt}
	dc := &docCache{cachePath: path}
	dc.writeMeta(meta)
}

func advWithCVE(id, cve string) Advisory {
	return Advisory{ID: id, Aliases: []string{cve}}
}

// TestEPSSEnricher_APIJoinFillsScore verifies the API path fills probability and
// percentile for a CVE the feed scores, and leaves an unscored CVE untouched.
func TestEPSSEnricher_APIJoinFillsScore(t *testing.T) {
	t.Parallel()
	srv := newEPSSAPIServer(t, map[string]struct{ epss, pct, date string }{
		"CVE-2021-44228": {"0.975", "0.999", "2026-06-26"},
	})

	e := &EPSSEnricher{APIBaseURL: srv.URL, HTTP: srv.Client()}
	advs := []Advisory{
		advWithCVE("GHSA-aaa", "CVE-2021-44228"),
		advWithCVE("GHSA-bbb", "CVE-2099-9999"), // not scored by the feed
	}

	require.NoError(t, e.Enrich(context.Background(), advs))

	require.NotNil(t, advs[0].EPSS)
	assert.InDelta(t, 0.975, advs[0].EPSS.Probability, 1e-9)
	assert.InDelta(t, 0.999, advs[0].EPSS.Percentile, 1e-9)
	assert.Equal(t, "2026-06-26", advs[0].EPSS.Date)

	// Absent CVE → no-op, not an error, not a fabricated zero score.
	assert.Nil(t, advs[1].EPSS)
}

// TestEPSSEnricher_NoCVEsIsNoop verifies advisories without CVE aliases produce
// no error and no enrichment.
func TestEPSSEnricher_NoCVEsIsNoop(t *testing.T) {
	t.Parallel()
	e := &EPSSEnricher{APIBaseURL: "http://127.0.0.1:0", HTTP: http.DefaultClient}
	advs := []Advisory{{ID: "GO-2024-0001"}}
	require.NoError(t, e.Enrich(context.Background(), advs))
	assert.Nil(t, advs[0].EPSS)
}

// TestEPSSEnricher_FetchFailureIsIncomplete verifies that when the API fails and
// no CSV floor cache is available, the enricher reports an error (unknown ≠ safe).
func TestEPSSEnricher_FetchFailureIsIncomplete(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	e := &EPSSEnricher{APIBaseURL: srv.URL, HTTP: srv.Client()} // no CacheDir → no floor
	advs := []Advisory{advWithCVE("GHSA-aaa", "CVE-2021-44228")}

	err := e.Enrich(context.Background(), advs)
	require.Error(t, err)
	assert.Nil(t, advs[0].EPSS)
}

// TestEPSSEnricher_CSVFloorOffline verifies the offline CSV floor fills scores
// from a pre-populated gzip cache without any network access.
func TestEPSSEnricher_CSVFloorOffline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	csv, err := os.ReadFile(filepath.Join("testdata", "epss", "epss_scores_sample.csv"))
	require.NoError(t, err)
	gzipCSVToCache(t, dir, csv, time.Now())

	e := &EPSSEnricher{Offline: true, CacheDir: dir, Now: fixedClock(time.Now())}
	advs := []Advisory{
		advWithCVE("GHSA-aaa", "CVE-2021-44228"),
		advWithCVE("GHSA-bbb", "CVE-2099-9999"),
	}

	require.NoError(t, e.Enrich(context.Background(), advs))
	require.NotNil(t, advs[0].EPSS)
	assert.InDelta(t, 0.975, advs[0].EPSS.Probability, 1e-4)
	assert.Nil(t, advs[1].EPSS)
}

// TestEPSSEnricher_OfflineNoCacheIsIncomplete verifies offline mode with no
// cached CSV fails closed.
func TestEPSSEnricher_OfflineNoCacheIsIncomplete(t *testing.T) {
	t.Parallel()
	e := &EPSSEnricher{Offline: true, CacheDir: t.TempDir(), Now: fixedClock(time.Now())}
	advs := []Advisory{advWithCVE("GHSA-aaa", "CVE-2021-44228")}
	err := e.Enrich(context.Background(), advs)
	require.Error(t, err)
	assert.Nil(t, advs[0].EPSS)
}

// TestEPSSEnricher_APIFailsFallsBackToCSVFloor verifies that when the API errors
// but a CSV floor cache exists, the data is applied AND the enricher still
// reports incomplete (freshness unconfirmed must never read as a clean pass).
func TestEPSSEnricher_APIFailsFallsBackToCSVFloor(t *testing.T) {
	t.Parallel()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(apiSrv.Close)

	dir := t.TempDir()
	csv, err := os.ReadFile(filepath.Join("testdata", "epss", "epss_scores_sample.csv"))
	require.NoError(t, err)
	// Stale cache (fetched long ago) and a dead CSV server so the conditional GET
	// fails and the enricher degrades to the cached body.
	gzipCSVToCache(t, dir, csv, time.Now().Add(-72*time.Hour))
	deadCSV := "http://127.0.0.1:0/epss.csv.gz"

	e := &EPSSEnricher{
		APIBaseURL: apiSrv.URL,
		CSVURL:     deadCSV,
		HTTP:       &http.Client{Timeout: 2 * time.Second},
		CacheDir:   dir,
		Now:        fixedClock(time.Now()),
	}
	advs := []Advisory{advWithCVE("GHSA-aaa", "CVE-2021-44228")}

	err = e.Enrich(context.Background(), advs)
	require.Error(t, err, "degraded freshness must surface as incomplete")
	require.NotNil(t, advs[0].EPSS, "stale-cache data must still be applied")
	assert.InDelta(t, 0.975, advs[0].EPSS.Probability, 1e-4)
}

// TestEPSSEnricher_Deterministic verifies identical inputs produce identical
// enriched output across runs.
func TestEPSSEnricher_Deterministic(t *testing.T) {
	t.Parallel()
	srv := newEPSSAPIServer(t, map[string]struct{ epss, pct, date string }{
		"CVE-2021-44228": {"0.975", "0.999", "2026-06-26"},
		"CVE-2023-1111":  {"0.012", "0.55", "2026-06-26"},
	})

	run := func() []*EPSSScore {
		e := &EPSSEnricher{APIBaseURL: srv.URL, HTTP: srv.Client()}
		advs := []Advisory{
			advWithCVE("GHSA-a", "CVE-2021-44228"),
			advWithCVE("GHSA-b", "CVE-2023-1111"),
		}
		require.NoError(t, e.Enrich(context.Background(), advs))
		return []*EPSSScore{advs[0].EPSS, advs[1].EPSS}
	}

	first := run()
	second := run()
	require.True(t, reflect.DeepEqual(first, second), "EPSS enrichment must be deterministic")
}

// TestUniqueCVEs verifies CVE collection dedupes and sorts deterministically and
// ignores non-CVE aliases.
func TestUniqueCVEs(t *testing.T) {
	t.Parallel()
	advs := []Advisory{
		{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228", "GHSA-x"}},
		{ID: "CVE-2020-0001", Aliases: []string{"cve-2021-44228"}}, // dup, different case
		{ID: "GO-2024-0001"},
	}
	got := uniqueCVEs(advs)
	assert.Equal(t, []string{"CVE-2020-0001", "CVE-2021-44228"}, got)
}
