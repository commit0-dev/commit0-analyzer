package advisory

import (
	"context"
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

// mirrorDir is the read-only offline-floor fixture: a cached NVD CVE feed slice.
func mirrorDir() string { return filepath.Join("testdata", "nvd", "mirror") }

// ─── NVDEnricher: CVE-keyed enrichment (primary, FP-safe role) ───────────────

// TestNVDEnricher_CVEJoin_AddsCVSSAndCWE verifies the primary role: joining an
// advisory by its CVE alias attaches the authoritative CVSS vector(s), CWE ids,
// and a source contribution — and leaves an advisory without a CVE alias
// completely untouched (the join adds zero new package→advisory edges).
func TestNVDEnricher_CVEJoin_AddsCVSSAndCWE(t *testing.T) {
	t.Parallel()

	enr := NewNVDEnricher(mirrorDir())

	advs := []Advisory{
		{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}},
		{ID: "GO-2024-0001"}, // no CVE alias → must be left untouched
	}

	err := enr.Enrich(context.Background(), advs)
	require.NoError(t, err)

	// First advisory: enriched from NVD.
	got := advs[0]
	require.Len(t, got.CVSS, 1, "the CVE-2021-44228 record carries one CVSS v3.1 metric")
	assert.Equal(t, "3.1", got.CVSS[0].Version)
	assert.Equal(t, 10.0, got.CVSS[0].BaseScore)
	assert.Equal(t, SourceNVD, got.CVSS[0].Source)
	assert.Equal(t, []string{"CWE-502", "CWE-917"}, got.CWEs, "CWEs must be deduped and sorted")
	assert.Equal(t, SeverityCritical, got.Severity)
	assert.Contains(t, got.Sources, SourceNVD)
	require.Len(t, got.SourceMeta, 1)
	assert.Equal(t, SourceNVD, got.SourceMeta[0].Name)
	assert.Equal(t, SeverityCritical, got.SourceMeta[0].Severity)

	// Second advisory: untouched (no CVE alias).
	assert.Empty(t, advs[1].CVSS)
	assert.Empty(t, advs[1].CWEs)
	assert.Empty(t, advs[1].SourceMeta)
	assert.NotContains(t, advs[1].Sources, SourceNVD)
}

// TestNVDEnricher_SeverityNeverDowngraded verifies enrichment never lowers an
// existing severity: a Critical advisory stays Critical even if NVD reported a
// lower score for a different aliased CVE.
func TestNVDEnricher_SeverityNeverDowngraded(t *testing.T) {
	t.Parallel()

	enr := NewNVDEnricher(mirrorDir())
	advs := []Advisory{{
		ID:       "GHSA-x",
		Aliases:  []string{"CVE-2099-0002"}, // NVD: MEDIUM (4.4)
		Severity: SeverityCritical,           // pre-existing, must not drop
	}}
	require.NoError(t, enr.Enrich(context.Background(), advs))
	assert.Equal(t, SeverityCritical, advs[0].Severity)
}

// TestNVDEnricher_NoCVE_NoFetch verifies that when no advisory carries a CVE
// alias, the enricher performs no fetch at all and returns nil even when the
// cache is missing — there is genuinely nothing to join.
func TestNVDEnricher_NoCVE_NoFetch(t *testing.T) {
	t.Parallel()

	enr := NewNVDEnricher(filepath.Join(t.TempDir(), "does-not-exist"))
	advs := []Advisory{{ID: "GO-2024-0001"}}
	require.NoError(t, enr.Enrich(context.Background(), advs))
	assert.Empty(t, advs[0].CVSS)
}

// TestNVDEnricher_OfflineMissingCache_Incomplete verifies the cardinal
// invariant: a CVE-bearing advisory with no cache and no API is INCOMPLETE
// (error), never a silent "no enrichment = clean".
func TestNVDEnricher_OfflineMissingCache_Incomplete(t *testing.T) {
	t.Parallel()

	enr := NewNVDEnricher(filepath.Join(t.TempDir(), "empty"))
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	err := enr.Enrich(context.Background(), advs)
	require.Error(t, err, "missing cache offline must surface as incomplete")
	assert.Empty(t, advs[0].CVSS, "no enrichment applied when feed is unavailable")
}

// TestNVDEnricher_FetchFailure_Incomplete verifies that an HTTP failure while
// NVD is requested (no usable cache) is incomplete, never silent clean.
func TestNVDEnricher_FetchFailure_Incomplete(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	enr := NewNVDEnricher(filepath.Join(t.TempDir(), "empty"),
		WithNVDBaseURL(srv.URL),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(time.Duration) {}),
		WithNVDMaxRetries(1),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	err := enr.Enrich(context.Background(), advs)
	require.Error(t, err)
}

// TestNVDEnricher_RefreshFailsButCacheUsable_DegradesIncomplete verifies the
// hybrid degrade path: when the live API fails but a cached floor exists, the
// enricher applies the cached enrichment AND reports incomplete (it could not
// confirm freshness). Both halves matter: coverage is preserved, and the
// uncertainty is surfaced rather than hidden.
func TestNVDEnricher_RefreshFailsButCacheUsable_DegradesIncomplete(t *testing.T) {
	t.Parallel()

	// Seed a temp cache by copying the fixture feed.
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(mirrorDir(), "nvd-cve-feed.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nvd-cve-feed.json"), data, 0o644))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	enr := NewNVDEnricher(dir,
		WithNVDBaseURL(srv.URL),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(time.Duration) {}),
		WithNVDMaxRetries(1),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	err = enr.Enrich(context.Background(), advs)
	require.Error(t, err, "refresh failure must surface as incomplete")
	require.Len(t, advs[0].CVSS, 1, "cached floor enrichment must still be applied (degrade)")
	assert.Equal(t, 10.0, advs[0].CVSS[0].BaseScore)
}

// ─── NVDCPESource: opt-in, lower-confidence CPE breadth (secondary role) ─────

// TestNVDCPESource_MatchTaggedNonGatingPackageLevel verifies every CPE match is
// attributed to the nvd-cpe token (the lower-confidence tag), stays
// package-level (never symbol-level), and that decidable in-range matches are
// proven (Incomplete=false) while product-level / undecidable matches stay
// UNKNOWN (Incomplete=true).
func TestNVDCPESource_MatchTaggedNonGatingPackageLevel(t *testing.T) {
	t.Parallel()

	src := NewNVDCPESource(mirrorDir())
	ctx := context.Background()

	t.Run("in-range proven", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "log4j"}, "2.14.0")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		a := advs[0]
		assert.Equal(t, "CVE-2021-44228", a.ID)
		assert.Equal(t, []string{SourceNVDCPE}, a.Sources, "match must be tagged cpe-heuristic")
		assert.False(t, a.SymbolLevel, "CPE matches are capped at package-level confidence")
		assert.False(t, a.Incomplete, "a decidable in-range CPE match is provable")
		assert.NotEmpty(t, a.CVSS)
	})

	t.Run("out-of-range excluded", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "log4j"}, "3.0.0")
		require.NoError(t, err)
		assert.Empty(t, advs, "a version decidably outside the CPE range must not match")
	})

	t.Run("exact version proven", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "examplelib"}, "1.0.0")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		assert.Equal(t, "CVE-2099-0001", advs[0].ID)
		assert.False(t, advs[0].Incomplete)
	})

	t.Run("product-level stays unknown", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "wholeproduct"}, "5.0.0")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		assert.Equal(t, "CVE-2099-0002", advs[0].ID)
		assert.True(t, advs[0].Incomplete, "a product-level CPE (no version bound) cannot be proven")
	})

	t.Run("unknown package returns nothing", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "no-such-product"}, "1.0.0")
		require.NoError(t, err)
		assert.Nil(t, advs)
	})
}

// TestNVDCPESource_FetchFailure_Unknown verifies a missing offline feed surfaces
// as an error (unknown), never an empty "clean" result.
func TestNVDCPESource_FetchFailure_Unknown(t *testing.T) {
	t.Parallel()

	src := NewNVDCPESource(filepath.Join(t.TempDir(), "empty"))
	advs, err := src.Query(context.Background(), Package{Ecosystem: EcosystemMaven, Name: "log4j"}, "2.14.0")
	require.Error(t, err)
	assert.Nil(t, advs)
}

// ─── Hybrid fetch: conditional GET + throttle + backoff ──────────────────────

// nvdPageHandler serves a paginated NVD 2.0 feed slice and records requests.
func nvdPageHandler(vulns []string) (http.Handler, *int32, *string) {
	var requests int32
	var lastIfNoneMatch string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		// One vuln per page (resultsPerPage=1) to force pagination.
		start := 0
		if v := r.URL.Query().Get("startIndex"); v != "" {
			_, _ = fmtSscan(v, &start)
		}
		if start >= len(vulns) {
			_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":` + itoa(len(vulns)) + `,"vulnerabilities":[]}`))
			return
		}
		body := `{"resultsPerPage":1,"startIndex":` + itoa(start) + `,"totalResults":` + itoa(len(vulns)) + `,"vulnerabilities":[` + vulns[start] + `]}`
		_, _ = w.Write([]byte(body))
	})
	return h, &requests, &lastIfNoneMatch
}

// TestNVD_ConditionalGet304_UsesCache verifies that when a prior ETag is cached,
// a 304 response short-circuits to the cached feed without re-extraction.
func TestNVD_ConditionalGet304_UsesCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(mirrorDir(), "nvd-cve-feed.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nvd-cve-feed.json"), data, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nvd-feed.etag"), []byte(`"v1"`), 0o644))

	var sawConditional bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			sawConditional = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	enr := NewNVDEnricher(dir,
		WithNVDBaseURL(srv.URL),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(time.Duration) {}),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	require.NoError(t, enr.Enrich(context.Background(), advs))
	assert.True(t, sawConditional, "must issue a conditional GET with the stored ETag")
	require.Len(t, advs[0].CVSS, 1, "304 must fall back to the cached feed")
}

// TestNVD_Throttle_EnforcesMinInterval verifies the rate limiter sleeps between
// paginated requests to respect the NVD API budget (6s anonymous), using a fake
// clock so the test is instant and deterministic.
func TestNVD_Throttle_EnforcesMinInterval(t *testing.T) {
	t.Parallel()

	v1 := `{"cve":{"id":"CVE-2021-44228","metrics":{},"weaknesses":[],"references":[],"configurations":[]}}`
	v2 := `{"cve":{"id":"CVE-2099-0001","metrics":{},"weaknesses":[],"references":[],"configurations":[]}}`
	h, requests, _ := nvdPageHandler([]string{v1, v2})
	srv := httptest.NewServer(h)
	defer srv.Close()

	var mu sync.Mutex
	var sleeps []time.Duration
	enr := NewNVDEnricher(t.TempDir(),
		WithNVDBaseURL(srv.URL),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(d time.Duration) {
			mu.Lock()
			sleeps = append(sleeps, d)
			mu.Unlock()
		}),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	require.NoError(t, enr.Enrich(context.Background(), advs))

	assert.Equal(t, int32(2), atomic.LoadInt32(requests), "two paginated requests cover totalResults=2")
	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(sleeps), 1, "must throttle between requests")
	assert.Equal(t, 6*time.Second, sleeps[0], "anonymous min interval is 6s")
}

// TestNVD_Throttle_WithAPIKeyFaster verifies the min interval shrinks to 0.6s
// when an API key is configured (50 req/30s budget).
func TestNVD_Throttle_WithAPIKeyFaster(t *testing.T) {
	t.Parallel()

	v1 := `{"cve":{"id":"CVE-2021-44228","metrics":{},"weaknesses":[],"references":[],"configurations":[]}}`
	v2 := `{"cve":{"id":"CVE-2099-0001","metrics":{},"weaknesses":[],"references":[],"configurations":[]}}`
	h, _, _ := nvdPageHandler([]string{v1, v2})
	srv := httptest.NewServer(h)
	defer srv.Close()

	var mu sync.Mutex
	var sleeps []time.Duration
	enr := NewNVDEnricher(t.TempDir(),
		WithNVDBaseURL(srv.URL),
		WithNVDAPIKey("test-key"),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(d time.Duration) {
			mu.Lock()
			sleeps = append(sleeps, d)
			mu.Unlock()
		}),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	require.NoError(t, enr.Enrich(context.Background(), advs))

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(sleeps), 1)
	assert.Equal(t, 600*time.Millisecond, sleeps[0], "keyed min interval is 0.6s")
}

// TestNVD_RateLimitBackoff verifies that HTTP 429 responses are retried with
// backoff and the fetch ultimately succeeds within the retry budget.
func TestNVD_RateLimitBackoff(t *testing.T) {
	t.Parallel()

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0}}]},"weaknesses":[],"references":[],"configurations":[]}}]}`))
	}))
	defer srv.Close()

	var sleeps int32
	enr := NewNVDEnricher(t.TempDir(),
		WithNVDBaseURL(srv.URL),
		WithNVDClock(func() time.Time { return time.Unix(0, 0) }, func(time.Duration) {
			atomic.AddInt32(&sleeps, 1)
		}),
		WithNVDMaxRetries(5),
	)
	advs := []Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2021-44228"}}}
	require.NoError(t, enr.Enrich(context.Background(), advs))
	assert.GreaterOrEqual(t, atomic.LoadInt32(&attempts), int32(3), "must retry past the 429s")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&sleeps), int32(2), "must back off between retries")
	require.Len(t, advs[0].CVSS, 1)
}

// ─── tiny local helpers (avoid pulling fmt/strconv into table noise) ─────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}
