package symbolindex_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
	"github.com/ducthinh993/anst-analyzer/internal/advisory/ghfetch"
	"github.com/ducthinh993/anst-analyzer/internal/advisory/symbolindex"
)

// ─── Fake plugin binary helpers ───────────────────────────────────────────────

// makeEchoPlugin writes a shell script that ignores stdin and always echoes the
// given JSON payload. Returns the path to the script.
func makeEchoPlugin(t *testing.T, payload string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-plugin.sh")
	// Single-quotes the payload; we rely on the caller passing valid JSON without
	// single-quotes inside (true for our test fixtures).
	content := "#!/bin/sh\nprintf '%s' '" + payload + "'\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	return script
}

// makeEmptyPlugin writes a plugin script that returns an empty JSON array.
func makeEmptyPlugin(t *testing.T) string {
	return makeEchoPlugin(t, "[]")
}

// ─── Fake HTTP server helpers ─────────────────────────────────────────────────

const (
	testOwner = "owner"
	testRepo  = "repo"
	testSHA   = "abc1234"
)

const sampleDiff = `diff --git a/src/utils.ts b/src/utils.ts
index 0000001..0000002 100644
--- a/src/utils.ts
+++ b/src/utils.ts
@@ -1,3 +1,4 @@
 export function greet(name: string): string {
-  return 'hello ' + name;
+  return 'Hello, ' + name + '!';
+  // fixed
 }
`

const sampleTSContent = `export function greet(name: string): string {
  return 'Hello, ' + name + '!';
  // fixed
}
`

// newGHTestServer returns an httptest.Server that serves the sample commit diff
// and the raw .ts file. requestCount is incremented on each incoming request.
func newGHTestServer(t *testing.T, requestCount *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+testSHA,
		func(w http.ResponseWriter, r *http.Request) {
			if requestCount != nil {
				requestCount.Add(1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleDiff))
		})

	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+testSHA+"/src/utils.ts",
		func(w http.ResponseWriter, r *http.Request) {
			if requestCount != nil {
				requestCount.Add(1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleTSContent))
		})

	return httptest.NewServer(mux)
}

// newGHClient builds a ghfetch.Client pointing at the test server.
func newGHClient(t *testing.T, srv *httptest.Server, cacheDir string) *ghfetch.Client {
	t.Helper()
	c := ghfetch.NewClient(cacheDir)
	c.BaseAPIURL = srv.URL
	c.BaseRawURL = srv.URL
	c.HTTPClient = srv.Client()
	return c
}

// commitURL builds a fake GitHub commit URL for the test owner/repo/sha.
func commitURL() string {
	return "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
}

// ─── Resolver tests ───────────────────────────────────────────────────────────

// TestResolver_ResolvesAndPersists verifies the happy path:
//   - A network fetch returns a fix → plugin extracts a symbol → Resolve returns it.
//   - A second Resolve call reads from the index with zero new HTTP requests.
func TestResolver_ResolvesAndPersists(t *testing.T) {
	var count atomic.Int64
	srv := newGHTestServer(t, &count)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEchoPlugin(t,
		`[{"file":"src/utils.ts","exportName":"greet","kind":"function"}]`)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	adv := &advisory.Advisory{
		ID:      "GHSA-test-0001",
		FixRefs: []string{commitURL()},
	}

	syms := r.Resolve(context.Background(), adv)

	require.Len(t, syms, 1, "expected one symbol from the fake plugin")
	assert.Equal(t, "greet", syms[0].Name)
	countAfterFirst := count.Load()
	assert.Greater(t, countAfterFirst, int64(0), "expected HTTP requests on first resolve")

	// Second resolve: must be served from index (no new network).
	syms2 := r.Resolve(context.Background(), adv)
	require.Len(t, syms2, 1)
	assert.Equal(t, "greet", syms2[0].Name)
	assert.Equal(t, countAfterFirst, count.Load(),
		"second Resolve must use index cache; no new HTTP requests")
}

// TestResolver_Offline_EmptyIndex_ReturnsEmpty verifies the offline soundness rule:
// when offline=true and the index is empty, Resolve returns empty without any network.
func TestResolver_Offline_EmptyIndex_ReturnsEmpty(t *testing.T) {
	var count atomic.Int64
	srv := newGHTestServer(t, &count)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEchoPlugin(t,
		`[{"file":"src/utils.ts","exportName":"greet","kind":"function"}]`)

	// offline=true: must never fetch even though the test server is alive.
	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, true)

	adv := &advisory.Advisory{
		ID:      "GHSA-offline-test",
		FixRefs: []string{commitURL()},
	}

	syms := r.Resolve(context.Background(), adv)

	assert.Empty(t, syms, "offline with empty index must return empty symbols")
	assert.Equal(t, int64(0), count.Load(),
		"offline Resolve must make zero HTTP requests")
}

// TestResolver_GHFetchFailure_DegradeQuietly verifies that a ghfetch error (404)
// yields empty symbols without panicking or propagating an error.
func TestResolver_GHFetchFailure_DegradeQuietly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEchoPlugin(t, `[{"file":"a.ts","exportName":"foo","kind":"function"}]`)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	adv := &advisory.Advisory{
		ID:      "GHSA-fail-0001",
		FixRefs: []string{commitURL()},
	}

	syms := r.Resolve(context.Background(), adv)

	assert.Empty(t, syms, "fetch failure must degrade to empty symbols, not panic or error")
}

// TestResolver_Staleness_ChangedFixRefs_Refetches verifies that when an advisory's
// FixRefs change (staleness guard), the old index entry is ignored and a fresh
// network fetch is performed.
func TestResolver_Staleness_ChangedFixRefs_Refetches(t *testing.T) {
	const altOwner = "other"
	const altRepo = "repo2"
	const altSHA = "dead123"

	var count atomic.Int64

	mux := http.NewServeMux()

	// Serve the original commit.
	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+testSHA,
		func(w http.ResponseWriter, _ *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleDiff))
		})
	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+testSHA+"/src/utils.ts",
		func(w http.ResponseWriter, _ *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleTSContent))
		})

	// Serve an alternate commit (different SHA, different content).
	altDiff := `diff --git a/src/helper.ts b/src/helper.ts
index 0000001..0000002 100644
--- a/src/helper.ts
+++ b/src/helper.ts
@@ -1 +1,2 @@
 export function sanitize(s: string) { return s; }
+// patched
`
	altContent := `export function sanitize(s: string) { return s; }
// patched
`
	mux.HandleFunc("/repos/"+altOwner+"/"+altRepo+"/commits/"+altSHA,
		func(w http.ResponseWriter, _ *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(altDiff))
		})
	mux.HandleFunc("/"+altOwner+"/"+altRepo+"/"+altSHA+"/src/helper.ts",
		func(w http.ResponseWriter, _ *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(altContent))
		})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEchoPlugin(t,
		`[{"file":"src/utils.ts","exportName":"greet","kind":"function"}]`)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	origFixRef := commitURL()
	adv := &advisory.Advisory{
		ID:      "GHSA-stale-0001",
		FixRefs: []string{origFixRef},
	}

	// First resolve: populates index with origFixRef.
	syms1 := r.Resolve(context.Background(), adv)
	require.NotEmpty(t, syms1, "first resolve must return symbols")
	countAfterFirst := count.Load()
	assert.Greater(t, countAfterFirst, int64(0))

	// Change FixRefs — the index entry should be invalidated.
	altFixRef := "https://github.com/" + altOwner + "/" + altRepo + "/commit/" + altSHA
	adv.FixRefs = []string{altFixRef}

	// Build a new resolver that uses the same cache dir (to read the persisted index)
	// but has a plugin that returns a different symbol name to confirm re-fetch happened.
	pluginBin2 := makeEchoPlugin(t,
		`[{"file":"src/helper.ts","exportName":"sanitize","kind":"function"}]`)
	r2 := symbolindex.NewResolver(cacheDir, ghClient, pluginBin2, false)
	syms2 := r2.Resolve(context.Background(), adv)

	require.Len(t, syms2, 1, "changed FixRefs must trigger re-fetch and return new symbols")
	assert.Equal(t, "sanitize", syms2[0].Name)
	assert.Greater(t, count.Load(), countAfterFirst,
		"changed FixRefs must cause new HTTP requests (not served from stale index)")
}

// TestResolver_MultipleFixRefs_DeduplicatesSymbols verifies that symbols from
// multiple FixRefs are aggregated, deduplicated by name, and sorted.
func TestResolver_MultipleFixRefs_DeduplicatesSymbols(t *testing.T) {
	const sha2 = "beef456"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+testSHA,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleDiff))
		})
	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+testSHA+"/src/utils.ts",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sampleTSContent))
		})
	diff2 := `diff --git a/src/foo.ts b/src/foo.ts
--- a/src/foo.ts
+++ b/src/foo.ts
@@ -1 +1,2 @@
 export function greet() {}
+export function bar() {}
`
	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+sha2,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(diff2))
		})
	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+sha2+"/src/foo.ts",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("export function greet() {}\nexport function bar() {}\n"))
		})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))

	// Plugin always returns "greet" regardless of which commit — so we get a
	// duplicate that the resolver must deduplicate.
	pluginBin := makeEchoPlugin(t,
		`[{"file":"src/utils.ts","exportName":"greet","kind":"function"}]`)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	adv := &advisory.Advisory{
		ID: "GHSA-multi-0001",
		FixRefs: []string{
			commitURL(),
			"https://github.com/" + testOwner + "/" + testRepo + "/commit/" + sha2,
		},
	}

	syms := r.Resolve(context.Background(), adv)

	// "greet" appears in both FixRefs; deduplication must yield exactly one entry.
	require.Len(t, syms, 1, "duplicate symbol across FixRefs must be deduplicated")
	assert.Equal(t, "greet", syms[0].Name)
}

// TestResolver_NoFixRefs_ReturnsEmpty verifies that an advisory with no FixRefs
// returns empty symbols without network access.
func TestResolver_NoFixRefs_ReturnsEmpty(t *testing.T) {
	var count atomic.Int64
	srv := newGHTestServer(t, &count)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEmptyPlugin(t)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	adv := &advisory.Advisory{
		ID:      "GHSA-nofixrefs",
		FixRefs: nil,
	}

	syms := r.Resolve(context.Background(), adv)

	assert.Empty(t, syms)
	assert.Equal(t, int64(0), count.Load(), "no FixRefs: must make zero HTTP requests")
}

// TestResolver_PersistsEmptyResult_NoContinuousRefetch verifies that when a
// FixRef resolves to no symbols (ghfetch 404 or plugin returns []), the empty
// result is persisted so subsequent scans don't re-fetch the same dead ref.
func TestResolver_PersistsEmptyResult_NoContinuousRefetch(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEmptyPlugin(t)

	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)

	adv := &advisory.Advisory{
		ID:      "GHSA-empty-0001",
		FixRefs: []string{commitURL()},
	}

	// First resolve: should attempt fetch (and get 404 → empty).
	syms1 := r.Resolve(context.Background(), adv)
	assert.Empty(t, syms1)
	countAfterFirst := count.Load()

	// Second resolve with a new resolver reading the same cache dir: must not re-fetch.
	r2 := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)
	syms2 := r2.Resolve(context.Background(), adv)
	assert.Empty(t, syms2)
	assert.Equal(t, countAfterFirst, count.Load(),
		"empty result must be persisted so second Resolve does not refetch")
}

// TestResolver_Offline_WithCachedEntry_ReturnsIt verifies that offline=true
// with a pre-populated index entry returns the cached symbols without fetching.
func TestResolver_Offline_WithCachedEntry_ReturnsIt(t *testing.T) {
	var count atomic.Int64
	srv := newGHTestServer(t, &count)
	defer srv.Close()

	cacheDir := t.TempDir()
	ghClient := newGHClient(t, srv, filepath.Join(cacheDir, "gh"))
	pluginBin := makeEchoPlugin(t,
		`[{"file":"src/utils.ts","exportName":"greet","kind":"function"}]`)

	// Online resolve to populate the index.
	r := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, false)
	adv := &advisory.Advisory{
		ID:      "GHSA-cached-0001",
		FixRefs: []string{commitURL()},
	}
	syms := r.Resolve(context.Background(), adv)
	require.Len(t, syms, 1)
	countAfterOnline := count.Load()

	// Now resolve offline with a new resolver over the same cache dir.
	rOffline := symbolindex.NewResolver(cacheDir, ghClient, pluginBin, true)
	symsOffline := rOffline.Resolve(context.Background(), adv)
	require.Len(t, symsOffline, 1)
	assert.Equal(t, "greet", symsOffline[0].Name)
	assert.Equal(t, countAfterOnline, count.Load(),
		"offline Resolve with cached entry must make zero new HTTP requests")
}
