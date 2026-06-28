package ghfetch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory/ghfetch"
)

// ─── ParseCommitURL ───────────────────────────────────────────────────────────

func TestParseCommitURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantSHA   string
		wantOK    bool
	}{
		{
			name:      "valid commit URL",
			url:       "https://github.com/lodash/lodash/commit/abc1234",
			wantOwner: "lodash",
			wantRepo:  "lodash",
			wantSHA:   "abc1234",
			wantOK:    true,
		},
		{
			name:      "valid full SHA",
			url:       "https://github.com/owner/repo/commit/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantSHA:   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			wantOK:    true,
		},
		{
			name:      "trailing .patch stripped",
			url:       "https://github.com/owner/repo/commit/abc1234.patch",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantSHA:   "abc1234",
			wantOK:    true,
		},
		{
			name:      "trailing .diff stripped",
			url:       "https://github.com/owner/repo/commit/abc1234.diff",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantSHA:   "abc1234",
			wantOK:    true,
		},
		{
			name:   "PR URL rejected",
			url:    "https://github.com/owner/repo/pull/42",
			wantOK: false,
		},
		{
			name:   "compare URL rejected",
			url:    "https://github.com/owner/repo/compare/v1.0.0...v1.0.1",
			wantOK: false,
		},
		{
			name:   "non-github host rejected",
			url:    "https://gitlab.com/owner/repo/commit/abc1234",
			wantOK: false,
		},
		{
			name:   "http scheme rejected",
			url:    "http://github.com/owner/repo/commit/abc1234",
			wantOK: false,
		},
		{
			name:   "non-hex SHA rejected",
			url:    "https://github.com/owner/repo/commit/not-a-sha!",
			wantOK: false,
		},
		{
			name:   "SHA too short rejected",
			url:    "https://github.com/owner/repo/commit/abc12",
			wantOK: false,
		},
		{
			name:   "empty URL rejected",
			url:    "",
			wantOK: false,
		},
		{
			name:   "missing path segments rejected",
			url:    "https://github.com/owner/repo",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo, sha, ok := ghfetch.ParseCommitURL(tc.url)
			if ok != tc.wantOK {
				t.Fatalf("ParseCommitURL(%q) ok=%v, want %v", tc.url, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if owner != tc.wantOwner {
				t.Errorf("owner=%q, want %q", owner, tc.wantOwner)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo=%q, want %q", repo, tc.wantRepo)
			}
			if sha != tc.wantSHA {
				t.Errorf("sha=%q, want %q", sha, tc.wantSHA)
			}
		})
	}
}

// ─── Helpers for httptest ─────────────────────────────────────────────────────

// sampleDiff is a minimal unified diff touching one .ts file and one non-source file.
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
diff --git a/README.md b/README.md
index 0000003..0000004 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # utils
+Updated.
`

const sampleTSContent = `export function greet(name: string): string {
  return 'Hello, ' + name + '!';
  // fixed
}
`

const testOwner = "owner"
const testRepo = "repo"
const testSHA = "abc1234"

// newTestServer returns a test server that handles commit diff + raw file fetches.
// requestCount is incremented on each request.
func newTestServer(t *testing.T, requestCount *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// GitHub API: commit diff
	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+testSHA, func(w http.ResponseWriter, r *http.Request) {
		if requestCount != nil {
			requestCount.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleDiff))
	})

	// raw.githubusercontent.com equivalent: file content
	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+testSHA+"/src/utils.ts", func(w http.ResponseWriter, r *http.Request) {
		if requestCount != nil {
			requestCount.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleTSContent))
	})

	return httptest.NewServer(mux)
}

// newClient builds a Client pointed at the test server with the given cache dir.
func newClient(t *testing.T, srv *httptest.Server, cacheDir string) *ghfetch.Client {
	t.Helper()
	c := ghfetch.NewClient(cacheDir)
	c.BaseAPIURL = srv.URL
	c.BaseRawURL = srv.URL
	c.HTTPClient = srv.Client()
	return c
}

// ─── FetchFix happy path ──────────────────────────────────────────────────────

func TestFetchFix_HappyPath(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newTestServer(t, nil)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
	fix, err := c.FetchFix(context.Background(), commitURL)
	if err != nil {
		t.Fatalf("FetchFix returned unexpected error: %v", err)
	}
	if fix == nil {
		t.Fatal("FetchFix returned nil fix, want non-nil")
	}
	if fix.Patch != sampleDiff {
		t.Errorf("fix.Patch mismatch\ngot:  %q\nwant: %q", fix.Patch, sampleDiff)
	}
	if len(fix.Files) != 1 {
		t.Fatalf("len(fix.Files)=%d, want 1 (only the .ts file)", len(fix.Files))
	}
	if fix.Files[0].Path != "src/utils.ts" {
		t.Errorf("fix.Files[0].Path=%q, want %q", fix.Files[0].Path, "src/utils.ts")
	}
	if fix.Files[0].Content != sampleTSContent {
		t.Errorf("fix.Files[0].Content mismatch\ngot:  %q\nwant: %q", fix.Files[0].Content, sampleTSContent)
	}
}

// ─── Degrade: non-200 responses ──────────────────────────────────────────────

func TestFetchFix_Degrade_403(t *testing.T) {
	cacheDir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newClient(t, srv, cacheDir)
	fix, err := c.FetchFix(context.Background(), "https://github.com/owner/repo/commit/abc1234")
	if err != nil {
		t.Fatalf("FetchFix returned error on 403 (should degrade): %v", err)
	}
	if fix != nil {
		t.Errorf("FetchFix returned non-nil fix on 403, want nil")
	}
}

func TestFetchFix_Degrade_404(t *testing.T) {
	cacheDir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newClient(t, srv, cacheDir)
	fix, err := c.FetchFix(context.Background(), "https://github.com/owner/repo/commit/abc1234")
	if err != nil {
		t.Fatalf("FetchFix returned error on 404 (should degrade): %v", err)
	}
	if fix != nil {
		t.Errorf("FetchFix returned non-nil fix on 404, want nil")
	}
}

// ─── Degrade: context cancellation ───────────────────────────────────────────

func TestFetchFix_Degrade_ContextCancelled(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newTestServer(t, nil)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	fix, err := c.FetchFix(ctx, "https://github.com/owner/repo/commit/abc1234")
	if err != nil {
		t.Fatalf("FetchFix returned error on cancelled context (should degrade): %v", err)
	}
	if fix != nil {
		t.Errorf("FetchFix returned non-nil fix on cancelled context, want nil")
	}
}

// ─── Degrade: server unreachable ─────────────────────────────────────────────

func TestFetchFix_Degrade_ServerUnreachable(t *testing.T) {
	cacheDir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close() // close immediately so connections fail

	c := newClient(t, srv, cacheDir)
	fix, err := c.FetchFix(context.Background(), "https://github.com/owner/repo/commit/abc1234")
	if err != nil {
		t.Fatalf("FetchFix returned error on unreachable server (should degrade): %v", err)
	}
	if fix != nil {
		t.Errorf("FetchFix returned non-nil fix for unreachable server, want nil")
	}
}

// ─── Cache: second call must not hit network ─────────────────────────────────

func TestFetchFix_Cache(t *testing.T) {
	cacheDir := t.TempDir()
	var count atomic.Int64
	srv := newTestServer(t, &count)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)
	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA

	// First fetch — populates cache.
	fix1, err := c.FetchFix(context.Background(), commitURL)
	if err != nil || fix1 == nil {
		t.Fatalf("first FetchFix failed: err=%v fix=%v", err, fix1)
	}
	countAfterFirst := count.Load()
	if countAfterFirst == 0 {
		t.Fatal("expected at least one HTTP request on first fetch")
	}

	// Second fetch — must be served from cache, no new requests.
	fix2, err := c.FetchFix(context.Background(), commitURL)
	if err != nil || fix2 == nil {
		t.Fatalf("second FetchFix failed: err=%v fix=%v", err, fix2)
	}
	countAfterSecond := count.Load()
	if countAfterSecond != countAfterFirst {
		t.Errorf("cache miss: HTTP request count went from %d to %d on second fetch",
			countAfterFirst, countAfterSecond)
	}
	if fix2.Patch != fix1.Patch {
		t.Errorf("cached patch mismatch")
	}
}

// ─── Unsupported URL (PR) → nil, nil, no HTTP ────────────────────────────────

func TestFetchFix_UnsupportedURL(t *testing.T) {
	cacheDir := t.TempDir()
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClient(t, srv, cacheDir)
	fix, err := c.FetchFix(context.Background(), "https://github.com/owner/repo/pull/42")
	if err != nil {
		t.Fatalf("FetchFix returned error for unsupported URL: %v", err)
	}
	if fix != nil {
		t.Errorf("FetchFix returned non-nil fix for PR URL, want nil")
	}
	if count.Load() != 0 {
		t.Errorf("FetchFix made HTTP requests for unsupported URL, want 0")
	}
}

// ─── Cache stored on disk ─────────────────────────────────────────────────────

func TestFetchFix_CachePersistedToDisk(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newTestServer(t, nil)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)
	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
	_, err := c.FetchFix(context.Background(), commitURL)
	if err != nil {
		t.Fatalf("FetchFix returned error: %v", err)
	}

	// Verify some cache file exists under cacheDir.
	found := false
	_ = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no cache file written to disk")
	}
}

// ─── Python ecosystem extension support ──────────────────────────────────────

// samplePyDiff is a minimal unified diff touching one .py file and one non-source file.
const samplePyDiff = `diff --git a/src/utils.py b/src/utils.py
index 0000001..0000002 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,3 +1,4 @@
 def greet(name):
-    return 'hello ' + name
+    return 'Hello, ' + name + '!'
+    # fixed
diff --git a/README.md b/README.md
index 0000003..0000004 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # utils
+Updated.
`

const samplePyContent = `def greet(name):
    return 'Hello, ' + name + '!'
    # fixed
`

// newPyTestServer returns a test server that handles commit diff + raw .py file fetches.
func newPyTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// GitHub API: commit diff
	mux.HandleFunc("/repos/"+testOwner+"/"+testRepo+"/commits/"+testSHA, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(samplePyDiff))
	})

	// raw.githubusercontent.com equivalent: .py file content
	mux.HandleFunc("/"+testOwner+"/"+testRepo+"/"+testSHA+"/src/utils.py", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(samplePyContent))
	})

	return httptest.NewServer(mux)
}

func TestFetchFixWithExtensions_PyPaths(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newPyTestServer(t)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
	fix, err := c.FetchFixWithExtensions(context.Background(), commitURL, ghfetch.PythonExtensions)
	if err != nil {
		t.Fatalf("FetchFixWithExtensions returned unexpected error: %v", err)
	}
	if fix == nil {
		t.Fatal("FetchFixWithExtensions returned nil fix, want non-nil")
	}
	if len(fix.Files) != 1 {
		t.Fatalf("len(fix.Files)=%d, want 1 (only the .py file)", len(fix.Files))
	}
	if fix.Files[0].Path != "src/utils.py" {
		t.Errorf("fix.Files[0].Path=%q, want %q", fix.Files[0].Path, "src/utils.py")
	}
	if fix.Files[0].Content != samplePyContent {
		t.Errorf("fix.Files[0].Content mismatch\ngot: %q\nwant: %q", fix.Files[0].Content, samplePyContent)
	}
}

// FetchFix (default JS/TS) must NOT pick up .py files — regression test.
func TestFetchFix_DoesNotPickUpPyFiles(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newPyTestServer(t)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
	fix, err := c.FetchFix(context.Background(), commitURL)
	if err != nil {
		t.Fatalf("FetchFix returned unexpected error: %v", err)
	}
	if fix == nil {
		t.Fatal("FetchFix returned nil fix, want non-nil")
	}
	// The diff only has a .py source file + README.md; JS/TS filter must yield 0 source files.
	if len(fix.Files) != 0 {
		t.Errorf("FetchFix picked up %d files from a .py-only diff, want 0", len(fix.Files))
	}
}

// ─── Non-GitHub forge degrade ─────────────────────────────────────────────────

func TestParseFixURL_GitHub(t *testing.T) {
	kind, owner, repo, sha, ok := ghfetch.ParseFixURL("https://github.com/owner/repo/commit/abc1234")
	if !ok {
		t.Fatal("ParseFixURL returned ok=false for valid GitHub URL")
	}
	if kind != ghfetch.ForgeGitHub {
		t.Errorf("kind=%v, want ForgeGitHub", kind)
	}
	if owner != "owner" || repo != "repo" || sha != "abc1234" {
		t.Errorf("got owner=%q repo=%q sha=%q, want owner repo abc1234", owner, repo, sha)
	}
}

func TestParseFixURL_GitLab_UnsupportedForge(t *testing.T) {
	kind, _, _, _, ok := ghfetch.ParseFixURL("https://gitlab.com/owner/repo/commit/abc1234")
	// A non-GitHub URL that looks like a commit URL is ok=true but ForgeUnsupported.
	// (Different from a totally unparseable URL.)
	if !ok {
		// ok=false is also acceptable (URL too ambiguous to parse forge); test both paths.
		return
	}
	if kind != ghfetch.ForgeUnsupported {
		t.Errorf("kind=%v, want ForgeUnsupported for GitLab URL", kind)
	}
}

func TestFetchFixWithExtensions_NonGitHubForge_DefinedDegrade(t *testing.T) {
	cacheDir := t.TempDir()
	// Non-GitHub commit URL — server is never reached.
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	// GitLab commit URL: should not silently return (nil, nil) without signalling
	// the forge is unsupported; instead FetchFixResult.UnsupportedForge must be true.
	result, err := c.FetchFixResult(context.Background(), "https://gitlab.com/owner/repo/-/commit/abc1234", ghfetch.JSExtensions)
	if err != nil {
		t.Fatalf("FetchFixResult returned unexpected error: %v", err)
	}
	if !result.UnsupportedForge {
		t.Errorf("FetchFixResult.UnsupportedForge=false for GitLab URL, want true (defined degrade, not silent zero)")
	}
	if count.Load() != 0 {
		t.Errorf("made %d HTTP requests for non-GitHub URL, want 0", count.Load())
	}
}

func TestFetchFixResult_GitHub_HappyPath(t *testing.T) {
	cacheDir := t.TempDir()
	srv := newTestServer(t, nil)
	defer srv.Close()

	c := newClient(t, srv, cacheDir)

	commitURL := "https://github.com/" + testOwner + "/" + testRepo + "/commit/" + testSHA
	result, err := c.FetchFixResult(context.Background(), commitURL, ghfetch.JSExtensions)
	if err != nil {
		t.Fatalf("FetchFixResult returned unexpected error: %v", err)
	}
	if result.UnsupportedForge {
		t.Error("FetchFixResult.UnsupportedForge=true for GitHub URL, want false")
	}
	if result.Fix == nil {
		t.Fatal("FetchFixResult.Fix=nil for valid GitHub commit, want non-nil")
	}
	if len(result.Fix.Files) != 1 {
		t.Errorf("len(Fix.Files)=%d, want 1", len(result.Fix.Files))
	}
}
