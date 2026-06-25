package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Mock vuln.go.dev server helpers ─────────────────────────────────────────

// modulesIndexEntry mirrors the JSON shape of /index/modules.json entries.
type modulesIndexEntry struct {
	Path  string            `json:"path"`
	Vulns []modulesVulnRef  `json:"vulns"`
}

type modulesVulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Fixed    string `json:"fixed,omitempty"`
}

// newMockVulnServer builds an httptest.Server that serves:
//   - /index/modules.json  — the given modules index
//   - /index/db.json       — {"modified": dbModified}
//   - /ID/<id>.json        — looked up from idFiles map (id → JSON bytes)
//
// It counts every /index/modules.json, /index/db.json, and /ID/* request
// using the provided counters (pass nil to skip counting).
func newMockVulnServer(
	t *testing.T,
	modules []modulesIndexEntry,
	dbModified string,
	idFiles map[string][]byte,
	indexRequests *atomic.Int64,
	dbRequests *atomic.Int64,
	idRequests *atomic.Int64,
) *httptest.Server {
	t.Helper()

	modulesJSON, err := json.Marshal(modules)
	require.NoError(t, err)

	dbJSON := []byte(`{"modified":"` + dbModified + `"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/index/modules.json":
			if indexRequests != nil {
				indexRequests.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(modulesJSON)

		case r.URL.Path == "/index/db.json":
			if dbRequests != nil {
				dbRequests.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(dbJSON)

		case len(r.URL.Path) > 4 && r.URL.Path[:4] == "/ID/":
			if idRequests != nil {
				idRequests.Add(1)
			}
			// Strip "/ID/" prefix and ".json" suffix to get the advisory ID.
			name := r.URL.Path[4:] // e.g. "GO-2024-0001.json"
			data, ok := idFiles[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)

		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(srv.Close)
	return srv
}

// ─── TDD Group 1: FetchModules writes matching OSV files ─────────────────────

// TestFetchModules_WritesMatchingFiles verifies that FetchModules:
//   - GETs /index/modules.json once
//   - Collects GO-IDs whose module path is in the requested set
//   - Writes exactly one <id>.json per matching advisory into destDir
//   - Returns the db modified timestamp from /index/db.json
//   - Written content matches what the mock server served
func TestFetchModules_WritesMatchingFiles(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")
	idB := loadFixture(t, "GO-2024-0002.json")

	const dbModified = "2024-06-15T00:00:00Z"

	modules := []modulesIndexEntry{
		{
			Path: "github.com/example/vulnpkg",
			Vulns: []modulesVulnRef{
				{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"},
			},
		},
		{
			Path: "github.com/example/pkgonly",
			Vulns: []modulesVulnRef{
				{ID: "GO-2024-0002", Modified: "2024-06-01T00:00:00Z"},
			},
		},
		{
			Path: "github.com/example/safe",
			Vulns: []modulesVulnRef{}, // no vulns
		},
	}

	idFiles := map[string][]byte{
		"GO-2024-0001.json": idA,
		"GO-2024-0002.json": idB,
	}

	srv := newMockVulnServer(t, modules, dbModified, idFiles, nil, nil, nil)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	destDir := t.TempDir()

	gotModified, err := f.FetchModules(context.Background(), []string{
		"github.com/example/vulnpkg",
		"github.com/example/pkgonly",
	}, destDir)
	require.NoError(t, err)
	assert.Equal(t, dbModified, gotModified)

	// Exactly GO-2024-0001.json and GO-2024-0002.json should be written.
	got0001, err := os.ReadFile(filepath.Join(destDir, "GO-2024-0001.json"))
	require.NoError(t, err, "GO-2024-0001.json must exist in destDir")
	assert.Equal(t, idA, got0001, "GO-2024-0001.json content must match mock")

	got0002, err := os.ReadFile(filepath.Join(destDir, "GO-2024-0002.json"))
	require.NoError(t, err, "GO-2024-0002.json must exist in destDir")
	assert.Equal(t, idB, got0002, "GO-2024-0002.json content must match mock")

	// No extra JSON files written (only the two advisory files).
	entries, err := os.ReadDir(destDir)
	require.NoError(t, err)
	var jsonFiles []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			jsonFiles = append(jsonFiles, e.Name())
		}
	}
	assert.Len(t, jsonFiles, 2, "exactly 2 advisory JSON files should be written")
}

// ─── TDD Group 2: Module with no advisories → no files, no error ─────────────

// TestFetchModules_NoAdvisories verifies that a module whose vulns list is empty
// results in no files written and a nil error.
func TestFetchModules_NoAdvisories(t *testing.T) {
	const dbModified = "2024-06-15T00:00:00Z"

	modules := []modulesIndexEntry{
		{Path: "github.com/example/safe", Vulns: []modulesVulnRef{}},
	}

	srv := newMockVulnServer(t, modules, dbModified, map[string][]byte{}, nil, nil, nil)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	destDir := t.TempDir()

	gotModified, err := f.FetchModules(context.Background(), []string{"github.com/example/safe"}, destDir)
	require.NoError(t, err)
	assert.Equal(t, dbModified, gotModified)

	// No files written.
	entries, err := os.ReadDir(destDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "no files should be written for a module with no advisories")
}

// ─── TDD Group 3: HTTP 500 on ID fetch → hard error, no partial state ────────

// TestFetchModules_IDFetch500_HardError verifies that an HTTP 500 from an /ID/
// endpoint causes FetchModules to return a non-nil error and write no OSV files.
func TestFetchModules_IDFetch500_HardError(t *testing.T) {
	const dbModified = "2024-06-15T00:00:00Z"

	// The mock will serve 500 for all /ID/ requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules.json":
			json.NewEncoder(w).Encode([]modulesIndexEntry{ //nolint:errcheck
				{
					Path: "github.com/example/vulnpkg",
					Vulns: []modulesVulnRef{
						{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"},
					},
				},
			})
		case "/index/db.json":
			w.Write([]byte(`{"modified":"` + dbModified + `"}`)) //nolint:errcheck
		default:
			// Any /ID/ request gets a 500.
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	destDir := t.TempDir()

	_, err := f.FetchModules(context.Background(), []string{"github.com/example/vulnpkg"}, destDir)
	require.Error(t, err, "HTTP 500 on /ID/ fetch must be a hard error")

	// No partial state: no JSON files in destDir.
	entries, err2 := os.ReadDir(destDir)
	require.NoError(t, err2)
	var jsonFiles []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			jsonFiles = append(jsonFiles, e.Name())
		}
	}
	assert.Empty(t, jsonFiles, "no advisory JSON files should be written after a hard error")
}

// TestFetchModules_ModulesIndexFetch500_HardError verifies that an HTTP 500 from
// /index/modules.json itself is a hard error.
func TestFetchModules_ModulesIndexFetch500_HardError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	destDir := t.TempDir()

	_, err := f.FetchModules(context.Background(), []string{"github.com/example/vulnpkg"}, destDir)
	require.Error(t, err, "HTTP 500 on /index/modules.json must be a hard error")
}

// TestFetchModules_ContextCancel verifies that cancelling the context results
// in an error, not a silent no-op.
func TestFetchModules_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve modules.json so FetchModules gets past the first call, then
		// any ID fetch is blocked — but context will be cancelled first.
		if r.URL.Path == "/index/modules.json" {
			json.NewEncoder(w).Encode([]modulesIndexEntry{ //nolint:errcheck
				{
					Path: "github.com/example/vulnpkg",
					Vulns: []modulesVulnRef{
						{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"},
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := f.FetchModules(ctx, []string{"github.com/example/vulnpkg"}, t.TempDir())
	require.Error(t, err, "cancelled context must produce an error")
}

// ─── TDD Group 4: De-duplication of GO-IDs ───────────────────────────────────

// TestFetchModules_DeduplicatesIDs verifies that the same GO-ID referenced by
// multiple modules is fetched only once and written only once.
func TestFetchModules_DeduplicatesIDs(t *testing.T) {
	idA := loadFixture(t, "GO-2024-0001.json")

	const dbModified = "2024-06-15T00:00:00Z"

	// Two modules share the same advisory ID.
	modules := []modulesIndexEntry{
		{
			Path:  "github.com/example/vulnpkg",
			Vulns: []modulesVulnRef{{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"}},
		},
		{
			Path:  "github.com/example/other",
			Vulns: []modulesVulnRef{{ID: "GO-2024-0001", Modified: "2024-06-01T00:00:00Z"}},
		},
	}

	var idFetchCount atomic.Int64
	srv := newMockVulnServer(t, modules, dbModified, map[string][]byte{
		"GO-2024-0001.json": idA,
	}, nil, nil, &idFetchCount)

	f := &Fetcher{BaseURL: srv.URL, HTTP: srv.Client()}
	destDir := t.TempDir()

	_, err := f.FetchModules(context.Background(), []string{
		"github.com/example/vulnpkg",
		"github.com/example/other",
	}, destDir)
	require.NoError(t, err)

	// The ID must have been fetched exactly once.
	assert.Equal(t, int64(1), idFetchCount.Load(), "shared GO-ID must be fetched only once")

	// The file must exist.
	_, err = os.Stat(filepath.Join(destDir, "GO-2024-0001.json"))
	assert.NoError(t, err)
}
