package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"
)

// defaultHTTPTimeout is the per-request timeout for vuln.go.dev fetches.
// 30 s is generous enough for index files (~370 KB) and individual OSV records
// on slow connections, while still failing fast on hung connections.
const defaultHTTPTimeout = 30 * time.Second

// Fetcher downloads OSV advisories from a vuln.go.dev-compatible endpoint
// (default: https://vuln.go.dev) into a local cache directory.
//
// It is intentionally stateless: all state lives in the destination directory
// written by FetchModules, so concurrent Fetcher instances targeting distinct
// directories are safe without additional coordination.
type Fetcher struct {
	// BaseURL is the root URL of the vuln.go.dev API (no trailing slash).
	// Defaults to "https://vuln.go.dev"; override in tests via httptest.Server.URL.
	BaseURL string
	// HTTP is the HTTP client used for all requests. A non-nil client with a
	// reasonable timeout is expected; NewFetcher sets a 30-second default.
	HTTP *http.Client
}

// NewFetcher returns a Fetcher targeting the real vuln.go.dev with a 30-second
// per-request timeout. Inject the returned value into CacheConfig.Fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		BaseURL: "https://vuln.go.dev",
		HTTP:    &http.Client{Timeout: defaultHTTPTimeout},
	}
}

// ─── vuln.go.dev index types ─────────────────────────────────────────────────

// moduleIndexEntry is one entry in /index/modules.json.
type moduleIndexEntry struct {
	Path  string          `json:"path"`
	Vulns []moduleVulnRef `json:"vulns"`
}

// moduleVulnRef is the per-advisory stub inside /index/modules.json.
type moduleVulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Fixed    string `json:"fixed,omitempty"`
}

// dbIndex is the shape of /index/db.json.
type dbIndex struct {
	Modified string `json:"modified"`
}

// ─── FetchModules ─────────────────────────────────────────────────────────────

// FetchModules downloads OSV advisories for the requested module paths from
// the vuln.go.dev v1 API and writes them atomically into destDir.
//
// Protocol:
//  1. GET /index/modules.json — full module→advisory index (fetched once).
//  2. Collect unique GO-IDs whose module path is in the modules set.
//  3. GET /ID/<id>.json for each unique ID; atomicWrite each into destDir.
//  4. GET /index/db.json — return its "modified" for the caller to record in
//     the manifest as DBSourceVersion.
//
// Failure semantics ("unknown ≠ safe"):
//   - Any non-200 HTTP response or network error is a hard error.
//   - On any error, NO advisory files are written (all writes are deferred
//     until all fetches succeed, so the caller never sees partial state).
//   - The caller (Cache.Refresh) is responsible for writing the manifest;
//     FetchModules never writes the manifest itself.
//
// Context cancellation is respected between individual ID fetches.
func (f *Fetcher) FetchModules(ctx context.Context, modules []string, destDir string) (dbModified string, err error) {
	// Build a fast-lookup set for the requested module paths.
	wantModule := make(map[string]struct{}, len(modules))
	for _, m := range modules {
		wantModule[m] = struct{}{}
	}

	// 1. Fetch /index/modules.json — one round-trip for the whole index.
	index, err := f.fetchModulesIndex(ctx)
	if err != nil {
		return "", err
	}

	// 2. Collect unique GO-IDs whose module is in the requested set.
	//    Deduplication avoids redundant ID fetches when multiple modules share
	//    the same advisory (rare but valid in the vuln.go.dev index).
	seen := make(map[string]struct{})
	var ids []string
	for _, entry := range index {
		if _, ok := wantModule[entry.Path]; !ok {
			continue
		}
		for _, v := range entry.Vulns {
			if _, dup := seen[v.ID]; dup {
				continue
			}
			seen[v.ID] = struct{}{}
			ids = append(ids, v.ID)
		}
	}

	// 3. Fetch each OSV record. Accumulate in memory first so that a failure
	//    part-way through does not leave a partially-written destDir.
	fetched := make(map[string][]byte, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		data, err := f.fetchID(ctx, id)
		if err != nil {
			return "", fmt.Errorf("advisory: fetch %s: %w", id, err)
		}
		fetched[id] = data
	}

	// 4. Fetch /index/db.json for the DB-level modified timestamp.
	modified, err := f.fetchDBModified(ctx)
	if err != nil {
		return "", err
	}

	// All fetches succeeded — now write files atomically.
	for id, data := range fetched {
		path := filepath.Join(destDir, id+".json")
		if err := atomicWrite(path, data); err != nil {
			return "", fmt.Errorf("advisory: write %s: %w", id, err)
		}
	}

	return modified, nil
}

// ─── internal fetch helpers ───────────────────────────────────────────────────

// fetchModulesIndex GETs /index/modules.json and returns the parsed slice.
func (f *Fetcher) fetchModulesIndex(ctx context.Context) ([]moduleIndexEntry, error) {
	body, err := f.get(ctx, f.BaseURL+"/index/modules.json")
	if err != nil {
		return nil, fmt.Errorf("advisory: fetch modules index: %w", err)
	}

	var index []moduleIndexEntry
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("advisory: decode modules index: %w", err)
	}
	return index, nil
}

// fetchID GETs /ID/<id>.json and returns the raw bytes.
func (f *Fetcher) fetchID(ctx context.Context, id string) ([]byte, error) {
	body, err := f.get(ctx, f.BaseURL+"/ID/"+id+".json")
	if err != nil {
		return nil, err
	}
	return body, nil
}

// fetchDBModified GETs /index/db.json and returns the "modified" field.
func (f *Fetcher) fetchDBModified(ctx context.Context) (string, error) {
	body, err := f.get(ctx, f.BaseURL+"/index/db.json")
	if err != nil {
		return "", fmt.Errorf("advisory: fetch db index: %w", err)
	}

	var db dbIndex
	if err := json.Unmarshal(body, &db); err != nil {
		return "", fmt.Errorf("advisory: decode db index: %w", err)
	}
	return db.Modified, nil
}

// get executes a GET request and returns the response body.
// A non-200 status code is treated as a hard error (unknown ≠ safe).
func (f *Fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}
	return body, nil
}
