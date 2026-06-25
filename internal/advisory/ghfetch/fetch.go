// Package ghfetch fetches the unified diff and changed-file contents for a
// GitHub commit URL, producing the inputs that the symbol extractor consumes.
//
// Soundness contract: any fetch failure, unsupported URL, non-200 response, or
// context cancellation returns (nil, nil) so callers can degrade to a
// package-level verdict.  A non-nil error is reserved for genuinely unexpected
// programming conditions.
package ghfetch

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ducthinh993/anst-analyzer/internal/advisory/symbolextract"
)

const (
	defaultBaseAPIURL = "https://api.github.com"
	defaultBaseRawURL = "https://raw.githubusercontent.com"
)

// sourceExtensions is the set of JS/TS file extensions whose content is fetched
// and forwarded to the symbol extractor. Mirrors the extractor's filter.
var sourceExtensions = map[string]bool{
	".js":  true,
	".cjs": true,
	".mjs": true,
	".jsx": true,
	".ts":  true,
	".cts": true,
	".mts": true,
	".tsx": true,
}

// Fix holds the unified diff of a security fix commit and the post-fix content
// of each changed source file.
type Fix struct {
	// Patch is the full unified diff returned by the GitHub API.
	Patch string
	// Files contains the post-fix content for each changed JS/TS source file.
	// Non-source files are excluded.  Paths are repo-relative (git "a/"/"b/"
	// prefixes stripped) to match the symbol extractor's path contract.
	Files []symbolextract.FileContent
}

// cachedFix is the JSON shape written to the on-disk cache.
type cachedFix struct {
	Patch string                      `json:"patch"`
	Files []symbolextract.FileContent `json:"files"`
}

// Client fetches GitHub commit diffs and file contents.
// All fields are exported so tests can inject a local httptest server.
type Client struct {
	// BaseAPIURL is the root of the GitHub API (no trailing slash).
	// Defaults to https://api.github.com.
	BaseAPIURL string
	// BaseRawURL is the root of the raw content server (no trailing slash).
	// Defaults to https://raw.githubusercontent.com.
	BaseRawURL string
	// HTTPClient is used for all requests.  Defaults to a 30-second client.
	HTTPClient *http.Client
	// Token is the GitHub personal-access token sent as a Bearer header.
	// Falls back to the GITHUB_TOKEN environment variable when empty.
	Token string
	// cacheDir is the root under which per-repo/per-sha cache files are stored.
	cacheDir string
}

// NewClient returns a Client that stores cached fixes under cacheDir.
// The directory is created on first use; it need not exist at construction.
func NewClient(cacheDir string) *Client {
	return &Client{
		BaseAPIURL: defaultBaseAPIURL,
		BaseRawURL: defaultBaseRawURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		cacheDir:   cacheDir,
	}
}

// ParseCommitURL parses a GitHub commit URL of the form
//
//	https://github.com/<owner>/<repo>/commit/<sha>[.patch|.diff]
//
// and returns the owner, repo, and sha components.  ok is false for any other
// URL shape (PR, compare, non-github host, non-hex SHA, wrong scheme).
func ParseCommitURL(raw string) (owner, repo, sha string, ok bool) {
	if raw == "" {
		return "", "", "", false
	}
	// Require HTTPS scheme.
	if !strings.HasPrefix(raw, "https://github.com/") {
		return "", "", "", false
	}
	// Strip scheme + host.
	path := strings.TrimPrefix(raw, "https://github.com/")
	// Expect exactly owner/repo/commit/<sha>.
	parts := strings.SplitN(path, "/", 5)
	if len(parts) < 4 {
		return "", "", "", false
	}
	if parts[2] != "commit" {
		return "", "", "", false
	}
	// owner/repo become filesystem path segments in the cache; constrain them to
	// the GitHub-legal charset so a crafted ref cannot escape the cache dir.
	if !isPathSegment(parts[0]) || !isPathSegment(parts[1]) {
		return "", "", "", false
	}
	rawSHA := parts[3]
	// Strip optional .patch or .diff suffix.
	rawSHA = strings.TrimSuffix(rawSHA, ".patch")
	rawSHA = strings.TrimSuffix(rawSHA, ".diff")

	// Validate: hex, 7–40 chars.
	if !isHexSHA(rawSHA) {
		return "", "", "", false
	}
	return parts[0], parts[1], rawSHA, true
}

// isPathSegment returns true when s is a non-empty GitHub-legal owner/repo
// segment ([A-Za-z0-9._-]) that is neither "." nor ".." — i.e. safe to use as
// a single filesystem path component.
func isPathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !isPathSegmentChar(c) {
			return false
		}
	}
	return true
}

// isPathSegmentChar reports whether c is allowed in a GitHub owner/repo segment.
func isPathSegmentChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-'
}

// isHexSHA returns true when s is a lowercase or uppercase hex string of
// length 7–40 (short SHA to full SHA).
func isHexSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isHexChar reports whether c is a hexadecimal digit (either case).
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// FetchFix fetches the unified diff and changed source-file contents for the
// commit at commitURL.
//
// Degrade semantics:
//   - Unsupported or unparseable URL → (nil, nil), no HTTP.
//   - Any non-200 response, network error, or context cancellation → (nil, nil).
//   - A commit whose changed files are all non-source → *Fix with empty Files.
//   - Cache hit → returns from disk, no HTTP.
func (c *Client) FetchFix(ctx context.Context, commitURL string) (*Fix, error) {
	owner, repo, sha, ok := ParseCommitURL(commitURL)
	if !ok {
		return nil, nil
	}

	// Check disk cache first.
	if cached := c.loadCache(owner, repo, sha); cached != nil {
		return cached, nil
	}

	// Fetch the unified diff from the GitHub API.
	patch, ok := c.fetchDiff(ctx, owner, repo, sha)
	if !ok {
		return nil, nil
	}

	// Parse changed source-file paths from the diff.
	paths := parseSourcePaths(patch)

	// Fetch each source file's content at the fixed SHA.
	files := make([]symbolextract.FileContent, 0, len(paths))
	for _, p := range paths {
		content, ok := c.fetchRaw(ctx, owner, repo, sha, p)
		if !ok {
			// Any single file fetch failure degrades the whole result.
			return nil, nil
		}
		files = append(files, symbolextract.FileContent{Path: p, Content: content})
	}

	fix := &Fix{Patch: patch, Files: files}
	c.saveCache(owner, repo, sha, fix)
	return fix, nil
}

// fetchDiff performs GET {BaseAPIURL}/repos/{owner}/{repo}/commits/{sha} with
// Accept: application/vnd.github.diff.  Returns (body, true) on 200 and
// ("", false) on any error or non-200 status.
func (c *Client) fetchDiff(ctx context.Context, owner, repo, sha string) (string, bool) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", c.BaseAPIURL, owner, repo, sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/vnd.github.diff")
	c.applyAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	return string(body), true
}

// fetchRaw performs GET {BaseRawURL}/{owner}/{repo}/{sha}/{path} and returns
// (content, true) on 200 or ("", false) on any failure.
func (c *Client) fetchRaw(ctx context.Context, owner, repo, sha, path string) (string, bool) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", c.BaseRawURL, owner, repo, sha, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	c.applyAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	return string(body), true
}

// applyAuth adds the Authorization header when a token is available.
func (c *Client) applyAuth(req *http.Request) {
	tok := c.Token
	if tok == "" {
		tok = os.Getenv("GITHUB_TOKEN")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

// parseSourcePaths scans a unified diff and returns the repo-relative paths of
// changed files whose extension is in sourceExtensions.  The git "a/"/"b/"
// prefixes are stripped so paths match the symbol extractor's contract.
func parseSourcePaths(patch string) []string {
	seen := make(map[string]bool)
	var paths []string
	sc := bufio.NewScanner(strings.NewReader(patch))
	for sc.Scan() {
		line := sc.Text()
		// "--- a/src/utils.ts" or "+++ b/src/utils.ts"
		var candidate string
		if strings.HasPrefix(line, "+++ b/") {
			candidate = strings.TrimPrefix(line, "+++ b/")
		} else if strings.HasPrefix(line, "--- a/") {
			candidate = strings.TrimPrefix(line, "--- a/")
			// /dev/null means deletion — skip (no content to fetch).
			if candidate == "/dev/null" {
				continue
			}
		} else {
			continue
		}
		if candidate == "" || seen[candidate] {
			continue
		}
		ext := filepath.Ext(candidate)
		if !sourceExtensions[ext] {
			continue
		}
		seen[candidate] = true
		paths = append(paths, candidate)
	}
	return paths
}

// ─── Disk cache ───────────────────────────────────────────────────────────────

// cachePath returns the path for the cache file for a given owner/repo/sha.
func (c *Client) cachePath(owner, repo, sha string) string {
	return filepath.Join(c.cacheDir, owner, repo, sha+".json")
}

// loadCache attempts to read a cached Fix from disk.  Returns nil on any error
// or cache miss (silent degrade — missing cache is not an error).
func (c *Client) loadCache(owner, repo, sha string) *Fix {
	data, err := os.ReadFile(c.cachePath(owner, repo, sha))
	if err != nil {
		return nil
	}
	var cf cachedFix
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil
	}
	return &Fix{Patch: cf.Patch, Files: cf.Files}
}

// saveCache writes a Fix to disk under {cacheDir}/{owner}/{repo}/{sha}.json.
// Errors are silently swallowed — a missing cache entry is handled on the next
// call by re-fetching.
func (c *Client) saveCache(owner, repo, sha string, fix *Fix) {
	p := c.cachePath(owner, repo, sha)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	cf := cachedFix{Patch: fix.Patch, Files: fix.Files}
	data, err := json.Marshal(cf)
	if err != nil {
		return
	}
	// Write to a temp file then rename for atomicity.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}
