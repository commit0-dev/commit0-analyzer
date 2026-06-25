// Package ghfetch fetches the unified diff and changed-file contents for a
// commit URL, producing the inputs that the symbol extractor consumes.
//
// Soundness contract: any fetch failure, non-200 response, or context
// cancellation degrades gracefully.  FetchFix returns (nil, nil) for backward
// compatibility.  FetchFixResult returns a FixResult whose UnsupportedForge
// field is true when the URL is a non-GitHub forge — this is a defined,
// surfaceable degrade, not a silent zero.  A non-nil error is reserved for
// genuinely unexpected programming conditions.
//
// Currently only GitHub is supported as a fetch target.  Non-GitHub forge URLs
// (GitLab, Gitea, Bitbucket, etc.) are detected and explicitly signalled via
// UnsupportedForge=true; no HTTP request is made.
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

// ForgeKind identifies the version-control hosting provider in a fix URL.
type ForgeKind int

const (
	// ForgeUnknown means the URL could not be parsed into a recognised forge shape.
	ForgeUnknown ForgeKind = iota
	// ForgeGitHub is a github.com commit URL.
	ForgeGitHub
	// ForgeUnsupported means the URL was parseable as a commit URL on a non-GitHub
	// forge (e.g. gitlab.com, gitea, Bitbucket) but that forge is not yet
	// supported.  Callers must surface this as a defined degrade (UNKNOWN +
	// incomplete), not treat it as equivalent to a network error.
	ForgeUnsupported
)

// JSExtensions is the extension set for JS/TS source files.
// It is the default used by FetchFix for backward compatibility.
var JSExtensions = map[string]bool{
	".js":  true,
	".cjs": true,
	".mjs": true,
	".jsx": true,
	".ts":  true,
	".cts": true,
	".mts": true,
	".tsx": true,
}

// PythonExtensions is the extension set for Python source files.
var PythonExtensions = map[string]bool{
	".py": true,
}

// FixResult is the richer return type from FetchFixResult.
// It separates the "unsupported forge" degrade from other failure modes so
// callers can surface it explicitly (e.g. set incomplete=true) rather than
// silently treating it as a cache miss or network error.
type FixResult struct {
	// Fix is non-nil on a successful fetch.  Nil when the fetch failed or the
	// forge is unsupported.
	Fix *Fix
	// UnsupportedForge is true when the URL was identified as a non-GitHub forge
	// commit URL.  Callers should surface this as UNKNOWN + incomplete.
	UnsupportedForge bool
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

// ParseFixURL is the ecosystem-aware successor to ParseCommitURL.  It returns:
//   - (ForgeGitHub, owner, repo, sha, true) for a valid github.com commit URL.
//   - (ForgeUnsupported, "", "", "", true) for a URL that looks like a commit
//     on a known non-GitHub forge (gitlab.com, gitea, Bitbucket paths, etc.)
//     so callers can surface an explicit "unsupported forge" degrade.
//   - (ForgeUnknown, "", "", "", false) for anything else (unparseable, PR,
//     non-HTTPS, non-hex SHA, etc.).
//
// The path-traversal and host guards from ParseCommitURL are preserved:
// owner/repo segments must match the GitHub-legal charset and may not be "."
// or "..".
func ParseFixURL(raw string) (forge ForgeKind, owner, repo, sha string, ok bool) {
	if raw == "" || !strings.HasPrefix(raw, "https://") {
		return ForgeUnknown, "", "", "", false
	}

	// GitHub fast path.
	if strings.HasPrefix(raw, "https://github.com/") {
		o, r, s, parsed := ParseCommitURL(raw)
		if !parsed {
			return ForgeUnknown, "", "", "", false
		}
		return ForgeGitHub, o, r, s, true
	}

	// Detect known non-GitHub forges by host prefix.
	knownForgeHosts := []string{
		"https://gitlab.com/",
		"https://bitbucket.org/",
		"https://codeberg.org/",
		"https://gitea.com/",
	}
	for _, prefix := range knownForgeHosts {
		if strings.HasPrefix(raw, prefix) {
			// It is a recognised non-GitHub forge — surfaceable degrade.
			return ForgeUnsupported, "", "", "", true
		}
	}

	// Unknown shape.
	return ForgeUnknown, "", "", "", false
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
// commit at commitURL using the default JS/TS extension set.
//
// Degrade semantics:
//   - Unsupported or unparseable URL → (nil, nil), no HTTP.
//   - Any non-200 response, network error, or context cancellation → (nil, nil).
//   - A commit whose changed files are all non-source → *Fix with empty Files.
//   - Cache hit → returns from disk, no HTTP.
//
// For richer degrade information (e.g. distinguishing unsupported forges from
// network errors), use FetchFixResult instead.
func (c *Client) FetchFix(ctx context.Context, commitURL string) (*Fix, error) {
	result, err := c.FetchFixResult(ctx, commitURL, JSExtensions)
	if err != nil {
		return nil, err
	}
	return result.Fix, nil
}

// FetchFixWithExtensions is like FetchFix but uses the caller-supplied extension
// set to filter which changed source files are fetched.  Use PythonExtensions for
// Python fix commits, JSExtensions (or nil) for JS/TS.
//
// If extensions is nil or empty, JSExtensions is used (backward-compatible default).
func (c *Client) FetchFixWithExtensions(ctx context.Context, commitURL string, extensions map[string]bool) (*Fix, error) {
	result, err := c.FetchFixResult(ctx, commitURL, extensions)
	if err != nil {
		return nil, err
	}
	return result.Fix, nil
}

// FetchFixResult is the recommended entry point for new callers.  It returns a
// FixResult that distinguishes:
//   - Successful fetch: Fix != nil, UnsupportedForge == false.
//   - Unsupported forge: Fix == nil, UnsupportedForge == true.  Callers should
//     surface this as UNKNOWN + incomplete, not treat it as equivalent to a
//     network error.
//   - Other failure (non-200, network error, cancelled, unparseable URL):
//     Fix == nil, UnsupportedForge == false.
//
// If extensions is nil or empty, JSExtensions is used.
func (c *Client) FetchFixResult(ctx context.Context, commitURL string, extensions map[string]bool) (FixResult, error) {
	if len(extensions) == 0 {
		extensions = JSExtensions
	}

	forge, owner, repo, sha, ok := ParseFixURL(commitURL)
	if !ok {
		// Unparseable URL (not even a known forge shape).
		return FixResult{}, nil
	}
	if forge != ForgeGitHub {
		// Recognised non-GitHub forge — explicit, surfaceable degrade.
		return FixResult{UnsupportedForge: true}, nil
	}

	// Check disk cache first.
	if cached := c.loadCache(owner, repo, sha); cached != nil {
		return FixResult{Fix: cached}, nil
	}

	// Fetch the unified diff from the GitHub API.
	patch, fetched := c.fetchDiff(ctx, owner, repo, sha)
	if !fetched {
		return FixResult{}, nil
	}

	// Parse changed source-file paths from the diff using the caller's extension set.
	paths := parseSourcePaths(patch, extensions)

	// Fetch each source file's content at the fixed SHA.
	files := make([]symbolextract.FileContent, 0, len(paths))
	for _, p := range paths {
		content, ok := c.fetchRaw(ctx, owner, repo, sha, p)
		if !ok {
			// Any single file fetch failure degrades the whole result.
			return FixResult{}, nil
		}
		files = append(files, symbolextract.FileContent{Path: p, Content: content})
	}

	fix := &Fix{Patch: patch, Files: files}
	c.saveCache(owner, repo, sha, fix)
	return FixResult{Fix: fix}, nil
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
// changed files whose extension is in the supplied extensions set.  The git
// "a/"/"b/" prefixes are stripped so paths match the symbol extractor's
// contract.  If extensions is nil or empty, the function falls back to
// JSExtensions.
func parseSourcePaths(patch string, extensions map[string]bool) []string {
	if len(extensions) == 0 {
		extensions = JSExtensions
	}
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
		if !extensions[ext] {
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
