package advisory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SourceGitLab is the source attribution tag for the GitLab Advisory Database
// (gemnasium-db). By default it mirrors the MIT-licensed community fork
// gitlab-org/advisories-community, which is time-delayed (~30 days) relative to
// the primary gemnasium-db but carries no GitLab usage restrictions and is
// therefore the correct default for this AGPL tool.
const SourceGitLab = "gitlab"

// gitlabDefaultBaseURL is the root of gitlab.com. The archive and project-API
// URLs are built from it; it is overridable via WithGitLabBaseURL for hermetic
// tests and to let advanced users point at the primary gemnasium-db host.
const gitlabDefaultBaseURL = "https://gitlab.com"

// gitlabProjectPath is the project path of the default community mirror, used to
// build the archive URL. gitlabProjectName is its bare name (the GitLab archive
// wraps its contents in "<name>-<ref>/"). gitlabProjectEncoded is the
// URL-encoded project path for the project API endpoint.
const (
	gitlabProjectPath    = "gitlab-org/advisories-community"
	gitlabProjectName    = "advisories-community"
	gitlabProjectEncoded = "gitlab-org%2Fadvisories-community"
)

// gitlabDefaultFreshness is how long an extracted cache is considered current.
// A Refresh within this window of the last successful one skips the download —
// the source is one large archive shared across every ecosystem, so re-fetching
// per scan would be wasteful. Overridable for tests via the freshness field.
const gitlabDefaultFreshness = 24 * time.Hour

// ─── Functional options ─────────────────────────────────────────────────────

// gitlabOption is a functional option for NewGitLabSource.
type gitlabOption func(*GitLabSource)

// WithGitLabBaseURL overrides the gitlab.com base URL used to build the archive
// and project-API requests (used by tests and to retarget the primary
// gemnasium-db host).
func WithGitLabBaseURL(u string) gitlabOption {
	return func(s *GitLabSource) { s.BaseURL = strings.TrimRight(u, "/") }
}

// WithGitLabHTTPClient overrides the HTTP client used for downloads.
func WithGitLabHTTPClient(c *http.Client) gitlabOption {
	return func(s *GitLabSource) { s.HTTP = c }
}

// ─── GitLabSource ───────────────────────────────────────────────────────────

// GitLabSource implements Source against the GitLab Advisory Database
// (gemnasium-db) offline-bundle model. Unlike OSVBundleSource it downloads ONE
// archive covering every ecosystem, safe-extracts the per-package YAML records
// preserving the "<package_type>/<package_slug>/<id>.yml" layout under cacheDir,
// and queries them fully offline. The manifest is written last so a crash
// mid-extraction leaves no valid manifest, forcing a re-fetch.
//
// Failure semantics ("unknown ≠ safe"): a missing cache directory mirrors the
// other bundle sources — Query returns no advisories (the "not yet refreshed"
// state), and the wiring layer marks the scan incomplete when the source was
// explicitly requested but uncached. An advisory whose affected_range cannot be
// parsed into a comparable range is NEVER dropped: it is returned with
// UndecidableRanges=true so AffectsVersionV reports Undecidable and the host
// emits a synthetic UNKNOWN finding.
//
// Thread safety: Query is safe to call from multiple goroutines (read-only file
// reads after extraction). Refresh serialises via a cross-process directory lock.
type GitLabSource struct {
	// BaseURL is the gitlab.com root (no trailing slash). Defaults to
	// gitlabDefaultBaseURL.
	BaseURL string
	// HTTP is the client used for archive/API downloads. Defaults to a 30-second
	// client; inject a longer-timeout client via WithGitLabHTTPClient for slow
	// links or very large archives.
	HTTP *http.Client
	// ForceUpdate, when true, forces Refresh to re-download even when the cache is
	// still fresh.
	ForceUpdate bool

	// cacheDir is the root under which "<package_type>/<package_slug>/" trees and
	// the manifest are written. Never mutated after construction.
	cacheDir string

	// freshness is the staleness window for skipping a re-download. Defaults to
	// gitlabDefaultFreshness; tests may shorten it.
	freshness time.Duration

	// maxTotalExtracted and maxExtractEntries are the aggregate tar-bomb caps,
	// defaulting to maxTotalExtractedBytes and maxEntries (shared with the OSV zip
	// extractor); tests may inject small values.
	maxTotalExtracted int64
	maxExtractEntries int64
}

// NewGitLabSource returns a GitLabSource caching the extracted archive under
// cacheDir. Apply functional options to override the base URL or HTTP client.
func NewGitLabSource(cacheDir string, opts ...gitlabOption) *GitLabSource {
	s := &GitLabSource{
		BaseURL:           gitlabDefaultBaseURL,
		HTTP:              &http.Client{Timeout: 30 * time.Second},
		cacheDir:          cacheDir,
		freshness:         gitlabDefaultFreshness,
		maxTotalExtracted: maxTotalExtractedBytes,
		maxExtractEntries: maxEntries,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ─── Refresh ────────────────────────────────────────────────────────────────

// Refresh ensures the local cache is populated and current. It downloads the
// whole gemnasium-db archive once, safe-extracts the YAML records, and writes the
// manifest last. It is idempotent: a Refresh within the freshness window of the
// last successful one (and ForceUpdate=false) skips the download entirely, so
// calling it from each ecosystem block still fetches at most once per scan.
//
// Failure semantics: any branch-resolution, download, or extraction failure is a
// hard error and the manifest is NOT written, so the next Refresh re-fetches.
func (s *GitLabSource) Refresh(ctx context.Context) error {
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		return fmt.Errorf("advisory: gitlab: create cache dir %q: %w", s.cacheDir, err)
	}

	unlock, err := lockDir(s.cacheDir)
	if err != nil {
		return fmt.Errorf("advisory: gitlab: lock cache dir %q: %w", s.cacheDir, err)
	}
	defer unlock()

	if !s.ForceUpdate && s.cacheFresh() {
		return nil
	}

	data, err := s.downloadArchive(ctx)
	if err != nil {
		return err
	}

	if err := safeExtractTarGz(data, s.cacheDir, s.maxTotalExtracted, s.maxExtractEntries); err != nil {
		return fmt.Errorf("advisory: gitlab: extract archive: %w", err)
	}

	version := time.Now().UTC().Format(time.RFC3339)
	if err := writeManifestToDir(s.cacheDir, version); err != nil {
		return fmt.Errorf("advisory: gitlab: write manifest: %w", err)
	}
	return nil
}

// cacheFresh reports whether the extracted cache has a manifest whose build
// timestamp is within the freshness window.
func (s *GitLabSource) cacheFresh() bool {
	data, err := os.ReadFile(filepath.Join(s.cacheDir, ManifestFilename))
	if err != nil {
		return false
	}
	var m SnapshotManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	if m.BuildTimestamp.IsZero() {
		return false
	}
	return time.Since(m.BuildTimestamp) < s.freshness
}

// downloadArchive resolves the default branch and downloads the archive,
// attempting the API default branch first, then "main", then "master".
func (s *GitLabSource) downloadArchive(ctx context.Context) ([]byte, error) {
	var lastErr error
	for _, br := range s.candidateBranches(ctx) {
		data, err := s.fetchArchive(ctx, br)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no branch candidates")
	}
	return nil, fmt.Errorf("advisory: gitlab: download archive: %w", lastErr)
}

// candidateBranches returns the ordered, de-duplicated list of branch names to
// try: the project-API default branch (when resolvable), then "main", "master".
func (s *GitLabSource) candidateBranches(ctx context.Context) []string {
	out := make([]string, 0, 3)
	add := func(b string) {
		if b == "" {
			return
		}
		for _, e := range out {
			if e == b {
				return
			}
		}
		out = append(out, b)
	}
	add(s.apiDefaultBranch(ctx))
	add("main")
	add("master")
	return out
}

// apiDefaultBranch queries the GitLab project API for the repository's default
// branch. Any error returns "" so the caller falls back to main/master.
func (s *GitLabSource) apiDefaultBranch(ctx context.Context) string {
	u := s.BaseURL + "/api/v4/projects/" + gitlabProjectEncoded
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var meta struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return ""
	}
	return strings.TrimSpace(meta.DefaultBranch)
}

// fetchArchive downloads the tar.gz archive for branch. A non-200 status is a
// hard error so the caller can try the next branch candidate.
func (s *GitLabSource) fetchArchive(ctx context.Context, branch string) ([]byte, error) {
	u := fmt.Sprintf("%s/%s/-/archive/%s/%s-%s.tar.gz",
		s.BaseURL, gitlabProjectPath, branch, gitlabProjectName, branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", u, err)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", u, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ─── Tar.gz safe-extraction ─────────────────────────────────────────────────

// safeExtractTarGz extracts the YAML advisory files from a gemnasium-db archive
// into destDir, preserving the "<package_type>/<package_slug>/<id>.yml" layout
// (the GitLab archive's "<project>-<ref>/" root wrapper is stripped).
//
// Safety invariants (tar-bomb + path-traversal guards):
//   - Only regular *.yml / *.yaml entries are extracted; directories, symlinks,
//     and other entries are skipped.
//   - Entries that resolve outside destDir ("..", absolute) are a hard error.
//   - Per-file uncompressed size > maxPerFileBytes is a hard error.
//   - Total uncompressed bytes > maxTotal is a hard error.
//   - The accepted-entry count > maxEntriesLimit is a hard error.
func safeExtractTarGz(data []byte, destDir string, maxTotal, maxEntriesLimit int64) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var total, count int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		name := stripFirstPathComponent(hdr.Name)
		if name == "" {
			continue
		}
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		if filepath.IsAbs(name) {
			return fmt.Errorf("path safety violation: absolute path in tar entry %q", hdr.Name)
		}
		cleaned := filepath.Clean(filepath.FromSlash(name))
		if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("path safety violation: traversal in tar entry %q", hdr.Name)
		}

		count++
		if count > maxEntriesLimit {
			return fmt.Errorf("tar-bomb guard: entry count exceeds %d limit", maxEntriesLimit)
		}
		if hdr.Size > maxPerFileBytes {
			return fmt.Errorf("tar-bomb guard: entry %q uncompressed size %d exceeds %d byte limit",
				hdr.Name, hdr.Size, maxPerFileBytes)
		}

		fileData, err := io.ReadAll(io.LimitReader(tr, maxPerFileBytes+1))
		if err != nil {
			return fmt.Errorf("read tar entry %q: %w", hdr.Name, err)
		}
		if int64(len(fileData)) > maxPerFileBytes {
			return fmt.Errorf("tar-bomb guard: entry %q content exceeds %d byte per-file limit",
				hdr.Name, maxPerFileBytes)
		}
		total += int64(len(fileData))
		if total > maxTotal {
			return fmt.Errorf("tar-bomb guard: total extracted size exceeds %d byte limit", maxTotal)
		}

		dest := filepath.Join(destDir, cleaned)
		rel, err := filepath.Rel(destDir, dest)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("path safety violation: entry %q escapes destination", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("create dir for %q: %w", hdr.Name, err)
		}
		if err := atomicWrite(dest, fileData, false); err != nil {
			return fmt.Errorf("write entry %q: %w", hdr.Name, err)
		}
	}

	if err := syncDir(destDir); err != nil {
		return err
	}
	return nil
}

// stripFirstPathComponent removes the leading path segment of a slash-separated
// archive path (the GitLab "<project>-<ref>/" wrapper). A path with no separator
// is a top-level file with no package-type directory and is dropped (returns "").
func stripFirstPathComponent(p string) string {
	p = strings.TrimPrefix(p, "./")
	i := strings.Index(p, "/")
	if i < 0 {
		return ""
	}
	return p[i+1:]
}

// ─── Query ──────────────────────────────────────────────────────────────────

// Query returns advisories from the extracted cache for pkg at version. The
// package's advisory directory is "<cacheDir>/<package_type>/<package_slug>/";
// every *.yml / *.yaml file in it is parsed and version-matched via the
// per-ecosystem comparator (adv.AffectsVersionV). Affected advisories are
// returned; undecidable ones are returned with Incomplete=true (UNKNOWN, never
// dropped); only provably not-affected advisories are dropped.
//
// An ecosystem gemnasium does not serve, or a missing cache directory (not yet
// refreshed / no advisories for the package), returns (nil, nil) — never an error.
func (s *GitLabSource) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	ptype, ok := toGitLabPackageType(pkg.Ecosystem)
	if !ok {
		// Ecosystem not served by gemnasium — out of scope, never a silent clean.
		return nil, nil
	}

	dir := filepath.Join(s.cacheDir, ptype, filepath.FromSlash(gitlabSlugPath(pkg.Ecosystem, pkg.Name)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Missing dir = cache not refreshed or no advisories for this package.
		return nil, nil
	}

	queryVersion := canonical(version)
	var results []Advisory
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if entry.IsDir() {
			continue
		}
		nm := entry.Name()
		if !strings.HasSuffix(nm, ".yml") && !strings.HasSuffix(nm, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, nm))
		if err != nil {
			continue
		}
		adv, ok := parseGitLabAdvisory(data, pkg)
		if !ok {
			continue
		}
		switch adv.AffectsVersionV(queryVersion) {
		case VersionAffected:
			results = append(results, adv)
		case VersionUndecidable:
			// Cannot decide — forward as UNKNOWN with Incomplete=true rather than
			// dropping it (unknown ≠ safe).
			adv.Incomplete = true
			results = append(results, adv)
			// VersionNotAffected: drop — the only safe drop.
		}
	}

	sort.SliceStable(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

// ─── YAML parsing ───────────────────────────────────────────────────────────

// gitlabAdvisoryYAML mirrors the gemnasium-db per-advisory YAML schema.
type gitlabAdvisoryYAML struct {
	Identifier       string   `yaml:"identifier"`
	Identifiers      []string `yaml:"identifiers"`
	PackageSlug      string   `yaml:"package_slug"`
	Title            string   `yaml:"title"`
	Description      string   `yaml:"description"`
	AffectedRange    string   `yaml:"affected_range"`
	AffectedVersions string   `yaml:"affected_versions"`
	FixedVersions    []string `yaml:"fixed_versions"`
	CWEIDs           []string `yaml:"cwe_ids"`
	CVSSv2           string   `yaml:"cvss_v2"`
	CVSSv3           string   `yaml:"cvss_v3"`
	CVSSv4           string   `yaml:"cvss_v4"`
	URLs             []string `yaml:"urls"`
	UUID             string   `yaml:"uuid"`
	PubDate          string   `yaml:"pubdate"`
	Date             string   `yaml:"date"`
}

// parseGitLabAdvisory parses one gemnasium YAML record into an Advisory for pkg.
// ID is the first CVE identifier when present, else the first identifier, else the
// uuid; the remaining identifiers become aliases. CVSS vectors are parsed
// losslessly via ParseCVSS (v3/v4; v2 is not scored by this engine and is
// skipped). An affected_range that cannot be parsed sets UndecidableRanges=true so
// the record is forwarded as UNKNOWN rather than dropped.
func parseGitLabAdvisory(data []byte, pkg Package) (Advisory, bool) {
	var y gitlabAdvisoryYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return Advisory{}, false
	}

	ids := gatherGitLabIdentifiers(y)
	if len(ids) == 0 {
		if strings.TrimSpace(y.UUID) == "" {
			return Advisory{}, false
		}
		ids = []string{strings.TrimSpace(y.UUID)}
	}
	id, aliases := chooseGitLabID(ids)

	adv := Advisory{
		ID:        id,
		Ecosystem: pkg.Ecosystem,
		Module:    pkg.Name,
		Aliases:   aliases,
		Sources:   []string{SourceGitLab},
		CWEs:      normalizeCWEs(y.CWEIDs),
	}

	var metrics []CVSSMetric
	for _, vec := range []string{y.CVSSv3, y.CVSSv4} {
		vec = strings.TrimSpace(vec)
		if vec == "" {
			continue
		}
		if m, err := ParseCVSS(vec); err == nil {
			m.Source = SourceGitLab
			metrics = append(metrics, m)
		}
	}
	if len(metrics) > 0 {
		adv.CVSS = metrics
		adv.Severity = severityFromMetrics(metrics, 0, "")
	}

	if ranges, ok := parseGitLabRange(y.AffectedRange, y.FixedVersions); ok {
		adv.VersionRanges = ranges
	} else {
		// Parse failure must never silently drop or clear the advisory: mark it
		// undecidable so AffectsVersionV returns Undecidable (forwarded UNKNOWN).
		adv.UndecidableRanges = true
	}

	return adv, true
}

// gatherGitLabIdentifiers unions the identifiers[] array with the deprecated
// single identifier field, dropping empties and preserving first-seen order.
func gatherGitLabIdentifiers(y gitlabAdvisoryYAML) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range y.Identifiers {
		add(v)
	}
	add(y.Identifier)
	return out
}

// chooseGitLabID picks the canonical ID (first CVE-* if any, else the first
// identifier) and returns the remaining identifiers as aliases (order preserved).
func chooseGitLabID(ids []string) (string, []string) {
	idx := 0
	for i, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			idx = i
			break
		}
	}
	chosen := ids[idx]
	var aliases []string
	for i, id := range ids {
		if i == idx {
			continue
		}
		aliases = append(aliases, id)
	}
	return chosen, aliases
}

// ─── affected_range parser ──────────────────────────────────────────────────

// parseGitLabRange parses a gemnasium affected_range string into VersionRanges.
//
// Supported syntax:
//   - comparators >=, >, <, <=, =, ==
//   - space- or comma-separated AND combination (">=1.0.0 <1.2.3")
//   - "||" OR combination → multiple VersionRanges
//   - Maven/NuGet interval notation ([1.0,2.0), (,1.2], [1.0,], [1.0])
//   - node-semver/cargo caret (^1.2.3) and tilde (~1.2.3) with 0.x rules
//   - a bare exact version (1.2.3) → {Introduced, LastAffected} at that version
//   - "*" → all versions (open range)
//
// Soundness: an exclusive lower bound (">X", or a "(" interval open) cannot be
// represented exactly by VersionRange, so it is widened to an inclusive lower
// bound (Introduced=X). This over-includes the single boundary version — a false
// positive, never a false negative.
//
// fixedVersions[] is used as a corroborating upper bound only when the parse
// produces a single range that has no upper bound and exactly one fixed version
// is recorded (so an otherwise open ">=X" range is bounded by the curated fix).
//
// Returns (nil, false) when the string cannot be parsed into comparable ranges;
// the caller then marks the advisory undecidable (UNKNOWN), never not-affected.
func parseGitLabRange(raw string, fixedVersions []string) ([]VersionRange, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, false
	}

	// Maven/NuGet interval notation.
	if strings.ContainsAny(s, "[(") {
		return parseBracketRanges(s)
	}

	var ranges []VersionRange
	for _, clause := range strings.Split(s, "||") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		vr, ok := parseAndClause(clause)
		if !ok {
			return nil, false
		}
		ranges = append(ranges, vr)
	}
	if len(ranges) == 0 {
		return nil, false
	}

	if len(ranges) == 1 {
		ranges[0] = applyFixedVersionBound(ranges[0], fixedVersions)
	}
	return ranges, true
}

// parseAndClause parses a single AND-combined clause (no "||") into one
// VersionRange. Tokens are split on whitespace and commas.
func parseAndClause(clause string) (VersionRange, bool) {
	tokens := tokenizeConstraints(clause)
	if len(tokens) == 0 {
		return VersionRange{}, false
	}
	var vr VersionRange
	for _, tok := range tokens {
		if !applyConstraintToken(tok, &vr) {
			return VersionRange{}, false
		}
	}
	return vr, true
}

// tokenizeConstraints splits a clause on whitespace and commas, dropping empties.
func tokenizeConstraints(clause string) []string {
	return strings.FieldsFunc(clause, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ','
	})
}

// applyConstraintToken applies a single constraint token to vr. Returns false for
// any token it cannot represent (the whole clause is then undecidable).
func applyConstraintToken(tok string, vr *VersionRange) bool {
	switch {
	case tok == "*" || tok == "x" || tok == "X":
		// Any version — leaves the range open.
		return true
	case strings.HasPrefix(tok, ">="):
		v := strings.TrimSpace(tok[2:])
		if v == "" {
			return false
		}
		vr.Introduced = v
		return true
	case strings.HasPrefix(tok, "<="):
		v := strings.TrimSpace(tok[2:])
		if v == "" {
			return false
		}
		vr.LastAffected = v
		return true
	case strings.HasPrefix(tok, "=="):
		v := strings.TrimSpace(tok[2:])
		if v == "" {
			return false
		}
		vr.Introduced = v
		vr.LastAffected = v
		return true
	case strings.HasPrefix(tok, ">"):
		// Exclusive lower bound — widen to inclusive (conservative over-inclusion).
		v := strings.TrimSpace(tok[1:])
		if v == "" {
			return false
		}
		vr.Introduced = v
		return true
	case strings.HasPrefix(tok, "<"):
		v := strings.TrimSpace(tok[1:])
		if v == "" {
			return false
		}
		vr.Fixed = v
		return true
	case strings.HasPrefix(tok, "="):
		v := strings.TrimSpace(tok[1:])
		if v == "" {
			return false
		}
		vr.Introduced = v
		vr.LastAffected = v
		return true
	case strings.HasPrefix(tok, "^"):
		return applyCaret(strings.TrimSpace(tok[1:]), vr)
	case strings.HasPrefix(tok, "~"):
		return applyTilde(strings.TrimSpace(tok[1:]), vr)
	case isVersionStart(tok):
		// Bare exact version.
		vr.Introduced = tok
		vr.LastAffected = tok
		return true
	default:
		return false
	}
}

// applyCaret expands a caret constraint (^X) into [X, upper) honoring npm 0.x
// rules, setting both bounds on vr.
func applyCaret(v string, vr *VersionRange) bool {
	maj, min, pat, n, ok := parseVersionCore(v)
	if !ok {
		return false
	}
	var upper string
	switch {
	case maj > 0:
		upper = fmt.Sprintf("%d.0.0", maj+1)
	case min > 0:
		upper = fmt.Sprintf("0.%d.0", min+1)
	case n >= 3:
		upper = fmt.Sprintf("0.0.%d", pat+1)
	case n == 2:
		upper = "0.1.0"
	default:
		upper = "1.0.0"
	}
	vr.Introduced = v
	vr.Fixed = upper
	return true
}

// applyTilde expands a tilde constraint (~X) into [X, upper), setting both bounds
// on vr. ~1.2.3 and ~1.2 → <1.3.0; ~1 → <2.0.0.
func applyTilde(v string, vr *VersionRange) bool {
	maj, min, _, n, ok := parseVersionCore(v)
	if !ok {
		return false
	}
	var upper string
	if n >= 2 {
		upper = fmt.Sprintf("%d.%d.0", maj, min+1)
	} else {
		upper = fmt.Sprintf("%d.0.0", maj+1)
	}
	vr.Introduced = v
	vr.Fixed = upper
	return true
}

// parseVersionCore extracts up to three leading numeric components (major, minor,
// patch) from v, ignoring a leading 'v' and any pre-release/build suffix. n is the
// number of numeric components actually present (1–3). ok is false when v has no
// leading numeric component or a component is non-numeric.
func parseVersionCore(v string) (maj, min, pat, n int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return 0, 0, 0, 0, false
	}
	parts := strings.Split(v, ".")
	vals := []int{0, 0, 0}
	for i, p := range parts {
		if i >= 3 {
			break
		}
		num, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return 0, 0, 0, 0, false
		}
		vals[i] = num
	}
	cnt := len(parts)
	if cnt > 3 {
		cnt = 3
	}
	return vals[0], vals[1], vals[2], cnt, true
}

// isVersionStart reports whether tok begins a bare version (a digit, or 'v'
// followed by a digit).
func isVersionStart(tok string) bool {
	if tok == "" {
		return false
	}
	if tok[0] >= '0' && tok[0] <= '9' {
		return true
	}
	return tok[0] == 'v' && len(tok) > 1 && tok[1] >= '0' && tok[1] <= '9'
}

// parseBracketRanges parses Maven/NuGet interval notation, which may contain
// several comma-separated intervals at the top level (commas inside an interval
// separate the bounds). It scans bracket groups so the two comma uses do not
// collide.
func parseBracketRanges(s string) ([]VersionRange, bool) {
	var ranges []VersionRange
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ',' || s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		open := s[i]
		if open != '[' && open != '(' {
			return nil, false
		}
		j := i + 1
		for j < len(s) && s[j] != ']' && s[j] != ')' {
			j++
		}
		if j >= len(s) {
			return nil, false // unbalanced
		}
		vr, ok := parseInterval(open, s[j], s[i+1:j])
		if !ok {
			return nil, false
		}
		ranges = append(ranges, vr)
		i = j + 1
	}
	if len(ranges) == 0 {
		return nil, false
	}
	return ranges, true
}

// parseInterval parses one interval's inner text into a VersionRange. A '(' open
// bound is exclusive but is widened to inclusive (Introduced) — conservative
// over-inclusion of the boundary, never a false negative.
func parseInterval(open, closeCh byte, inner string) (VersionRange, bool) {
	parts := strings.SplitN(inner, ",", 2)
	var vr VersionRange
	if len(parts) == 1 {
		// Single value, e.g. "[1.0]" — exact version.
		v := strings.TrimSpace(parts[0])
		if v == "" {
			return VersionRange{}, false
		}
		vr.Introduced = v
		vr.LastAffected = v
		return vr, true
	}
	lo := strings.TrimSpace(parts[0])
	hi := strings.TrimSpace(parts[1])
	if lo != "" {
		vr.Introduced = lo
	}
	if hi != "" {
		if closeCh == ']' {
			vr.LastAffected = hi // inclusive upper
		} else {
			vr.Fixed = hi // exclusive upper
		}
	}
	_ = open
	return vr, true
}

// applyFixedVersionBound bounds an otherwise open range with the curated fix
// version when exactly one is recorded. It never widens or replaces an existing
// upper bound.
func applyFixedVersionBound(vr VersionRange, fixed []string) VersionRange {
	if vr.Fixed != "" || vr.LastAffected != "" {
		return vr
	}
	var nonEmpty []string
	for _, f := range fixed {
		if f = strings.TrimSpace(f); f != "" {
			nonEmpty = append(nonEmpty, f)
		}
	}
	if len(nonEmpty) != 1 {
		return vr
	}
	vr.Fixed = nonEmpty[0]
	return vr
}

// ─── Ecosystem & slug mapping ───────────────────────────────────────────────

// gitlabPackageType maps commit0-analyzer ecosystem constants to gemnasium package_type
// directory names. Ecosystems gemnasium does not serve (Hex, SwiftURL, conan)
// are absent, so toGitLabPackageType reports ok=false for them.
var gitlabPackageType = map[string]string{
	EcosystemNPM:       "npm",
	EcosystemMaven:     "maven",
	EcosystemPyPI:      "pypi",
	EcosystemGo:        "go",
	EcosystemNuGet:     "nuget",
	EcosystemPackagist: "packagist",
	EcosystemRubyGems:  "gem",
	EcosystemCratesIO:  "cargo",
	EcosystemPub:       "pub",
}

// toGitLabPackageType maps a commit0-analyzer ecosystem to its gemnasium package_type. The
// second return is false when gemnasium does not serve the ecosystem.
func toGitLabPackageType(ecosystem string) (string, bool) {
	t, ok := gitlabPackageType[ecosystem]
	return t, ok
}

// gitlabSlugPath builds the package_slug path component (after the package_type)
// for pkg. Maven group:artifact becomes group/artifact; PyPI names are
// PEP503-normalized; every other ecosystem uses the name verbatim (scoped npm
// names, Packagist vendor/package, and Go module paths already carry their
// slashes).
func gitlabSlugPath(ecosystem, name string) string {
	switch ecosystem {
	case EcosystemMaven:
		return strings.ReplaceAll(name, ":", "/")
	case EcosystemPyPI:
		return pep503Normalize(name)
	default:
		return name
	}
}

// pep503Normalize applies PEP 503 normalization: lowercase, with runs of
// "-", "_", or "." collapsed to a single "-". This matches the gemnasium pypi
// directory naming.
func pep503Normalize(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}
