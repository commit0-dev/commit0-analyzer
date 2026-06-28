package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SourceNVD is the source-attribution tag for the NVD CVE-keyed enrichment role.
// It marks CVSS metrics and SourceContributions that NVD supplied by joining an
// advisory's existing CVE alias. This role adds no new package→advisory edges, so
// it is structurally FP-safe.
const SourceNVD = "nvd"

// SourceNVDCPE is the source-attribution tag for the opt-in, lower-confidence
// CPE-breadth role. Advisories carrying this tag were matched heuristically by
// CPE product, are never symbol-level, and are gated off by default downstream:
// the wiring layer maps this tag to properties["match"]="cpe-heuristic".
const SourceNVDCPE = "nvd-cpe"

// NVD API 2.0 rate-limit budgets: 5 requests / 30s anonymous, 50 / 30s with a
// key. We translate those into a conservative minimum inter-request interval.
const (
	nvdAnonInterval   = 6 * time.Second        // 30s / 5
	nvdKeyedInterval  = 600 * time.Millisecond // 30s / 50
	nvdBackoffBase    = 6 * time.Second
	nvdDefaultRetries = 5
	nvdHTTPTimeout    = 60 * time.Second
)

// nvdFeedFile is the merged-feed cache filename written by a successful refresh
// and read as the offline floor. The mirror fixture uses the same name.
const nvdFeedFile = "nvd-cve-feed.json"

// nvdETagFile stores the last-seen feed ETag for conditional GETs. It is not a
// *.json file so loadCachedIndex's glob never mistakes it for a feed slice.
const nvdETagFile = "nvd-feed.etag"

// errNVDNotModified is the sentinel returned by refresh when the server answers
// 304 Not Modified: the cached floor is current and should be loaded as-is.
var errNVDNotModified = errors.New("advisory: nvd feed not modified")

// cveIDPattern matches a canonical CVE identifier (CVE-YYYY-NNNN..).
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ─── shared feed client (offline floor + hybrid API refresh) ─────────────────

// nvdFeedClient loads and refreshes the NVD CVE feed index shared by both the
// enricher (CVE-join role) and the CPE source (breadth role). The index is built
// at most once per client via sync.Once so a multi-package scan reuses it.
type nvdFeedClient struct {
	cacheDir   string
	baseURL    string
	http       *http.Client
	apiKey     string
	now        func() time.Time
	sleep      func(time.Duration)
	maxRetries int

	mu      sync.Mutex
	lastReq time.Time

	once   sync.Once
	idx    map[string]*nvdRecord
	idxErr error
}

// minInterval returns the per-request throttle floor for the configured key.
func (c *nvdFeedClient) minInterval() time.Duration {
	if c.apiKey != "" {
		return nvdKeyedInterval
	}
	return nvdAnonInterval
}

// index returns the CVE→record map, building it once. The returned error is the
// hybrid-degrade signal: a non-nil error with a non-nil map means "cached floor
// usable but freshness unconfirmed" (incomplete); a non-nil error with a nil map
// means "no usable data" (incomplete, nothing applied).
func (c *nvdFeedClient) index(ctx context.Context) (map[string]*nvdRecord, error) {
	c.once.Do(func() {
		c.idx, c.idxErr = c.buildIndex(ctx)
	})
	return c.idx, c.idxErr
}

func (c *nvdFeedClient) buildIndex(ctx context.Context) (map[string]*nvdRecord, error) {
	var refreshErr error
	if c.baseURL != "" {
		if err := c.refresh(ctx); err != nil && !errors.Is(err, errNVDNotModified) {
			refreshErr = err
		}
	}

	idx, loadErr := c.loadCachedIndex()
	if loadErr != nil {
		switch {
		case refreshErr != nil:
			return nil, fmt.Errorf("advisory: nvd feed unavailable (refresh: %v; cache: %v)", refreshErr, loadErr)
		case c.baseURL == "":
			return nil, fmt.Errorf("advisory: nvd offline and no cached feed: %w", loadErr)
		default:
			return nil, loadErr
		}
	}

	// Cache loaded. If the live refresh failed, degrade: serve the cached floor
	// but report incomplete so freshness uncertainty is never silently hidden.
	return idx, refreshErr
}

// loadCachedIndex parses every *.json feed slice in cacheDir into the CVE index.
func (c *nvdFeedClient) loadCachedIndex() (map[string]*nvdRecord, error) {
	files, err := filepath.Glob(filepath.Join(c.cacheDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("advisory: nvd glob cache %q: %w", c.cacheDir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("advisory: nvd no cached feed in %q", c.cacheDir)
	}

	sort.Strings(files) // deterministic merge order
	idx := make(map[string]*nvdRecord)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("advisory: nvd read feed %q: %w", f, err)
		}
		var resp nvdAPIResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("advisory: nvd decode feed %q: %w", f, err)
		}
		for _, v := range resp.Vulnerabilities {
			rec := toNVDRecord(v)
			if rec.ID == "" {
				continue
			}
			idx[rec.ID] = rec
		}
	}
	return idx, nil
}

// refresh fetches the feed from the API 2.0 endpoint (paginated, throttled,
// conditional) and writes the merged result to the cache. A 304 returns
// errNVDNotModified so the caller loads the existing cache unchanged.
func (c *nvdFeedClient) refresh(ctx context.Context) error {
	storedETag := c.readETag()

	var (
		merged  []json.RawMessage
		newETag string
		start   int
	)
	for {
		condETag := ""
		if start == 0 {
			condETag = storedETag
		}
		body, status, respETag, err := c.doGet(ctx, start, condETag)
		if err != nil {
			return err
		}
		if status == http.StatusNotModified {
			return errNVDNotModified
		}

		var page nvdAPIResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("advisory: nvd decode page (startIndex=%d): %w", start, err)
		}
		merged = append(merged, page.Vulnerabilities...)
		if start == 0 {
			newETag = respETag
		}

		if page.ResultsPerPage <= 0 || len(page.Vulnerabilities) == 0 {
			break
		}
		start += page.ResultsPerPage
		if page.TotalResults > 0 && start >= page.TotalResults {
			break
		}
	}

	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return fmt.Errorf("advisory: nvd create cache dir %q: %w", c.cacheDir, err)
	}
	out, err := json.Marshal(nvdAPIResponse{Vulnerabilities: merged})
	if err != nil {
		return fmt.Errorf("advisory: nvd marshal feed: %w", err)
	}
	if err := atomicWrite(filepath.Join(c.cacheDir, nvdFeedFile), out, true); err != nil {
		return fmt.Errorf("advisory: nvd write feed: %w", err)
	}
	if newETag != "" {
		if err := atomicWrite(filepath.Join(c.cacheDir, nvdETagFile), []byte(newETag), false); err != nil {
			return fmt.Errorf("advisory: nvd write etag: %w", err)
		}
	}
	return nil
}

// readETag returns the stored feed ETag, or "" when none is cached.
func (c *nvdFeedClient) readETag() string {
	data, err := os.ReadFile(filepath.Join(c.cacheDir, nvdETagFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// doGet issues one throttled, retrying GET for the given page. It honours the
// rate-limit budget (throttle before each attempt), retries 429/403/503 with
// exponential backoff, sends a conditional If-None-Match when condETag is set,
// and returns the body, status code, and response ETag.
func (c *nvdFeedClient) doGet(ctx context.Context, startIndex int, condETag string) (body []byte, status int, etag string, err error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		c.throttle()

		b, s, e, reqErr := c.rawGet(ctx, startIndex, condETag)
		if reqErr != nil {
			lastErr = reqErr
			if attempt < c.maxRetries {
				c.sleep(c.backoff(attempt))
				continue
			}
			break
		}

		switch s {
		case http.StatusOK, http.StatusNotModified:
			return b, s, e, nil
		case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
			lastErr = fmt.Errorf("advisory: nvd GET startIndex=%d: rate-limited status %d", startIndex, s)
			if attempt < c.maxRetries {
				c.sleep(c.backoff(attempt))
				continue
			}
		default:
			return nil, 0, "", fmt.Errorf("advisory: nvd GET startIndex=%d: unexpected status %d", startIndex, s)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("advisory: nvd GET startIndex=%d: retries exhausted", startIndex)
	}
	return nil, 0, "", lastErr
}

// throttle blocks until at least minInterval has elapsed since the last request,
// using the injected clock so tests are deterministic and instant.
func (c *nvdFeedClient) throttle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastReq.IsZero() {
		if wait := c.minInterval() - c.now().Sub(c.lastReq); wait > 0 {
			c.sleep(wait)
		}
	}
	c.lastReq = c.now()
}

// backoff returns the exponential backoff for the given zero-based attempt.
func (c *nvdFeedClient) backoff(attempt int) time.Duration {
	return nvdBackoffBase << attempt
}

// rawGet performs a single HTTP GET with no retry/throttle logic.
func (c *nvdFeedClient) rawGet(ctx context.Context, startIndex int, condETag string) ([]byte, int, string, error) {
	url := c.baseURL
	if startIndex > 0 {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "startIndex=" + strconv.Itoa(startIndex)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, "", fmt.Errorf("advisory: nvd build request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	if condETag != "" {
		req.Header.Set("If-None-Match", condETag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("advisory: nvd GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return nil, resp.StatusCode, resp.Header.Get("ETag"), nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("advisory: nvd read body %s: %w", url, err)
	}
	return data, resp.StatusCode, resp.Header.Get("ETag"), nil
}

// ─── feed JSON shapes (NVD API 2.0) ──────────────────────────────────────────

type nvdAPIResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []json.RawMessage  `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string         `json:"id"`
	Metrics        nvdMetrics     `json:"metrics"`
	Weaknesses     []nvdWeakness  `json:"weaknesses"`
	References     []nvdReference `json:"references"`
	Configurations []nvdConfig    `json:"configurations"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
}

type nvdMetric struct {
	Type     string      `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string `json:"version"`
	VectorString string `json:"vectorString"`
}

type nvdWeakness struct {
	Description []nvdLangString `json:"description"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatchRaw `json:"cpeMatch"`
}

type nvdCPEMatchRaw struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// ─── normalized record ───────────────────────────────────────────────────────

// nvdRecord is the distilled, deterministic per-CVE view used by both roles.
type nvdRecord struct {
	ID         string
	CVSS       []CVSSMetric
	CWEs       []string
	References []string
	CPEMatches []nvdCPEMatchRaw
}

// toNVDRecord distils a raw CVE into the normalized record, parsing CVSS vectors
// (v4.0 → v3.1 → v3.0 precedence), deduping/sorting CWEs, and flattening the
// vulnerable CPE matches. Unparseable vectors are skipped rather than failing the
// whole record (a single bad vector must not drop the rest of the signal).
func toNVDRecord(raw json.RawMessage) *nvdRecord {
	var v nvdVulnerability
	if err := json.Unmarshal(raw, &v); err != nil {
		return &nvdRecord{}
	}
	cve := v.CVE

	rec := &nvdRecord{ID: cve.ID}

	for _, group := range [][]nvdMetric{cve.Metrics.V40, cve.Metrics.V31, cve.Metrics.V30} {
		for _, m := range group {
			metric, err := ParseCVSS(m.CVSSData.VectorString)
			if err != nil {
				continue
			}
			metric.Source = SourceNVD
			rec.CVSS = append(rec.CVSS, metric)
		}
	}

	cweSet := make(map[string]struct{})
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cweSet[d.Value] = struct{}{}
			}
		}
	}
	if len(cweSet) > 0 {
		rec.CWEs = make([]string, 0, len(cweSet))
		for cwe := range cweSet {
			rec.CWEs = append(rec.CWEs, cwe)
		}
		sort.Strings(rec.CWEs)
	}

	seenRef := make(map[string]struct{})
	for _, r := range cve.References {
		if r.URL == "" {
			continue
		}
		if _, dup := seenRef[r.URL]; dup {
			continue
		}
		seenRef[r.URL] = struct{}{}
		rec.References = append(rec.References, r.URL)
	}

	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				if cm.Vulnerable {
					rec.CPEMatches = append(rec.CPEMatches, cm)
				}
			}
		}
	}

	return rec
}

// ─── NVDEnricher: CVE-keyed enrichment (primary role) ────────────────────────

// NVDEnricher implements Enricher. It joins each advisory to NVD by its existing
// CVE alias and attaches the authoritative CVSS vector(s), CWE ids, and a source
// contribution. It creates no new findings, so it cannot introduce false
// positives. A requested-but-unavailable feed is incomplete, never silent clean.
type NVDEnricher struct {
	feed *nvdFeedClient
}

// NVDOption configures an NVDEnricher / NVDCPESource feed client.
type NVDOption func(*nvdFeedClient)

// WithNVDBaseURL sets the API 2.0 base URL (enables the live hybrid layer).
func WithNVDBaseURL(url string) NVDOption {
	return func(c *nvdFeedClient) { c.baseURL = strings.TrimRight(url, "/") }
}

// WithNVDHTTPClient overrides the HTTP client.
func WithNVDHTTPClient(h *http.Client) NVDOption {
	return func(c *nvdFeedClient) {
		if h != nil {
			c.http = h
		}
	}
}

// WithNVDAPIKey sets the NVD API key (raises the rate-limit budget).
func WithNVDAPIKey(key string) NVDOption {
	return func(c *nvdFeedClient) { c.apiKey = key }
}

// WithNVDClock injects the clock and sleep functions (for deterministic tests).
func WithNVDClock(now func() time.Time, sleep func(time.Duration)) NVDOption {
	return func(c *nvdFeedClient) {
		if now != nil {
			c.now = now
		}
		if sleep != nil {
			c.sleep = sleep
		}
	}
}

// WithNVDMaxRetries overrides the backoff retry budget.
func WithNVDMaxRetries(n int) NVDOption {
	return func(c *nvdFeedClient) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

func newNVDFeedClient(cacheDir string, opts ...NVDOption) *nvdFeedClient {
	c := &nvdFeedClient{
		cacheDir:   cacheDir,
		http:       &http.Client{Timeout: nvdHTTPTimeout},
		now:        time.Now,
		sleep:      time.Sleep,
		maxRetries: nvdDefaultRetries,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewNVDEnricher returns an NVDEnricher backed by the feed cached under cacheDir.
// With no WithNVDBaseURL it operates purely offline against the cached floor.
func NewNVDEnricher(cacheDir string, opts ...NVDOption) *NVDEnricher {
	return &NVDEnricher{feed: newNVDFeedClient(cacheDir, opts...)}
}

// Name implements Enricher.
func (e *NVDEnricher) Name() string { return SourceNVD }

// Enrich implements Enricher: join by CVE alias and attach NVD signal.
//
// Failure semantics: if no advisory carries a CVE alias there is nothing to
// fetch and Enrich returns nil. Otherwise the feed is required; an unavailable
// feed returns a non-nil error (incomplete). When the live refresh fails but a
// cached floor exists, the cached enrichment is applied AND an error is returned
// (degrade + incomplete) — coverage is preserved without hiding the uncertainty.
func (e *NVDEnricher) Enrich(ctx context.Context, advs []Advisory) error {
	if !anyHasCVE(advs) {
		return nil
	}

	idx, ferr := e.feed.index(ctx)
	if idx != nil {
		applyNVDEnrichment(advs, idx, e.feed.now)
	}
	if ferr != nil {
		return fmt.Errorf("advisory: nvd enrichment incomplete: %w", ferr)
	}
	return nil
}

// applyNVDEnrichment attaches each matched CVE record's signal to the advisory,
// deterministically (aliases iterated in sorted order). Severity is only ever
// raised, never lowered.
func applyNVDEnrichment(advs []Advisory, idx map[string]*nvdRecord, now func() time.Time) {
	for i := range advs {
		for _, cve := range sortedCVEAliases(advs[i].Aliases) {
			rec, ok := idx[cve]
			if !ok {
				continue
			}
			advs[i].CVSS = append(advs[i].CVSS, rec.CVSS...)
			advs[i].CWEs = mergeSortedStrings(advs[i].CWEs, rec.CWEs)
			advs[i].Sources = appendUniqueString(advs[i].Sources, SourceNVD)

			if s := severityFromMetrics(advs[i].CVSS, 0, ""); s > advs[i].Severity {
				advs[i].Severity = s
			}

			advs[i].SourceMeta = append(advs[i].SourceMeta, SourceContribution{
				Name:      SourceNVD,
				Severity:  severityFromMetrics(rec.CVSS, 0, ""),
				Vector:    primaryVector(rec.CVSS),
				FetchedAt: now().UTC().Format(time.RFC3339),
			})
		}
	}
}

// ─── NVDCPESource: opt-in CPE breadth (secondary role) ───────────────────────

// NVDCPESource implements Source. It is the opt-in, lower-confidence CPE-breadth
// matcher: it surfaces CVEs whose CPE product matches the queried package, tagged
// SourceNVDCPE, always package-level, and marked Incomplete unless an exact or
// decidably-in-range version match is provable. It is wired only when --source
// includes the distinct "nvd-cpe" token. A feed fetch failure is unknown (error),
// never an empty clean result.
type NVDCPESource struct {
	feed *nvdFeedClient
}

// NewNVDCPESource returns an NVDCPESource backed by the feed cached under cacheDir.
func NewNVDCPESource(cacheDir string, opts ...NVDOption) *NVDCPESource {
	return &NVDCPESource{feed: newNVDFeedClient(cacheDir, opts...)}
}

// Query implements Source. It returns (nil, nil) when no CPE product matches the
// package, and a non-nil error when the feed could not be loaded (unknown ≠ safe).
func (s *NVDCPESource) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	idx, err := s.feed.index(ctx)
	if err != nil {
		return nil, fmt.Errorf("advisory: nvd-cpe query incomplete: %w", err)
	}

	product := normalizeCPEToken(lastPackageSegment(pkg.Name))
	if product == "" {
		return nil, nil
	}

	ids := make([]string, 0, len(idx))
	for id := range idx {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic output order

	var out []Advisory
	for _, id := range ids {
		matched, provable := cpeMatchesPackage(idx[id].CPEMatches, product, version)
		if !matched {
			continue
		}
		rec := idx[id]
		out = append(out, Advisory{
			ID:          id,
			Ecosystem:   pkg.Ecosystem,
			Module:      pkg.Name,
			Aliases:     []string{id},
			Sources:     []string{SourceNVDCPE},
			SymbolLevel: false, // CPE breadth is never symbol-level
			Incomplete:  !provable,
			CVSS:        append([]CVSSMetric(nil), rec.CVSS...),
			CWEs:        append([]string(nil), rec.CWEs...),
			Severity:    severityFromMetrics(rec.CVSS, 0, ""),
		})
	}
	return out, nil
}

// cpeMatchesPackage reports whether any vulnerable CPE match targets product, and
// whether the queried version is provably in scope. An exact version pin that
// differs from the query is not a match; a decidably out-of-range version is not
// a match; a decidably in-range bounded version is a provable match; a
// product-level CPE (no version bound) or an undecidable comparison matches but
// is NOT provable (stays UNKNOWN).
func cpeMatchesPackage(matches []nvdCPEMatchRaw, product, version string) (matched, provable bool) {
	bare := strings.TrimPrefix(version, "v")
	for _, m := range matches {
		if !m.Vulnerable {
			continue
		}
		if normalizeCPEToken(cpeProduct(m.Criteria)) != product {
			continue
		}

		if pinned := cpeVersionField(m.Criteria); pinned != "" && pinned != "*" && pinned != "-" {
			if pinned == bare {
				return true, true
			}
			continue // pins a different exact version
		}

		m, p := evalCPERange(bare, m)
		if m {
			if p {
				return true, true
			}
			matched = true // matched but not provable; keep scanning for a stronger match
		}
	}
	return matched, false
}

// evalCPERange evaluates a CPE version-range match. It returns (matched,
// provable): a product-level entry (no bounds) matches but is not provable; a
// decidably out-of-range version does not match; a decidably in-range bounded
// version is a provable match; an undecidable comparison matches but is not
// provable (conservative inclusion — unknown ≠ safe).
func evalCPERange(bare string, m nvdCPEMatchRaw) (matched, provable bool) {
	lo, loInc, hasLo := bound(m.VersionStartIncluding, m.VersionStartExcluding)
	hi, hiInc, hasHi := bound(m.VersionEndIncluding, m.VersionEndExcluding)
	if !hasLo && !hasHi {
		return true, false // product-level, no version constraint
	}

	decidable := true
	if hasLo {
		if cmp, ok := cpeVersionCompare(bare, lo); !ok {
			decidable = false
		} else if (loInc && cmp < 0) || (!loInc && cmp <= 0) {
			return false, false // below the lower bound
		}
	}
	if hasHi {
		if cmp, ok := cpeVersionCompare(bare, hi); !ok {
			decidable = false
		} else if (hiInc && cmp > 0) || (!hiInc && cmp >= 0) {
			return false, false // above the upper bound
		}
	}
	if !decidable {
		return true, false // include conservatively, unproven
	}
	return true, true
}

// bound returns the active bound value, its inclusivity, and whether one is set.
func bound(including, excluding string) (value string, inclusive, present bool) {
	if including != "" {
		return including, true, true
	}
	if excluding != "" {
		return excluding, false, true
	}
	return "", false, false
}

// ─── small shared helpers ────────────────────────────────────────────────────

// anyHasCVE reports whether at least one advisory carries a CVE alias.
func anyHasCVE(advs []Advisory) bool {
	for _, a := range advs {
		for _, alias := range a.Aliases {
			if cveIDPattern.MatchString(alias) {
				return true
			}
		}
	}
	return false
}

// sortedCVEAliases returns the CVE aliases of an advisory, deduped and sorted.
func sortedCVEAliases(aliases []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, a := range aliases {
		if !cveIDPattern.MatchString(a) {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// mergeSortedStrings unions two string slices, deduped and sorted.
func mergeSortedStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// appendUniqueString appends s only if not already present (order preserved).
func appendUniqueString(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// primaryVector returns the first CVSS vector string, or "" when none.
func primaryVector(metrics []CVSSMetric) string {
	if len(metrics) > 0 {
		return metrics[0].Vector
	}
	return ""
}

// lastPackageSegment returns the final path/coordinate segment of a package name
// (after '/' or ':'), e.g. "github.com/foo/bar" → "bar",
// "org.apache:log4j-core" → "log4j-core".
func lastPackageSegment(name string) string {
	seg := name
	if i := strings.LastIndexAny(seg, "/:"); i >= 0 {
		seg = seg[i+1:]
	}
	return seg
}

// normalizeCPEToken lowercases and unifies separators so CPE product tokens and
// package names compare on equal footing (CPE uses '_'; packages often use '-').
func normalizeCPEToken(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

// cpeProduct extracts the product field (index 4) of a CPE 2.3 URI:
// cpe:2.3:part:vendor:product:version:...
func cpeProduct(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

// cpeVersionField extracts the version field (index 5) of a CPE 2.3 URI.
func cpeVersionField(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) > 5 {
		return parts[5]
	}
	return ""
}

// cpeVersionCompare compares two dotted versions numerically, returning the
// comparison (-1/0/+1) and whether it was decidable. A non-numeric, non-equal
// segment makes the comparison undecidable (ok=false) so the caller stays
// conservative rather than inventing a precise ordering.
func cpeVersionCompare(a, b string) (int, bool) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr != nil || berr != nil {
			if av == bv {
				continue // equal non-numeric segment, keep going
			}
			return 0, false // undecidable
		}
		if ai != bi {
			if ai < bi {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}
