package advisory

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SourceEPSS is the --source flag token that opts the EPSS exploit-prediction
// enricher into the post-merge enrichment chain. EPSS is prioritization metadata
// (a CVE-keyed exploit-probability join), not a package→advisory source, and is
// opt-in because the feeds are heavy enough to slow a default scan.
const SourceEPSS = "epss"

// epssAPIBaseURL is the FIRST.org EPSS query API. It returns the most recent
// scores for an explicit set of CVEs and is preferred for freshness.
const epssAPIBaseURL = "https://api.first.org/data/v1/epss"

// epssCSVURL is the daily full-snapshot CSV (gzip-compressed). It is the offline
// floor: cached + conditional-GET, consulted when the API is unavailable or to
// fill CVEs the API did not score.
const epssCSVURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// epssDefaultMaxAge is how long a cached CSV snapshot is trusted before a
// conditional-GET refresh is attempted. EPSS publishes daily, so 24h is the
// natural cadence.
const epssDefaultMaxAge = 24 * time.Hour

// epssAPIBatch bounds how many CVEs are requested per API call to keep URLs and
// responses a sane size.
const epssAPIBatch = 100

// cvePattern matches a canonical CVE identifier (case-insensitive).
var cvePattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// EPSSEnricher fills Advisory.EPSS by joining on each advisory's CVE aliases.
//
// It is hybrid: the FIRST.org query API provides the freshest scores, and the
// daily CSV snapshot is the offline floor (cached with a conditional GET). A CVE
// the feeds do not score is left untouched — that is a legitimate "no signal",
// NOT "safe". A genuine fetch failure with no usable cache is reported as an
// error so the caller marks the scan incomplete (unknown ≠ safe).
type EPSSEnricher struct {
	// APIBaseURL is the FIRST.org EPSS API base; empty uses epssAPIBaseURL.
	APIBaseURL string
	// CSVURL is the daily snapshot URL; empty uses epssCSVURL.
	CSVURL string
	// HTTP is the client for both feeds; nil uses a client with defaultHTTPTimeout.
	HTTP *http.Client
	// CacheDir is where the CSV snapshot floor is cached. Empty disables the floor
	// (API-only); offline mode then has no data source and fails closed.
	CacheDir string
	// Offline disables all network access. The CSV floor must already be cached.
	Offline bool
	// MaxAge bounds CSV cache trust before a refresh; zero uses epssDefaultMaxAge.
	MaxAge time.Duration
	// Now is the clock used for staleness; nil uses time.Now.
	Now func() time.Time
}

// Name implements Enricher.
func (e *EPSSEnricher) Name() string { return "epss" }

func (e *EPSSEnricher) httpClient() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (e *EPSSEnricher) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *EPSSEnricher) maxAge() time.Duration {
	if e.MaxAge > 0 {
		return e.MaxAge
	}
	return epssDefaultMaxAge
}

// Enrich implements Enricher. It collects the CVEs across advs, fetches their
// EPSS scores (API first, CSV floor as fallback/fill), and assigns them to every
// advisory carrying that CVE.
func (e *EPSSEnricher) Enrich(ctx context.Context, advs []Advisory) error {
	cves := uniqueCVEs(advs)
	if len(cves) == 0 {
		// Nothing to join on — a successful no-op, not a failure.
		return nil
	}

	want := make(map[string]struct{}, len(cves))
	for _, c := range cves {
		want[c] = struct{}{}
	}

	scores := make(map[string]EPSSScore, len(cves))
	var apiErr error
	if !e.Offline {
		apiScores, err := e.queryAPI(ctx, cves)
		if err != nil {
			apiErr = err
		} else {
			for k, v := range apiScores {
				scores[k] = v
			}
		}
	}

	// The CSV floor is the REQUIRED data source when offline or when the API
	// failed; in those cases a floor failure is incomplete. When the API already
	// succeeded, the floor is only consulted to fill CVEs the API did not score,
	// and its absence is NOT a failure — an unscored CVE is a legitimate
	// "no signal" (the CSV would not score it either).
	floorPrimary := e.Offline || apiErr != nil
	var floorErr error
	if floorPrimary || len(scores) < len(want) {
		floor, err := e.queryCSVFloor(ctx, want)
		// Merge whatever the floor produced even on a degraded read (stale cache):
		// the data is still usable; the error only governs the incomplete signal.
		for k, v := range floor {
			if _, ok := scores[k]; !ok {
				scores[k] = v
			}
		}
		floorErr = err
	}

	applyEPSS(advs, scores)

	// Failure semantics (unknown ≠ safe): when the floor was the required source
	// and it failed or could only serve a stale cache, the result is incomplete.
	// A gap-fill floor failure (API already authoritative) is intentionally ignored.
	if floorPrimary && floorErr != nil {
		return e.combinedFailure(apiErr, floorErr)
	}
	return nil
}

func (e *EPSSEnricher) combinedFailure(apiErr, floorErr error) error {
	switch {
	case apiErr != nil && floorErr != nil:
		return fmt.Errorf("advisory: epss enrichment failed (api: %v; csv: %w)", apiErr, floorErr)
	case apiErr != nil:
		return fmt.Errorf("advisory: epss enrichment failed: %w", apiErr)
	default:
		return fmt.Errorf("advisory: epss enrichment failed: %w", floorErr)
	}
}

// applyEPSS assigns each score to every advisory carrying the matching CVE.
func applyEPSS(advs []Advisory, scores map[string]EPSSScore) {
	for i := range advs {
		for _, cve := range cveIDs(&advs[i]) {
			if s, ok := scores[cve]; ok {
				sc := s
				advs[i].EPSS = &sc
				break
			}
		}
	}
}

// ─── FIRST.org API ────────────────────────────────────────────────────────────

// epssAPIResponse is the shape of a FIRST.org EPSS API response.
type epssAPIResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// queryAPI fetches scores for the given CVEs in deterministic batches.
func (e *EPSSEnricher) queryAPI(ctx context.Context, cves []string) (map[string]EPSSScore, error) {
	base := e.APIBaseURL
	if base == "" {
		base = epssAPIBaseURL
	}

	out := make(map[string]EPSSScore, len(cves))
	for start := 0; start < len(cves); start += epssAPIBatch {
		end := start + epssAPIBatch
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[start:end]

		url := base + "?cve=" + strings.Join(batch, ",")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build epss api request: %w", err)
		}
		resp, err := e.httpClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET epss api: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET epss api: unexpected status %d", resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("read epss api body: %w", readErr)
		}

		var parsed epssAPIResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode epss api body: %w", err)
		}
		for _, d := range parsed.Data {
			score, ok := parseEPSSRow(d.CVE, d.EPSS, d.Percentile, d.Date)
			if !ok {
				continue
			}
			out[strings.ToUpper(d.CVE)] = score
		}
	}
	return out, nil
}

// ─── CSV snapshot floor ───────────────────────────────────────────────────────

// queryCSVFloor ensures the gzip CSV snapshot is cached, then stream-parses it,
// indexing only the requested CVEs to bound memory.
func (e *EPSSEnricher) queryCSVFloor(ctx context.Context, want map[string]struct{}) (map[string]EPSSScore, error) {
	if e.CacheDir == "" {
		return nil, fmt.Errorf("epss CSV floor unavailable: no cache dir configured")
	}
	csvURL := e.CSVURL
	if csvURL == "" {
		csvURL = epssCSVURL
	}

	dc := &docCache{
		httpc:     e.httpClient(),
		url:       csvURL,
		cachePath: filepath.Join(e.CacheDir, "epss_scores-current.csv.gz"),
		offline:   e.Offline,
		now:       e.now,
		maxAge:    e.maxAge(),
	}
	path, ensErr := dc.ensure(ctx)
	if path == "" {
		return nil, ensErr
	}

	scores, parseErr := parseEPSSCSV(path, want)
	if parseErr != nil {
		return nil, parseErr
	}
	// A degraded (stale-cache) read still returns the data plus the warning so the
	// caller can surface incomplete.
	return scores, ensErr
}

// parseEPSSCSV stream-reads the gzip-compressed EPSS CSV, returning scores only
// for CVEs present in want. The CSV has comment lines prefixed with '#', then a
// header row "cve,epss,percentile", then data rows.
func parseEPSSCSV(path string, want map[string]struct{}) (map[string]EPSSScore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open epss csv: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("open epss gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	out := make(map[string]EPSSScore, len(want))
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 3 {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(cols[0]))
		if cve == "CVE" { // header row
			continue
		}
		if _, ok := want[cve]; !ok {
			continue
		}
		score, ok := parseEPSSRow(cols[0], cols[1], cols[2], "")
		if !ok {
			continue
		}
		out[cve] = score
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan epss csv: %w", err)
	}
	return out, nil
}

// parseEPSSRow parses the probability/percentile/date triple of one EPSS record.
// A row whose probability does not parse is skipped (returns ok=false) rather
// than fabricating a zero score.
func parseEPSSRow(cve, epss, percentile, date string) (EPSSScore, bool) {
	if strings.TrimSpace(cve) == "" {
		return EPSSScore{}, false
	}
	prob, err := strconv.ParseFloat(strings.TrimSpace(epss), 64)
	if err != nil {
		return EPSSScore{}, false
	}
	pct, _ := strconv.ParseFloat(strings.TrimSpace(percentile), 64)
	return EPSSScore{
		Probability: prob,
		Percentile:  pct,
		Date:        strings.TrimSpace(date),
	}, true
}

// ─── Conditional-GET document cache (shared by EPSS CSV + KEV JSON) ───────────

// docCache fetches a single remote document into a local file with a
// conditional GET (ETag / Last-Modified) and a staleness window. It is the
// offline-floor primitive for the enrichment feeds that are a single file.
type docCache struct {
	httpc     *http.Client
	url       string
	cachePath string
	offline   bool
	now       func() time.Time
	maxAge    time.Duration
}

// docMeta is the sidecar persisted next to a cached document for conditional GET.
type docMeta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

func (d *docCache) metaPath() string { return d.cachePath + ".meta.json" }

// ensure returns the path to a usable cached document. The error return encodes
// freshness honesty, mirroring the cache.go RefreshFallbackWarning contract:
//
//	(path != "", err == nil)  → fresh / freshness-confirmed; use it cleanly.
//	(path != "", err != nil)  → stale cache used because the live check failed;
//	                            the caller MUST apply the data AND propagate err
//	                            so the scan is marked incomplete (unknown ≠ safe).
//	(path == "", err != nil)  → no usable data at all; the caller fails closed.
func (d *docCache) ensure(ctx context.Context) (string, error) {
	meta, haveMeta := d.readMeta()
	haveBody := d.bodyExists()

	if d.offline {
		if haveBody {
			return d.cachePath, nil
		}
		return "", fmt.Errorf("offline mode requires a cached document at %q (missing)", d.cachePath)
	}

	// A fresh-enough cache short-circuits the network entirely.
	if haveBody && haveMeta && d.now().Sub(meta.FetchedAt) < d.maxAge {
		return d.cachePath, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		if haveBody {
			return d.cachePath, fmt.Errorf("build request for %q: %w", d.url, err)
		}
		return "", fmt.Errorf("build request for %q: %w", d.url, err)
	}
	if haveMeta {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}

	resp, err := d.httpc.Do(req)
	if err != nil {
		if haveBody {
			// Network unreachable but a (possibly stale) cache exists: degrade.
			return d.cachePath, fmt.Errorf("GET %q: %w", d.url, err)
		}
		return "", fmt.Errorf("GET %q: %w", d.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Server confirmed our cache is current; refresh the freshness stamp.
		if haveBody {
			d.writeMeta(docMeta{
				ETag:         firstNonEmpty(resp.Header.Get("ETag"), meta.ETag),
				LastModified: firstNonEmpty(resp.Header.Get("Last-Modified"), meta.LastModified),
				FetchedAt:    d.now(),
			})
			return d.cachePath, nil
		}
		// 304 without a body is a protocol surprise; treat as no data.
		return "", fmt.Errorf("GET %q: 304 Not Modified but no cached body present", d.url)

	case http.StatusOK:
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			if haveBody {
				return d.cachePath, fmt.Errorf("read %q: %w", d.url, readErr)
			}
			return "", fmt.Errorf("read %q: %w", d.url, readErr)
		}
		if err := os.MkdirAll(filepath.Dir(d.cachePath), 0o755); err != nil {
			if haveBody {
				return d.cachePath, fmt.Errorf("create cache dir: %w", err)
			}
			return "", fmt.Errorf("create cache dir: %w", err)
		}
		if err := atomicWrite(d.cachePath, body, true); err != nil {
			if haveBody {
				return d.cachePath, fmt.Errorf("write cache: %w", err)
			}
			return "", fmt.Errorf("write cache: %w", err)
		}
		d.writeMeta(docMeta{
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			FetchedAt:    d.now(),
		})
		return d.cachePath, nil

	default:
		if haveBody {
			return d.cachePath, fmt.Errorf("GET %q: unexpected status %d", d.url, resp.StatusCode)
		}
		return "", fmt.Errorf("GET %q: unexpected status %d", d.url, resp.StatusCode)
	}
}

func (d *docCache) bodyExists() bool {
	info, err := os.Stat(d.cachePath)
	return err == nil && !info.IsDir()
}

func (d *docCache) readMeta() (docMeta, bool) {
	data, err := os.ReadFile(d.metaPath())
	if err != nil {
		return docMeta{}, false
	}
	var m docMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return docMeta{}, false
	}
	return m, true
}

func (d *docCache) writeMeta(m docMeta) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	// Best-effort: a meta write failure only costs a redundant future fetch.
	_ = atomicWrite(d.metaPath(), data, false)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ─── CVE alias helpers (shared by EPSS + KEV) ─────────────────────────────────

// cveIDs returns the upper-cased CVE identifiers carried by an advisory's ID and
// aliases, deduplicated and in stable order.
func cveIDs(a *Advisory) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if !cvePattern.MatchString(s) {
			return
		}
		up := strings.ToUpper(s)
		if _, ok := seen[up]; ok {
			return
		}
		seen[up] = struct{}{}
		out = append(out, up)
	}
	add(a.ID)
	for _, al := range a.Aliases {
		add(al)
	}
	return out
}

// uniqueCVEs returns every distinct CVE across all advisories, sorted for
// deterministic request batching.
func uniqueCVEs(advs []Advisory) []string {
	seen := make(map[string]struct{})
	var out []string
	for i := range advs {
		for _, cve := range cveIDs(&advs[i]) {
			if _, ok := seen[cve]; ok {
				continue
			}
			seen[cve] = struct{}{}
			out = append(out, cve)
		}
	}
	sort.Strings(out)
	return out
}
