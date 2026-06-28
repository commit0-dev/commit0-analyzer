package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// kevCatalogURL is the CISA Known Exploited Vulnerabilities catalog (single JSON
// file). It is cached with a conditional GET as the offline floor.
const kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// kevDefaultMaxAge bounds how long a cached KEV catalog is trusted before a
// conditional-GET refresh is attempted. CISA updates the catalog roughly daily.
const kevDefaultMaxAge = 24 * time.Hour

// KEVEnricher fills Advisory.KEV by joining each advisory's CVE aliases against
// the CISA KEV catalog. A CVE that is not in the catalog is left untouched — a
// missing entry is "not currently catalogued", NEVER "safe". A fetch failure
// with no usable cache is reported as an error so the scan is marked incomplete.
type KEVEnricher struct {
	// URL is the KEV catalog URL; empty uses kevCatalogURL.
	URL string
	// HTTP is the client; nil uses a client with defaultHTTPTimeout.
	HTTP *http.Client
	// CacheDir is where the catalog JSON is cached. Empty disables caching
	// (online-only); offline mode then has no data source and fails closed.
	CacheDir string
	// Offline disables network access. The catalog must already be cached.
	Offline bool
	// MaxAge bounds cache trust before refresh; zero uses kevDefaultMaxAge.
	MaxAge time.Duration
	// Now is the clock used for staleness; nil uses time.Now.
	Now func() time.Time
}

// Name implements Enricher.
func (k *KEVEnricher) Name() string { return "kev" }

func (k *KEVEnricher) httpClient() *http.Client {
	if k.HTTP != nil {
		return k.HTTP
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (k *KEVEnricher) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

func (k *KEVEnricher) maxAge() time.Duration {
	if k.MaxAge > 0 {
		return k.MaxAge
	}
	return kevDefaultMaxAge
}

// kevCatalog is the shape of the CISA KEV catalog JSON.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Enrich implements Enricher. It loads the catalog, indexes it by CVE, and marks
// every advisory whose CVE appears in the catalog.
func (k *KEVEnricher) Enrich(ctx context.Context, advs []Advisory) error {
	cves := uniqueCVEs(advs)
	if len(cves) == 0 {
		return nil
	}

	catalog, ensErr, err := k.loadCatalog(ctx)
	if err != nil {
		return err
	}

	applyKEV(advs, catalog)

	// A degraded (stale-cache) load still surfaces as incomplete so a
	// freshness-unconfirmed catalog never reads as a clean pass.
	if ensErr != nil {
		return fmt.Errorf("advisory: kev catalog degraded: %w", ensErr)
	}
	return nil
}

// loadCatalog returns the CVE→entry index. The second return is a non-fatal
// degraded-cache warning (data is still usable); the third is a hard failure.
func (k *KEVEnricher) loadCatalog(ctx context.Context) (map[string]KEVEntry, error, error) {
	if k.CacheDir == "" && k.Offline {
		return nil, nil, fmt.Errorf("advisory: kev offline mode requires a cache dir")
	}

	url := k.URL
	if url == "" {
		url = kevCatalogURL
	}

	// Without a cache dir we still support a direct online fetch by routing the
	// document through a temp cache path; the enricher's primary mode uses CacheDir.
	cacheDir := k.CacheDir
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	dc := &docCache{
		httpc:     k.httpClient(),
		url:       url,
		cachePath: filepath.Join(cacheDir, "cisa_known_exploited_vulnerabilities.json"),
		offline:   k.Offline,
		now:       k.now,
		maxAge:    k.maxAge(),
	}
	path, ensErr := dc.ensure(ctx)
	if path == "" {
		return nil, nil, fmt.Errorf("advisory: kev enrichment failed: %w", ensErr)
	}

	index, parseErr := parseKEVCatalog(path)
	if parseErr != nil {
		return nil, nil, fmt.Errorf("advisory: kev catalog parse: %w", parseErr)
	}
	return index, ensErr, nil
}

// parseKEVCatalog reads the catalog file and indexes it by upper-cased CVE id.
func parseKEVCatalog(path string) (map[string]KEVEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read kev catalog: %w", err)
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("decode kev catalog: %w", err)
	}

	out := make(map[string]KEVEntry, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if cve == "" {
			continue
		}
		out[cve] = KEVEntry{
			Listed:          true,
			DateAdded:       strings.TrimSpace(v.DateAdded),
			DueDate:         strings.TrimSpace(v.DueDate),
			KnownRansomware: strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known"),
		}
	}
	return out, nil
}

// applyKEV marks every advisory whose CVE appears in the catalog index.
func applyKEV(advs []Advisory, index map[string]KEVEntry) {
	for i := range advs {
		for _, cve := range cveIDs(&advs[i]) {
			if entry, ok := index[cve]; ok {
				e := entry
				advs[i].KEV = &e
				break
			}
		}
	}
}
