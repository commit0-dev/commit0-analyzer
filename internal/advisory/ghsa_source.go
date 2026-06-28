package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SourceGHSA is the source attribution tag for the GitHub Security Advisory
// (GHSA) database. It covers both the offline OSV-format bundle (the
// github/advisory-database repository) and the live GraphQL delta/enrichment
// layer.
const SourceGHSA = "ghsa"

// ghsaDefaultGraphQLURL is the GitHub GraphQL API endpoint used for the live
// delta/enrichment layer.
const ghsaDefaultGraphQLURL = "https://api.github.com/graphql"

// ghsaGraphQLPageSize bounds how many vulnerabilities are requested per GraphQL
// page. Pagination follows pageInfo.hasNextPage so a package with more than this
// many advisories is fully fetched (no silent truncation → no false negative).
const ghsaGraphQLPageSize = 100

// GHSASource implements Source against the GitHub Security Advisory database
// using the hybrid model from the advisory-intelligence plan:
//
//   - Offline floor (bundle): OSV-format JSON records cached per ecosystem under
//     <cacheDir>/<ecosystem>/*.json, queried fully offline. This is the breadth
//     floor and the only layer used when no GitHub token is available.
//   - Live delta/enrichment (GraphQL): the securityVulnerabilities query layers
//     fresher entries plus CWE and CVSS-vector enrichment. It is token-gated:
//     with no token the layer is skipped (degrade, not fail); a requested-and-
//     attempted GraphQL call that errors makes the result incomplete.
//
// Failure semantics ("unknown ≠ safe"): a GraphQL error when GHSA was requested
// propagates as a non-nil error so MultiSource marks the scan incomplete. A
// missing bundle directory mirrors OSVBundleSource: it returns no advisories
// (the "not yet refreshed" state) and the wiring layer is responsible for
// ensuring the bundle is present.
//
// Thread safety: Query is safe to call from multiple goroutines. The bundle
// index is built once under a mutex and is read-only thereafter.
type GHSASource struct {
	// GraphQLURL is the GitHub GraphQL endpoint. Defaults to the public API.
	GraphQLURL string
	// HTTP is the client used for GraphQL requests. Defaults to a 30-second client.
	HTTP *http.Client
	// Token is the GitHub token sent as a Bearer header. Falls back to the
	// GITHUB_TOKEN environment variable when empty. When neither is set, the
	// GraphQL layer is skipped.
	Token string

	// cacheDir is the root under which per-ecosystem bundle subdirectories live.
	cacheDir string

	// indexMu guards indexes, a per-ecosystem-directory cache of the parsed bundle.
	indexMu sync.Mutex
	indexes map[string]*ghsaIndex
}

// ghsaOption is a functional option for NewGHSASource.
type ghsaOption func(*GHSASource)

// WithGHSAGraphQLURL overrides the GraphQL endpoint (used by tests to inject an
// httptest server).
func WithGHSAGraphQLURL(url string) ghsaOption {
	return func(s *GHSASource) { s.GraphQLURL = url }
}

// WithGHSAToken sets the GitHub token explicitly, bypassing the GITHUB_TOKEN
// environment lookup.
func WithGHSAToken(token string) ghsaOption {
	return func(s *GHSASource) { s.Token = token }
}

// WithGHSAHTTPClient overrides the HTTP client used for GraphQL requests.
func WithGHSAHTTPClient(c *http.Client) ghsaOption {
	return func(s *GHSASource) { s.HTTP = c }
}

// NewGHSASource returns a GHSASource whose offline bundle lives under cacheDir.
// Apply functional options to override the GraphQL endpoint, token, or HTTP
// client.
func NewGHSASource(cacheDir string, opts ...ghsaOption) *GHSASource {
	s := &GHSASource{
		GraphQLURL: ghsaDefaultGraphQLURL,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		cacheDir:   cacheDir,
		indexes:    make(map[string]*ghsaIndex),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Query implements Source. It returns advisories from the offline bundle and,
// when a token is available, layers in fresher/enriched GraphQL results.
//
// An ecosystem GHSA does not serve returns (nil, nil). A GraphQL failure when
// the layer was attempted returns the bundle advisories alongside a non-nil
// error so the caller marks the scan incomplete.
func (s *GHSASource) Query(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	ghEco, ok := toGHSAEcosystem(pkg.Ecosystem)
	if !ok {
		// Ecosystem not served by GHSA — never a silent clean, just out of scope.
		return nil, nil
	}

	bundleAdvs, err := s.queryBundle(ctx, pkg, version)
	if err != nil {
		return nil, err
	}

	if !s.graphQLEnabled() {
		// Token-optional degrade: no token → GraphQL layer absent, bundle floor only.
		return bundleAdvs, nil
	}

	gqlAdvs, gqlErr := s.queryGraphQL(ctx, ghEco, pkg, version)
	if gqlErr != nil {
		// Requested-and-attempted GraphQL call failed → incomplete. Return whatever
		// the bundle floor provided so coverage is not silently lost.
		return bundleAdvs, gqlErr
	}

	// GraphQL is the fresher/enriched layer, so it is the preferred representative;
	// bundle-only entries are appended so breadth is never lost.
	return combineGHSA(gqlAdvs, bundleAdvs), nil
}

// graphQLEnabled reports whether the live GraphQL layer should run. It runs only
// when a token is available (explicit or via GITHUB_TOKEN) and an endpoint is set.
func (s *GHSASource) graphQLEnabled() bool {
	return s.GraphQLURL != "" && s.token() != ""
}

// token returns the configured token, falling back to the GITHUB_TOKEN env var.
func (s *GHSASource) token() string {
	if s.Token != "" {
		return s.Token
	}
	return os.Getenv("GITHUB_TOKEN")
}

// ─── Bundle (offline floor) ─────────────────────────────────────────────────

// ecoDir returns the per-ecosystem bundle directory path.
func (s *GHSASource) ecoDir(ecosystem string) string {
	return filepath.Join(s.cacheDir, ecosystem)
}

// queryBundle returns advisories from the offline OSV-format bundle for pkg at
// version. A missing ecosystem directory mirrors OSVBundleSource: it returns
// (nil, nil), the "not yet refreshed" state, not an error.
func (s *GHSASource) queryBundle(ctx context.Context, pkg Package, version string) ([]Advisory, error) {
	dir := s.ecoDir(pkg.Ecosystem)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	idx, err := s.indexFor(ctx, dir, pkg.Ecosystem)
	if err != nil {
		return nil, err
	}
	return idx.lookup(pkg, version), nil
}

// indexFor returns the parsed bundle index for an ecosystem directory, building
// and caching it on first use.
func (s *GHSASource) indexFor(ctx context.Context, dir, ecosystem string) (*ghsaIndex, error) {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if idx, ok := s.indexes[dir]; ok {
		return idx, nil
	}
	idx, err := buildGHSAIndex(ctx, dir, ecosystem)
	if err != nil {
		return nil, err
	}
	s.indexes[dir] = idx
	return idx, nil
}

// ghsaIndex groups parsed, non-withdrawn GHSA advisories by module name so each
// package query is a map lookup rather than a directory rescan.
type ghsaIndex struct {
	byName map[string][]Advisory
}

// buildGHSAIndex parses every *.json record in dir once, enriches it with CVSS
// and CWE data, and groups the non-withdrawn advisories by their (ecosystem-
// normalized) module name.
func buildGHSAIndex(ctx context.Context, dir, ecosystem string) (*ghsaIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("advisory: ghsa: index dir %q: %w", dir, err)
	}
	idx := &ghsaIndex{byName: make(map[string][]Advisory)}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == ManifestFilename {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("advisory: ghsa: read %q: %w", entry.Name(), err)
		}
		advs, err := parseGHSARecordPerPackage(data, ecosystem)
		if err != nil {
			// Corrupt or non-matching record: skip without a hard error, matching
			// the OSV bundle index behaviour.
			continue
		}
		for i := range advs {
			if advs[i].Withdrawn != "" {
				// Withdrawn entries are filtered from results; the Withdrawn field on
				// the parsed advisory keeps the reason inspectable for debug logging.
				continue
			}
			key := advs[i].Module
			if ecosystem == EcosystemNPM {
				key = normalizeNPMPackageName(key)
			}
			idx.byName[key] = append(idx.byName[key], advs[i])
		}
	}
	return idx, nil
}

// lookup returns advisories for pkg whose version ranges include version,
// stamped with the GHSA source attribution. Undecidable ranges are forwarded
// with Incomplete=true (unknown ≠ safe), never dropped.
func (idx *ghsaIndex) lookup(pkg Package, version string) []Advisory {
	queryName := pkg.Name
	if pkg.Ecosystem == EcosystemNPM {
		queryName = normalizeNPMPackageName(queryName)
	}
	candidates := idx.byName[queryName]
	if len(candidates) == 0 {
		return nil
	}
	queryVersion := canonical(version)
	var results []Advisory
	for i := range candidates {
		adv := copyAdvisory(candidates[i])
		adv.Ecosystem = pkg.Ecosystem
		switch adv.AffectsVersionV(queryVersion) {
		case VersionAffected:
			results = append(results, adv)
		case VersionUndecidable:
			adv.Incomplete = true
			results = append(results, adv)
			// VersionNotAffected: drop — the only safe drop.
		}
	}
	return results
}

// parseGHSARecordPerPackage parses a single OSV-format GHSA record into one
// Advisory per affected package, then layers in the GHSA-specific enrichment the
// shared OSV parser does not produce: parsed CVSS metrics (via ParseCVSS) and
// CWE identifiers from database_specific.cwe_ids. Source attribution is set to
// SourceGHSA and severity is upgraded from the parsed metrics, never downgraded.
func parseGHSARecordPerPackage(data []byte, ecosystem string) ([]Advisory, error) {
	advs, err := parseOSVRecordPerPackage(data, ecosystem)
	if err != nil {
		return nil, err
	}

	var meta ghsaRecordMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("advisory: ghsa: parse record metadata: %w", err)
	}
	metrics := parseGHSACVSSMetrics(meta.Severity)
	cwes := normalizeCWEs(meta.DatabaseSpecific.CWEIDs)

	for i := range advs {
		advs[i].Sources = []string{SourceGHSA}
		if len(metrics) > 0 {
			advs[i].CVSS = append([]CVSSMetric(nil), metrics...)
			// Upgrade severity from the precise vector score; severityFromMetrics
			// never lowers a present signal, and only a scored metric participates.
			if sev := severityFromMetrics(metrics, 0, ""); sev > advs[i].Severity {
				advs[i].Severity = sev
			}
		}
		advs[i].CWEs = cwes
	}
	return advs, nil
}

// ghsaRecordMeta captures the OSV record fields the shared parser does not
// surface but GHSA records carry: the CVSS severity[] vectors and the
// database_specific.cwe_ids list.
type ghsaRecordMeta struct {
	Severity         []osvSeverityEntry `json:"severity"`
	DatabaseSpecific struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

// parseGHSACVSSMetrics parses every CVSS_V3/CVSS_V4 severity entry into a
// CVSSMetric via the P0 ParseCVSS engine. An unparseable vector is skipped
// (the OSV severity fallback still carries the band); it never fabricates a score.
func parseGHSACVSSMetrics(entries []osvSeverityEntry) []CVSSMetric {
	var out []CVSSMetric
	for _, e := range entries {
		t := strings.ToUpper(e.Type)
		if t != "CVSS_V3" && t != "CVSS_V4" {
			continue
		}
		m, err := ParseCVSS(e.Score)
		if err != nil {
			continue
		}
		m.Source = SourceGHSA
		out = append(out, m)
	}
	return out
}

// ─── GraphQL (live delta/enrichment) ────────────────────────────────────────

// queryGraphQL fetches all securityVulnerabilities for pkg from the GitHub
// GraphQL API, paging until exhausted, and returns the advisories that affect
// version. Withdrawn entries are filtered. Any HTTP, transport, or GraphQL-level
// error returns a non-nil error so the caller marks the scan incomplete.
func (s *GHSASource) queryGraphQL(ctx context.Context, ghEco string, pkg Package, version string) ([]Advisory, error) {
	queryVersion := canonical(version)
	var (
		results []Advisory
		cursor  string
	)
	for {
		page, err := s.fetchGraphQLPage(ctx, ghEco, pkg.Name, cursor)
		if err != nil {
			return nil, err
		}
		for _, node := range page.Nodes {
			adv := ghsaNodeToAdvisory(node, pkg.Ecosystem)
			if adv.Withdrawn != "" {
				continue
			}
			switch adv.AffectsVersionV(queryVersion) {
			case VersionAffected:
				results = append(results, adv)
			case VersionUndecidable:
				adv.Incomplete = true
				results = append(results, adv)
				// VersionNotAffected: drop — the only safe drop.
			}
		}
		if !page.PageInfo.HasNextPage || page.PageInfo.EndCursor == "" {
			break
		}
		cursor = page.PageInfo.EndCursor
	}
	return results, nil
}

// ghsaGraphQLRequest is the JSON request body for the GitHub GraphQL API.
type ghsaGraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

// ghsaSecurityVulnerabilitiesQuery fetches a single page of vulnerabilities for
// an ecosystem/package, including the advisory enrichment (CVSS, CWE, aliases).
const ghsaSecurityVulnerabilitiesQuery = `query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!, $after: String) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
      advisory {
        ghsaId
        summary
        withdrawnAt
        identifiers { type value }
        cvss { score vectorString }
        cwes(first: 50) { nodes { cweId } }
      }
    }
  }
}`

// fetchGraphQLPage performs one GraphQL request and returns the decoded page.
func (s *GHSASource) fetchGraphQLPage(ctx context.Context, ghEco, pkgName, cursor string) (*ghsaVulnConnection, error) {
	vars := map[string]interface{}{
		"ecosystem": ghEco,
		"package":   pkgName,
		"first":     ghsaGraphQLPageSize,
	}
	if cursor != "" {
		vars["after"] = cursor
	}
	body, err := json.Marshal(ghsaGraphQLRequest{
		Query:     ghsaSecurityVulnerabilitiesQuery,
		Variables: vars,
	})
	if err != nil {
		return nil, fmt.Errorf("advisory: ghsa: marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.GraphQLURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("advisory: ghsa: build GraphQL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token())

	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("advisory: ghsa: GraphQL POST %s: %w", s.GraphQLURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: ghsa: GraphQL POST %s: unexpected status %d", s.GraphQLURL, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("advisory: ghsa: read GraphQL body: %w", err)
	}

	var decoded ghsaGraphQLResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("advisory: ghsa: decode GraphQL response: %w", err)
	}
	if len(decoded.Errors) > 0 {
		msgs := make([]string, len(decoded.Errors))
		for i, e := range decoded.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("advisory: ghsa: GraphQL errors: %s", strings.Join(msgs, "; "))
	}
	return &decoded.Data.SecurityVulnerabilities, nil
}

// ghsaGraphQLResponse is the top-level GraphQL response envelope.
type ghsaGraphQLResponse struct {
	Data struct {
		SecurityVulnerabilities ghsaVulnConnection `json:"securityVulnerabilities"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ghsaVulnConnection is the paginated securityVulnerabilities connection.
type ghsaVulnConnection struct {
	PageInfo struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
	Nodes []ghsaVulnNode `json:"nodes"`
}

// ghsaVulnNode is one securityVulnerabilities node.
type ghsaVulnNode struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerableVersionRange"`
	FirstPatchedVersion    *struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
	Advisory struct {
		GhsaID      string `json:"ghsaId"`
		Summary     string `json:"summary"`
		WithdrawnAt string `json:"withdrawnAt"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		CVSS *struct {
			Score        float64 `json:"score"`
			VectorString string  `json:"vectorString"`
		} `json:"cvss"`
		CWEs struct {
			Nodes []struct {
				CweID string `json:"cweId"`
			} `json:"nodes"`
		} `json:"cwes"`
	} `json:"advisory"`
}

// ghsaNodeToAdvisory converts a GraphQL vulnerability node into an internal
// Advisory. The vulnerableVersionRange is parsed via the GHSA range grammar; an
// unparseable range marks the advisory undecidable rather than dropping it.
func ghsaNodeToAdvisory(node ghsaVulnNode, ecosystem string) Advisory {
	adv := Advisory{
		ID:        node.Advisory.GhsaID,
		Ecosystem: ecosystem,
		Module:    node.Package.Name,
		Sources:   []string{SourceGHSA},
		Withdrawn: node.Advisory.WithdrawnAt,
	}

	// Aliases: every identifier value except the advisory's own GHSA id.
	aliasSet := make(map[string]struct{}, len(node.Advisory.Identifiers))
	for _, id := range node.Advisory.Identifiers {
		if id.Value == "" || id.Value == adv.ID {
			continue
		}
		aliasSet[id.Value] = struct{}{}
	}
	adv.Aliases = sortedKeys(aliasSet)

	// CWEs.
	rawCWEs := make([]string, 0, len(node.Advisory.CWEs.Nodes))
	for _, c := range node.Advisory.CWEs.Nodes {
		rawCWEs = append(rawCWEs, c.CweID)
	}
	adv.CWEs = normalizeCWEs(rawCWEs)

	// CVSS: parse the vector losslessly when present; the numeric score is the
	// severity fallback for a v4.0 vector whose exact score is deferred.
	var bareScore float64
	if node.Advisory.CVSS != nil {
		bareScore = node.Advisory.CVSS.Score
		if node.Advisory.CVSS.VectorString != "" {
			if m, err := ParseCVSS(node.Advisory.CVSS.VectorString); err == nil {
				m.Source = SourceGHSA
				adv.CVSS = []CVSSMetric{m}
			}
		}
	}
	adv.Severity = severityFromMetrics(adv.CVSS, bareScore, "")

	// Version range.
	if vr, ok := parseGHSAVersionRange(node.VulnerableVersionRange); ok {
		adv.VersionRanges = []VersionRange{vr}
	} else {
		// An unparseable range is undecidable, never a silent not-affected.
		adv.UndecidableRanges = true
	}

	return adv
}

// parseGHSAVersionRange parses a GHSA vulnerableVersionRange string (e.g.
// ">= 1.0.0, < 1.5.0", "<= 1.0.8", "= 0.2.0") into a single VersionRange.
//
// Supported operators: ">=" (inclusive lower → Introduced), "<" (exclusive upper
// → Fixed), "<=" (inclusive upper → LastAffected), "=" (exact → Introduced and
// LastAffected at the same version). Any other shape — empty input, a bare ">"
// (exclusive lower bound the model cannot represent), or an unrecognised operator
// such as "~>" — returns ok=false so the caller marks the advisory undecidable
// (unknown ≠ safe) rather than guessing.
func parseGHSAVersionRange(s string) (VersionRange, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return VersionRange{}, false
	}
	var vr VersionRange
	for _, part := range strings.Split(s, ",") {
		c := strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(c, ">="):
			v := strings.TrimSpace(strings.TrimPrefix(c, ">="))
			if v == "" {
				return VersionRange{}, false
			}
			vr.Introduced = v
		case strings.HasPrefix(c, "<="):
			v := strings.TrimSpace(strings.TrimPrefix(c, "<="))
			if v == "" {
				return VersionRange{}, false
			}
			vr.LastAffected = v
		case strings.HasPrefix(c, "<"):
			v := strings.TrimSpace(strings.TrimPrefix(c, "<"))
			if v == "" {
				return VersionRange{}, false
			}
			vr.Fixed = v
		case strings.HasPrefix(c, "="):
			v := strings.TrimSpace(strings.TrimPrefix(c, "="))
			if v == "" {
				return VersionRange{}, false
			}
			vr.Introduced = v
			vr.LastAffected = v
		default:
			// Includes a bare ">" exclusive lower bound and any unrecognised
			// operator — cannot be represented exactly, so undecidable.
			return VersionRange{}, false
		}
	}
	return vr, true
}

// ─── Combine bundle + GraphQL ───────────────────────────────────────────────

// combineGHSA merges advisory groups (GraphQL first, bundle second) by alias-
// equivalence. The first group's entries are the preferred representatives; a
// later entry that shares any identifier fills gaps in the representative
// (version ranges, CVSS, CWEs) and unions its aliases/sources without ever
// downgrading severity. Entries with no overlap are appended so breadth is never
// lost. The result is stable-sorted by ID for deterministic output.
func combineGHSA(groups ...[]Advisory) []Advisory {
	var all []Advisory
	for _, g := range groups {
		all = append(all, g...)
	}
	if len(all) == 0 {
		return nil
	}

	var (
		result []Advisory
		idsets []map[string]struct{}
	)
	for _, adv := range all {
		ids := identitySet(adv)
		matched := -1
		for i, set := range idsets {
			if setsIntersect(ids, set) {
				matched = i
				break
			}
		}
		if matched == -1 {
			result = append(result, copyAdvisory(adv))
			idsets = append(idsets, ids)
			continue
		}
		result[matched] = fillGHSAFields(result[matched], adv)
		for id := range ids {
			idsets[matched][id] = struct{}{}
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// fillGHSAFields enriches dst with any data src carries that dst lacks, unions
// aliases and sources, and keeps the higher severity. It never downgrades or
// drops a signal.
func fillGHSAFields(dst, src Advisory) Advisory {
	dst.Sources = unionStrings(dst.Sources, src.Sources)

	aliasSet := make(map[string]struct{}, len(dst.Aliases)+len(src.Aliases)+1)
	for _, a := range dst.Aliases {
		aliasSet[a] = struct{}{}
	}
	for _, a := range src.Aliases {
		aliasSet[a] = struct{}{}
	}
	if src.ID != "" && src.ID != dst.ID {
		aliasSet[src.ID] = struct{}{}
	}
	delete(aliasSet, dst.ID)
	dst.Aliases = sortedKeys(aliasSet)

	// Version coverage: only fill when dst has none, so the fresher layer's ranges
	// win and bundle ranges are used only as a fallback.
	if len(dst.VersionRanges) == 0 && len(dst.Versions) == 0 {
		if len(src.VersionRanges) > 0 {
			dst.VersionRanges = append([]VersionRange(nil), src.VersionRanges...)
		}
		if len(src.Versions) > 0 {
			dst.Versions = append([]string(nil), src.Versions...)
		}
		dst.UndecidableRanges = src.UndecidableRanges
		dst.Incomplete = src.Incomplete
	}

	if len(dst.CVSS) == 0 && len(src.CVSS) > 0 {
		dst.CVSS = append([]CVSSMetric(nil), src.CVSS...)
	}
	if len(dst.CWEs) == 0 && len(src.CWEs) > 0 {
		dst.CWEs = append([]string(nil), src.CWEs...)
	}
	if len(dst.Symbols) == 0 && len(src.Symbols) > 0 {
		dst.Symbols = append([]Symbol(nil), src.Symbols...)
		dst.SymbolLevel = src.SymbolLevel
	}
	if len(dst.FixRefs) == 0 && len(src.FixRefs) > 0 {
		dst.FixRefs = append([]string(nil), src.FixRefs...)
	}
	if src.Severity > dst.Severity {
		dst.Severity = src.Severity
	}
	return dst
}

// ─── Ecosystem mapping ──────────────────────────────────────────────────────

// ghsaEcosystemEnum maps anst ecosystem constants to the GitHub GraphQL
// SecurityAdvisoryEcosystem enum values. Ecosystems GHSA does not serve are
// absent, so toGHSAEcosystem reports ok=false for them.
var ghsaEcosystemEnum = map[string]string{
	EcosystemGo:        "GO",
	EcosystemNPM:       "NPM",
	EcosystemPyPI:      "PIP",
	EcosystemMaven:     "MAVEN",
	EcosystemNuGet:     "NUGET",
	EcosystemPackagist: "COMPOSER",
	EcosystemCratesIO:  "RUST",
	EcosystemRubyGems:  "RUBYGEMS",
	EcosystemPub:       "PUB",
	EcosystemHex:       "ERLANG",
	EcosystemSwiftURL:  "SWIFT",
}

// toGHSAEcosystem maps an anst ecosystem constant to its GHSA GraphQL enum value.
// The second return is false when GHSA does not serve the ecosystem, in which
// case Query returns (nil, nil).
func toGHSAEcosystem(ecosystem string) (string, bool) {
	v, ok := ghsaEcosystemEnum[ecosystem]
	return v, ok
}
