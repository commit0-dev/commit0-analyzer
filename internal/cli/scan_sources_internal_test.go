package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStderr redirects os.Stderr for the duration of fn and returns whatever
// was written to it. Used to assert the warn-and-degrade behavior of
// runEnrichment without coupling tests to an exit code.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	_ = w.Close()
	os.Stderr = orig
	data, readErr := io.ReadAll(r)
	require.NoError(t, readErr)
	return string(data)
}

// TestParseSourceFlag_KnownTokens verifies every accepted token (short, full,
// and the new ghsa/nvd/nvd-cpe tokens) maps to its canonical source name.
func TestParseSourceFlag_KnownTokens(t *testing.T) {
	cases := []struct {
		flag string
		want map[string]bool
	}{
		{"go-vuln-db", map[string]bool{advisory.SourceGoVulnDB: true}},
		{"osv", map[string]bool{advisory.SourceOSV: true}},
		{"osv.dev", map[string]bool{advisory.SourceOSV: true}},
		{"ghsa", map[string]bool{advisory.SourceGHSA: true}},
		{"gitlab", map[string]bool{advisory.SourceGitLab: true}},
		{"nvd", map[string]bool{advisory.SourceNVD: true}},
		{"nvd-cpe", map[string]bool{advisory.SourceNVDCPE: true}},
		{"epss", map[string]bool{advisory.SourceEPSS: true}},
		{
			defaultSourceFlag,
			map[string]bool{
				advisory.SourceGoVulnDB: true,
				advisory.SourceOSV:      true,
				advisory.SourceGHSA:     true,
				advisory.SourceGitLab:   true,
			},
		},
		{
			"go-vuln-db,osv,ghsa,nvd,nvd-cpe,epss",
			map[string]bool{
				advisory.SourceGoVulnDB: true,
				advisory.SourceOSV:      true,
				advisory.SourceGHSA:     true,
				advisory.SourceNVD:      true,
				advisory.SourceNVDCPE:   true,
				advisory.SourceEPSS:     true,
			},
		},
		// Whitespace + duplicate tolerance.
		{" osv , osv ", map[string]bool{advisory.SourceOSV: true}},
	}
	for _, tc := range cases {
		got, err := parseSourceFlag(tc.flag)
		require.NoError(t, err, "flag %q must parse", tc.flag)
		assert.Equal(t, tc.want, got, "flag %q", tc.flag)
	}
}

// TestParseSourceFlag_DefaultIncludesGHSA pins the default source set so a
// regression that drops GHSA or GitLab from the default is caught.
func TestParseSourceFlag_DefaultIncludesGHSA(t *testing.T) {
	assert.Equal(t, "go-vuln-db,osv,ghsa,gitlab", defaultSourceFlag)
	got, err := parseSourceFlag(defaultSourceFlag)
	require.NoError(t, err)
	assert.True(t, got[advisory.SourceGHSA], "GHSA must be in the default source set")
	assert.True(t, got[advisory.SourceGitLab], "GitLab must be in the default source set")
	assert.False(t, got[advisory.SourceNVD], "NVD enrichment must be opt-in, not default")
	assert.False(t, got[advisory.SourceNVDCPE], "NVD-CPE must be opt-in, not default")
	assert.False(t, got[advisory.SourceEPSS], "EPSS enrichment must be opt-in, not default")
}

// TestParseSourceFlag_BadTokens verifies unknown tokens and an all-empty flag are
// rejected (the error path drives exit 3, never a silent clean).
func TestParseSourceFlag_BadTokens(t *testing.T) {
	bad := []string{"snyk", "nvdcpe", "GHSA", "ghsa,bogus", ""}
	for _, flag := range bad {
		_, err := parseSourceFlag(flag)
		assert.Error(t, err, "flag %q must be rejected", flag)
	}
}

// TestBuildEnrichmentChain_DefaultIsCWEAndKEV verifies that with the default
// source set (no nvd/epss tokens) only the local CWE normalizer and the CISA KEV
// join run. KEV + CWE are always-on prioritization metadata; the rate-limited NVD
// enricher and heavy EPSS enricher are opt-in so a default scan stays fast.
func TestBuildEnrichmentChain_DefaultIsCWEAndKEV(t *testing.T) {
	dir := t.TempDir()

	chain := buildEnrichmentChain(dir, true, map[string]bool{advisory.SourceGHSA: true})
	require.Len(t, chain, 2, "default chain must be exactly CWE + KEV")

	got := []string{chain[0].Name(), chain[1].Name()}
	assert.Equal(t, []string{"cwe", "kev"}, got,
		"default chain order must be deterministic: cwe, kev")
}

// TestBuildEnrichmentChain_OptInNVDAndEPSS verifies the rate-limited NVD enricher
// and the heavy EPSS enricher attach only when their --source token is selected,
// preserving the fixed order cwe, kev, nvd, epss.
func TestBuildEnrichmentChain_OptInNVDAndEPSS(t *testing.T) {
	dir := t.TempDir()

	// NVD only.
	chain := buildEnrichmentChain(dir, true, map[string]bool{advisory.SourceNVD: true})
	require.Len(t, chain, 3, "cwe + kev + nvd when only nvd is selected")
	assert.Equal(t, []string{"cwe", "kev", advisory.SourceNVD},
		[]string{chain[0].Name(), chain[1].Name(), chain[2].Name()})

	// EPSS only.
	chain = buildEnrichmentChain(dir, true, map[string]bool{advisory.SourceEPSS: true})
	require.Len(t, chain, 3, "cwe + kev + epss when only epss is selected")
	assert.Equal(t, []string{"cwe", "kev", advisory.SourceEPSS},
		[]string{chain[0].Name(), chain[1].Name(), chain[2].Name()})

	// Both opted in → full deterministic order.
	chain = buildEnrichmentChain(dir, true, map[string]bool{
		advisory.SourceNVD:  true,
		advisory.SourceEPSS: true,
	})
	require.Len(t, chain, 4, "cwe + kev + nvd + epss when both are selected")
	assert.Equal(t, []string{"cwe", "kev", advisory.SourceNVD, advisory.SourceEPSS},
		[]string{chain[0].Name(), chain[1].Name(), chain[2].Name(), chain[3].Name()},
		"chain order must be deterministic: cwe, kev, nvd, epss")
}

// failingEnricher always errors, to exercise the degrade path in runEnrichment.
type failingEnricher struct{ name string }

func (f failingEnricher) Name() string { return f.name }
func (f failingEnricher) Enrich(_ context.Context, _ []advisory.Advisory) error {
	return errors.New("synthetic enricher failure")
}

// passingEnricher always succeeds, to prove a healthy chain warns nothing.
type passingEnricher struct{ name string }

func (p passingEnricher) Name() string                                          { return p.name }
func (p passingEnricher) Enrich(_ context.Context, _ []advisory.Advisory) error { return nil }

// TestRunEnrichment_FailureDegradesNotIncomplete verifies a failing enricher
// warns to stderr and degrades. Because runEnrichment has no incomplete signal
// and every call site invokes it as a plain statement, an enrichment failure can
// never mark the scan incomplete or change the exit code — enrichment is
// prioritization metadata, not vulnerability coverage. An empty chain or empty
// advisory slice is a silent no-op.
func TestRunEnrichment_FailureDegradesNotIncomplete(t *testing.T) {
	advs := []advisory.Advisory{{ID: "GHSA-x", Aliases: []string{"CVE-2024-0001"}}}
	chain := advisory.EnrichmentChain{failingEnricher{name: "nvd"}}

	stderr := captureStderr(t, func() {
		runEnrichment(context.Background(), chain, advs, "pkg@1.0.0")
	})
	assert.Contains(t, stderr, `advisory enricher "nvd"`,
		"a failing enricher must warn to stderr (degrade)")

	assert.Empty(t, captureStderr(t, func() {
		runEnrichment(context.Background(), nil, advs, "pkg@1.0.0")
	}), "an empty chain must be a silent no-op")

	assert.Empty(t, captureStderr(t, func() {
		runEnrichment(context.Background(), chain, nil, "pkg@1.0.0")
	}), "no advisories must be a silent no-op")
}

// TestRunEnrichment_SuccessIsSilent verifies a chain that succeeds emits no
// warning.
func TestRunEnrichment_SuccessIsSilent(t *testing.T) {
	advs := []advisory.Advisory{{ID: "GHSA-y", Aliases: []string{"CVE-2024-0002"}}}
	chain := advisory.EnrichmentChain{passingEnricher{name: "epss"}}

	assert.Empty(t, captureStderr(t, func() {
		runEnrichment(context.Background(), chain, advs, "pkg@1.0.0")
	}), "a succeeding chain must not warn")
}

// TestAppendSecondarySources_Selection verifies GHSA attaches by default and
// NVD-CPE only when opted in, each with its trust tier.
func TestAppendSecondarySources_Selection(t *testing.T) {
	dir := t.TempDir()

	// Default-style selection (ghsa on, nvd-cpe off).
	got := appendSecondarySources(nil, map[string]bool{advisory.SourceGHSA: true}, dir, true)
	require.Len(t, got, 1)
	assert.Equal(t, advisory.SourceGHSA, got[0].Name)
	assert.Equal(t, trustGHSA, got[0].Trust)

	// Opt-in nvd-cpe added on top of ghsa.
	got = appendSecondarySources(nil, map[string]bool{advisory.SourceGHSA: true, advisory.SourceNVDCPE: true}, dir, true)
	require.Len(t, got, 2)
	names := []string{got[0].Name, got[1].Name}
	assert.ElementsMatch(t, []string{advisory.SourceGHSA, advisory.SourceNVDCPE}, names)

	// Neither selected → nothing appended.
	got = appendSecondarySources(nil, map[string]bool{advisory.SourceOSV: true}, dir, true)
	assert.Empty(t, got)
}

// TestSourceTrustOrdering pins the trust hierarchy: symbol-curated Go-DB > GHSA >
// OSV > opt-in NVD-CPE, with 0 reserved for unset.
func TestSourceTrustOrdering(t *testing.T) {
	assert.Greater(t, trustGoVulnDB, trustGHSA)
	assert.Greater(t, trustGHSA, trustOSV)
	assert.Greater(t, trustOSV, trustNVDCPE)
	assert.Greater(t, trustNVDCPE, 0, "lowest tier must still be above the unset zero value")
}
