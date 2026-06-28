package advisory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Fixture builders ───────────────────────────────────────────────────────

// buildTarGz creates an in-memory gzip-compressed tar archive from the provided
// name→content map. Names are full archive paths (e.g. the GitLab archive root
// wrapper "advisories-community-main/npm/lodash/CVE-2021-1111.yml").
func buildTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// gitlabSampleArchive returns a tar.gz with sample advisories across npm, maven,
// pypi, plus one deliberately-unparseable npm advisory. The archive is wrapped in
// the GitLab standard "<project>-<ref>/" root directory.
func gitlabSampleArchive(t *testing.T) []byte {
	t.Helper()
	const root = "advisories-community-main/"
	return buildTarGz(t, map[string]string{
		root + "npm/lodash/CVE-2021-1111.yml": `---
identifier: CVE-2021-1111
identifiers:
  - CVE-2021-1111
  - GMS-2021-0001
package_slug: npm/lodash
title: Prototype pollution
description: A prototype pollution issue.
affected_range: ">=1.0.0 <1.2.0"
affected_versions: All versions before 1.2.0
fixed_versions:
  - 1.2.0
cwe_ids:
  - CWE-1321
cvss_v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
urls:
  - https://example.com/lodash
uuid: aaaa-bbbb-cccc
pubdate: "2021-01-01"
`,
		root + "maven/org.example/lib/CVE-2021-2222.yml": `---
identifiers:
  - CVE-2021-2222
package_slug: maven/org.example/lib
title: Maven interval advisory
affected_range: "[1.0,1.2)"
fixed_versions:
  - "1.2"
uuid: dddd-eeee
`,
		root + "pypi/some-package/CVE-2021-3333.yml": `---
identifiers:
  - CVE-2021-3333
package_slug: pypi/some-package
title: PyPI advisory
affected_range: ">=1.0.0,<1.2.0"
fixed_versions:
  - 1.2.0
uuid: ffff-0000
`,
		root + "npm/weird/CVE-2021-4444.yml": `---
identifiers:
  - CVE-2021-4444
package_slug: npm/weird
title: Unparseable range advisory
affected_range: "this is not a version range"
uuid: 1111-2222
`,
	})
}

// gitlabTestServer spins an httptest server that mimics the GitLab archive +
// project API endpoints used by GitLabSource.Refresh.
func gitlabTestServer(t *testing.T, tgz []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case r.URL.Path == "/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tgz)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─── Refresh + Query: happy path & contract ─────────────────────────────────

func TestGitLabSource_RefreshAndQuery(t *testing.T) {
	srv := gitlabTestServer(t, gitlabSampleArchive(t))
	src := NewGitLabSource(t.TempDir(),
		WithGitLabBaseURL(srv.URL),
		WithGitLabHTTPClient(srv.Client()))
	ctx := context.Background()

	require.NoError(t, src.Refresh(ctx))

	t.Run("npm in-range match with enrichment", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemNPM, Name: "lodash"}, "1.1.0")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		adv := advs[0]
		assert.Equal(t, "CVE-2021-1111", adv.ID)
		assert.Equal(t, []string{"GMS-2021-0001"}, adv.Aliases)
		assert.Equal(t, []string{SourceGitLab}, adv.Sources)
		assert.Equal(t, EcosystemNPM, adv.Ecosystem)
		assert.False(t, adv.Incomplete)
		assert.Equal(t, []string{"CWE-1321"}, adv.CWEs)
		require.Len(t, adv.CVSS, 1)
		assert.Equal(t, "3.1", adv.CVSS[0].Version)
		assert.Equal(t, SeverityCritical, adv.Severity)
	})

	t.Run("npm out-of-range (at fixed version) not returned", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemNPM, Name: "lodash"}, "1.2.0")
		require.NoError(t, err)
		assert.Empty(t, advs)
	})

	t.Run("maven bracket range match", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "org.example:lib"}, "1.1")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		assert.Equal(t, "CVE-2021-2222", advs[0].ID)
	})

	t.Run("maven bracket range upper bound exclusive", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemMaven, Name: "org.example:lib"}, "1.2")
		require.NoError(t, err)
		assert.Empty(t, advs)
	})

	t.Run("pypi PEP503-normalized name match", func(t *testing.T) {
		// "Some_Package" normalizes to "some-package" to match the directory.
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemPyPI, Name: "Some_Package"}, "1.1.0")
		require.NoError(t, err)
		require.Len(t, advs, 1)
		assert.Equal(t, "CVE-2021-3333", advs[0].ID)
	})

	t.Run("unparseable range returned as undecidable, never dropped", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemNPM, Name: "weird"}, "1.0.0")
		require.NoError(t, err)
		require.Len(t, advs, 1, "unparseable-range advisory must NOT be dropped")
		assert.Equal(t, "CVE-2021-4444", advs[0].ID)
		assert.True(t, advs[0].Incomplete, "unparseable range must surface as Incomplete (UNKNOWN)")
		assert.True(t, advs[0].UndecidableRanges)
	})

	t.Run("unserved ecosystem returns nil,nil", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemHex, Name: "phoenix"}, "1.0.0")
		require.NoError(t, err)
		assert.Nil(t, advs)
	})

	t.Run("unknown package returns nil,nil", func(t *testing.T) {
		advs, err := src.Query(ctx, Package{Ecosystem: EcosystemNPM, Name: "no-such-pkg"}, "1.0.0")
		require.NoError(t, err)
		assert.Nil(t, advs)
	})
}

// TestGitLabSource_OfflineEmptyCache verifies the offline floor contract: with no
// refresh and an empty cache, Query returns (nil,nil) — never an error and never a
// silent claim of clean (the caller marks incomplete for an explicitly-requested
// but uncached source).
func TestGitLabSource_OfflineEmptyCache(t *testing.T) {
	src := NewGitLabSource(t.TempDir())
	advs, err := src.Query(context.Background(),
		Package{Ecosystem: EcosystemNPM, Name: "lodash"}, "1.1.0")
	require.NoError(t, err)
	assert.Nil(t, advs)
}

// TestGitLabSource_RefreshIdempotent verifies the archive is downloaded only once
// when the cache is fresh: a second Refresh with a populated, fresh manifest must
// not re-download.
func TestGitLabSource_RefreshIdempotent(t *testing.T) {
	var downloads int
	tgz := gitlabSampleArchive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/"):
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			downloads++
			_, _ = w.Write(tgz)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	src := NewGitLabSource(t.TempDir(),
		WithGitLabBaseURL(srv.URL),
		WithGitLabHTTPClient(srv.Client()))
	ctx := context.Background()
	require.NoError(t, src.Refresh(ctx))
	require.NoError(t, src.Refresh(ctx))
	assert.Equal(t, 1, downloads, "fresh cache must not be re-downloaded")
}

// ─── affected_range parser ──────────────────────────────────────────────────

func TestParseGitLabRange(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		fixed []string
		want  []VersionRange
		ok    bool
	}{
		{
			name: "ge-lt space AND",
			in:   ">=1.0.0 <1.2.3",
			want: []VersionRange{{Introduced: "1.0.0", Fixed: "1.2.3"}},
			ok:   true,
		},
		{
			name: "ge-lt comma AND",
			in:   ">=1.0.0,<1.2.3",
			want: []VersionRange{{Introduced: "1.0.0", Fixed: "1.2.3"}},
			ok:   true,
		},
		{
			name: "le inclusive upper",
			in:   ">=1.0.0 <=1.2.3",
			want: []VersionRange{{Introduced: "1.0.0", LastAffected: "1.2.3"}},
			ok:   true,
		},
		{
			name: "OR clauses",
			in:   ">=1.0.0 <1.2.0||>=2.0.0 <2.1.0",
			want: []VersionRange{
				{Introduced: "1.0.0", Fixed: "1.2.0"},
				{Introduced: "2.0.0", Fixed: "2.1.0"},
			},
			ok: true,
		},
		{
			name: "exact equals",
			in:   "=1.2.3",
			want: []VersionRange{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
			ok:   true,
		},
		{
			name: "bare exact version",
			in:   "1.2.3",
			want: []VersionRange{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
			ok:   true,
		},
		{
			name: "caret normal",
			in:   "^1.2.3",
			want: []VersionRange{{Introduced: "1.2.3", Fixed: "2.0.0"}},
			ok:   true,
		},
		{
			name: "caret 0.x pins minor",
			in:   "^0.2.3",
			want: []VersionRange{{Introduced: "0.2.3", Fixed: "0.3.0"}},
			ok:   true,
		},
		{
			name: "caret 0.0.x pins patch",
			in:   "^0.0.3",
			want: []VersionRange{{Introduced: "0.0.3", Fixed: "0.0.4"}},
			ok:   true,
		},
		{
			name: "tilde pins minor",
			in:   "~1.2.3",
			want: []VersionRange{{Introduced: "1.2.3", Fixed: "1.3.0"}},
			ok:   true,
		},
		{
			name: "maven bracket exclusive upper",
			in:   "[1.0,2.0)",
			want: []VersionRange{{Introduced: "1.0", Fixed: "2.0"}},
			ok:   true,
		},
		{
			name: "maven open lower inclusive upper",
			in:   "(,1.2]",
			want: []VersionRange{{LastAffected: "1.2"}},
			ok:   true,
		},
		{
			name: "maven open upper",
			in:   "[1.0,]",
			want: []VersionRange{{Introduced: "1.0"}},
			ok:   true,
		},
		{
			name:  "open range corroborated by single fixed version",
			in:    ">=1.0.0",
			fixed: []string{"1.5.0"},
			want:  []VersionRange{{Introduced: "1.0.0", Fixed: "1.5.0"}},
			ok:    true,
		},
		{
			name: "gt treated as inclusive lower (conservative)",
			in:   ">1.0.0",
			want: []VersionRange{{Introduced: "1.0.0"}},
			ok:   true,
		},
		{
			name: "unparseable",
			in:   "this is not a version",
			ok:   false,
		},
		{
			name: "empty",
			in:   "",
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseGitLabRange(tc.in, tc.fixed)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestPEP503Normalize(t *testing.T) {
	cases := map[string]string{
		"Some_Package":   "some-package",
		"Flask":          "flask",
		"zope.interface": "zope-interface",
		"a--b__c":        "a-b-c",
	}
	for in, want := range cases {
		assert.Equal(t, want, pep503Normalize(in), in)
	}
}
