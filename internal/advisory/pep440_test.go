package advisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParsePEP440 covers valid and invalid PEP 440 version strings.
func TestParsePEP440(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantErr bool
		// Expected fields when wantErr is false.
		epoch int
		pre   *pep440PreRelease
		post  int // -1 = not set
		dev   int // -1 = not set
		local string
	}{
		// ── Simple numeric ────────────────────────────────────────────────────
		{name: "simple_1.0", input: "1.0", epoch: 0, post: -1, dev: -1},
		{name: "simple_1.0.0", input: "1.0.0", epoch: 0, post: -1, dev: -1},
		{name: "simple_0", input: "0", epoch: 0, post: -1, dev: -1},
		{name: "many_parts", input: "1.2.3.4.5", epoch: 0, post: -1, dev: -1},

		// ── Epoch ─────────────────────────────────────────────────────────────
		{name: "epoch_1", input: "1!1.0", epoch: 1, post: -1, dev: -1},
		{name: "epoch_2", input: "2!3.4.5", epoch: 2, post: -1, dev: -1},
		{name: "epoch_0_explicit", input: "0!1.0", epoch: 0, post: -1, dev: -1},

		// ── Pre-release ───────────────────────────────────────────────────────
		{name: "alpha_1", input: "1.0a1", pre: &pep440PreRelease{Kind: "a", N: 1}, post: -1, dev: -1},
		{name: "beta_2", input: "1.0b2", pre: &pep440PreRelease{Kind: "b", N: 2}, post: -1, dev: -1},
		{name: "rc_1", input: "1.0rc1", pre: &pep440PreRelease{Kind: "rc", N: 1}, post: -1, dev: -1},
		// PEP 440 canonical aliases
		{name: "alpha_dot", input: "1.0.a1", pre: &pep440PreRelease{Kind: "a", N: 1}, post: -1, dev: -1},
		{name: "preview_alias", input: "1.0preview1", pre: &pep440PreRelease{Kind: "rc", N: 1}, post: -1, dev: -1},
		{name: "c_alias", input: "1.0c1", pre: &pep440PreRelease{Kind: "rc", N: 1}, post: -1, dev: -1},
		// pre-release with dash separator
		{name: "alpha_dash", input: "1.0-alpha1", pre: &pep440PreRelease{Kind: "a", N: 1}, post: -1, dev: -1},
		// pre-release with underscore separator
		{name: "alpha_under", input: "1.0_a1", pre: &pep440PreRelease{Kind: "a", N: 1}, post: -1, dev: -1},

		// ── Post-release ──────────────────────────────────────────────────────
		{name: "post_1", input: "1.0.post1", post: 1, dev: -1},
		{name: "post_0", input: "1.0.post0", post: 0, dev: -1},
		// implicit post (dash form)
		{name: "post_dash", input: "1.0-1", post: 1, dev: -1},

		// ── Dev release ───────────────────────────────────────────────────────
		{name: "dev_0", input: "1.0.dev0", dev: 0, post: -1},
		{name: "dev_1", input: "1.0.dev1", dev: 1, post: -1},

		// ── Local version segment ─────────────────────────────────────────────
		{name: "local", input: "1.0+local.1", local: "local.1", post: -1, dev: -1},
		{name: "local_build", input: "1.0+ubuntu-1", local: "ubuntu-1", post: -1, dev: -1},

		// ── Combined ─────────────────────────────────────────────────────────
		{name: "epoch_pre_dev", input: "1!2.0a1.dev1", epoch: 1, pre: &pep440PreRelease{Kind: "a", N: 1}, dev: 1, post: -1},
		{name: "post_dev", input: "1.0.post1.dev0", post: 1, dev: 0},

		// ── PEP 440 Appendix B: leading "v" is accepted ───────────────────────
		// PEP 440 Appendix B explicitly allows a single leading "v" or "V" (case-insensitive).
		// canonical() in osv.go prepends "v" to every non-"v" version string, so
		// parsePEP440 must accept "v2.28.0" as equivalent to "2.28.0".
		{name: "v_prefix_simple", input: "v1.0", epoch: 0, post: -1, dev: -1},
		{name: "v_prefix_three_parts", input: "v2.28.0", epoch: 0, post: -1, dev: -1},
		{name: "V_prefix_upper", input: "V1.2.3", epoch: 0, post: -1, dev: -1},
		{name: "v_prefix_with_pre", input: "v1.0a1", pre: &pep440PreRelease{Kind: "a", N: 1}, post: -1, dev: -1},

		// ── PEP 440 Appendix B: surrounding whitespace is stripped ────────────
		{name: "leading_space", input: "  1.0", epoch: 0, post: -1, dev: -1},
		{name: "trailing_space", input: "1.0  ", epoch: 0, post: -1, dev: -1},
		{name: "both_spaces", input: "  1.0  ", epoch: 0, post: -1, dev: -1},

		// ── Invalid / unparseable ─────────────────────────────────────────────
		{name: "empty", input: "", wantErr: true},
		{name: "text_only", input: "notaversion", wantErr: true},
		{name: "negative_epoch", input: "-1!1.0", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := parsePEP440(tc.input)
			if tc.wantErr {
				assert.Error(t, err, "expected parse error for %q", tc.input)
				return
			}
			require.NoError(t, err, "unexpected parse error for %q", tc.input)
			assert.Equal(t, tc.epoch, v.Epoch, "epoch mismatch")
			if tc.pre == nil {
				assert.Nil(t, v.Pre, "expected no pre-release segment")
			} else {
				require.NotNil(t, v.Pre, "expected pre-release segment")
				assert.Equal(t, tc.pre.Kind, v.Pre.Kind, "pre-release kind mismatch")
				assert.Equal(t, tc.pre.N, v.Pre.N, "pre-release number mismatch")
			}
			assert.Equal(t, tc.post, v.Post, "post mismatch")
			assert.Equal(t, tc.dev, v.Dev, "dev mismatch")
			assert.Equal(t, tc.local, v.Local, "local mismatch")
		})
	}
}

// TestPEP440Compare covers the ordering semantics from PEP 440 §7.
func TestPEP440Compare(t *testing.T) {
	t.Parallel()

	// lessThan returns true when a < b per PEP 440 ordering.
	lessThan := func(a, b string) bool {
		va, err := parsePEP440(a)
		require.NoError(t, err, "parsePEP440(%q)", a)
		vb, err := parsePEP440(b)
		require.NoError(t, err, "parsePEP440(%q)", b)
		return va.compare(vb) < 0
	}
	equal := func(a, b string) bool {
		va, err := parsePEP440(a)
		require.NoError(t, err, "parsePEP440(%q)", a)
		vb, err := parsePEP440(b)
		require.NoError(t, err, "parsePEP440(%q)", b)
		return va.compare(vb) == 0
	}

	// ── Basic numeric ordering ────────────────────────────────────────────────
	assert.True(t, lessThan("1.0", "2.0"))
	assert.True(t, lessThan("1.0", "1.1"))
	assert.True(t, lessThan("1.0", "1.0.1"))
	assert.False(t, lessThan("2.0", "1.0"))
	assert.True(t, equal("1.0", "1.0.0"))
	assert.True(t, equal("1.0.0", "1.0.0.0"))

	// ── Pre-release ordering (dev < alpha < beta < rc < final) ───────────────
	assert.True(t, lessThan("1.0.dev1", "1.0a1"))
	assert.True(t, lessThan("1.0a1", "1.0b1"))
	assert.True(t, lessThan("1.0b1", "1.0rc1"))
	assert.True(t, lessThan("1.0rc1", "1.0"))
	assert.True(t, lessThan("1.0a1", "1.0a2"))
	assert.True(t, lessThan("1.0b1", "1.0rc1"))

	// ── Post-release ordering (post beats final) ──────────────────────────────
	assert.True(t, lessThan("1.0", "1.0.post1"))
	assert.True(t, lessThan("1.0.post1", "1.0.post2"))

	// ── Epoch dominates ───────────────────────────────────────────────────────
	// epoch=1 beats any epoch=0 version no matter how large
	assert.True(t, lessThan("99.0", "1!1.0"))
	assert.True(t, lessThan("1!1.0", "2!1.0"))

	// ── Dev on post-release ───────────────────────────────────────────────────
	assert.True(t, lessThan("1.0.post1.dev0", "1.0.post1"))

	// ── Local versions sort after public, but not comparable cross-local ──────
	// Local version > public version of same release.
	assert.True(t, lessThan("1.0", "1.0+local.1"))
}

// TestPEP440VersionInRangeV covers the tri-state comparator that feeds
// AffectsVersionV for EcosystemPyPI advisories.
func TestPEP440VersionInRangeV(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		version    string
		introduced string
		fixed      string
		lastAff    string
		want       VersionVerdict
	}{
		// ── Spec golden cases from the deep-dive ─────────────────────────────
		// "1.0" in ["0", "2.0"]: true (inclusive start)
		{name: "spec_in_range", version: "1.0", introduced: "0", fixed: "2.0", want: VersionAffected},
		// "1.0a1" in ["0", "1.0"]: true (pre-release is before final)
		{name: "spec_prerelease_before_final", version: "1.0a1", introduced: "0", fixed: "1.0", want: VersionAffected},
		// "1.0.post1" in ["0", "1.0"]: false (post comes after 1.0; exclusive end)
		{name: "spec_post_after_fixed", version: "1.0.post1", introduced: "0", fixed: "1.0", want: VersionNotAffected},
		// "1.0" in ["0", "1.0"]: false (exclusive end)
		{name: "spec_at_fixed_exclusive", version: "1.0", introduced: "0", fixed: "1.0", want: VersionNotAffected},
		// "1.0.1" in ["0", "1.0"]: false (above range)
		{name: "spec_above_range", version: "1.0.1", introduced: "0", fixed: "1.0", want: VersionNotAffected},
		// "1!1.0" vs ["0", "2.0"]: epoch 1 > epoch 0 means 1!1.0 >= 0!2.0 → NOT affected.
		// The deep-dive spec example "true (epoch 1 > epoch 0)" is incorrect: a higher
		// epoch means the version is ABOVE the epoch-0 range, not inside it.
		{name: "spec_epoch_1_above_epoch0_range", version: "1!1.0", introduced: "0", fixed: "2.0", want: VersionNotAffected},
		// Epoch-1 version IS affected by an epoch-1 range.
		{name: "epoch_1_in_epoch1_range", version: "1!1.0", introduced: "1!0", fixed: "1!2.0", want: VersionAffected},

		// ── Boundary: introduced inclusive ───────────────────────────────────
		{name: "at_introduced", version: "1.0", introduced: "1.0", fixed: "2.0", want: VersionAffected},
		{name: "before_introduced", version: "0.9", introduced: "1.0", fixed: "2.0", want: VersionNotAffected},

		// ── Open upper bound (unfixed) ────────────────────────────────────────
		{name: "unfixed_high", version: "99.0", introduced: "1.0", fixed: "", want: VersionAffected},
		{name: "unfixed_at_intro", version: "1.0", introduced: "1.0", fixed: "", want: VersionAffected},
		{name: "unfixed_before_intro", version: "0.9", introduced: "1.0", fixed: "", want: VersionNotAffected},

		// ── Open lower bound ─────────────────────────────────────────────────
		{name: "no_lower_low", version: "0.0.1", introduced: "", fixed: "1.0", want: VersionAffected},
		{name: "no_lower_at_fixed", version: "1.0", introduced: "", fixed: "1.0", want: VersionNotAffected},

		// ── Both bounds empty ─────────────────────────────────────────────────
		{name: "both_empty", version: "1.2.3", introduced: "", fixed: "", want: VersionAffected},

		// ── LastAffected (inclusive upper) ────────────────────────────────────
		{name: "last_at_bound", version: "1.0", introduced: "", fixed: "", lastAff: "1.0", want: VersionAffected},
		{name: "last_above_bound", version: "1.1", introduced: "", fixed: "", lastAff: "1.0", want: VersionNotAffected},

		// ── PEP 440 pre/post/dev semantics ────────────────────────────────────
		// dev releases sort before everything else for their release
		{name: "dev_before_range", version: "1.0.dev1", introduced: "1.0", fixed: "2.0", want: VersionNotAffected},
		// post-release is after the release
		{name: "post_above_fixed", version: "1.0.post1", introduced: "0", fixed: "1.0", want: VersionNotAffected},

		// ── Parse errors → VersionUndecidable ────────────────────────────────
		{name: "empty_version", version: "", introduced: "", fixed: "1.0", want: VersionUndecidable},
		{name: "garbage_version", version: "notaversion", introduced: "0", fixed: "1.0", want: VersionUndecidable},
		{name: "garbage_introduced", version: "1.0", introduced: "notaversion", fixed: "1.0", want: VersionUndecidable},
		{name: "garbage_fixed", version: "1.0", introduced: "0", fixed: "notaversion", want: VersionUndecidable},

		// ── v-prefix pass-through (canonical() prepends "v") ─────────────────
		// canonical() in osv.go prepends a "v" to every non-"v" version string.
		// pep440VersionInRangeV must accept the resulting "v2.28.0" and produce
		// the correct verdict rather than VersionUndecidable.
		{name: "v_prefix_affected", version: "v2.28.0", introduced: "0", fixed: "2.28.2", want: VersionAffected},
		{name: "v_prefix_not_affected", version: "v2.28.2", introduced: "0", fixed: "2.28.2", want: VersionNotAffected},
		{name: "v_prefix_above_range", version: "v3.0.0", introduced: "0", fixed: "2.28.2", want: VersionNotAffected},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := VersionRange{
				Introduced:   tc.introduced,
				Fixed:        tc.fixed,
				LastAffected: tc.lastAff,
			}
			got := pep440VersionInRangeV(tc.version, r)
			assert.Equal(t, tc.want, got, "pep440VersionInRangeV(%q, %+v)", tc.version, r)
		})
	}
}

// TestAffectsVersionV_PyPI verifies that AffectsVersionV on a PyPI advisory
// routes to the PEP 440 comparator and that parse errors return VersionUndecidable
// (never VersionNotAffected).
func TestAffectsVersionV_PyPI(t *testing.T) {
	t.Parallel()

	pypi := func(introduced, fixed string) *Advisory {
		return &Advisory{
			Ecosystem: EcosystemPyPI,
			VersionRanges: []VersionRange{
				{Introduced: introduced, Fixed: fixed},
			},
		}
	}

	// Real-world pattern: OSV PyPI "0" as introduced sentinel (PEP 440 "0" is valid).
	adv := pypi("0", "2.28.2")
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("2.28.0"))
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("2.28.1"))
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("2.28.2"))
	assert.Equal(t, VersionNotAffected, adv.AffectsVersionV("3.0"))

	// Pre-release of the fix is still affected.
	assert.Equal(t, VersionAffected, adv.AffectsVersionV("2.28.2a1"))

	// Parse error → Undecidable, NEVER NotAffected.
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV(""))
	assert.Equal(t, VersionUndecidable, adv.AffectsVersionV("garbage"))

	// Epoch-bearing version (epoch 1) is ABOVE any epoch-0 range → NotAffected.
	// epoch 1 > epoch 0, so 1!1.0 >= 0!2.0 (the fixed bound), meaning it's outside [0, 2.0).
	adv2 := pypi("0", "2.0")
	assert.Equal(t, VersionNotAffected, adv2.AffectsVersionV("1!1.0"))

	// Celery-like range: 0 → 5.0.2.
	celery := pypi("0", "5.0.2")
	assert.Equal(t, VersionAffected, celery.AffectsVersionV("5.0.1"))
	assert.Equal(t, VersionAffected, celery.AffectsVersionV("0.2"))
	assert.Equal(t, VersionNotAffected, celery.AffectsVersionV("5.0.2"))
	assert.Equal(t, VersionNotAffected, celery.AffectsVersionV("5.1.0"))
}

// TestDirSource_Query_PyPI_CanonicalSeam is an integration test that exercises
// the full ingestion path from dirSource.query through canonical() to the PEP 440
// comparator.  canonical() prepends "v" to any non-"v" version; the comparator
// must accept "v2.28.0" and return VersionAffected (not VersionUndecidable).
//
// This test covers the seam that pep440_test unit tests bypass by calling
// pep440VersionInRangeV directly with clean versions.
func TestDirSource_Query_PyPI_CanonicalSeam(t *testing.T) {
	t.Parallel()

	// Minimal OSV advisory for a PyPI package: "requests" vulnerable in [0, 2.28.2).
	// Note: real PyPI advisories use "ECOSYSTEM" range type, but parseOSVRecord
	// currently only extracts "SEMVER" ranges. Using SEMVER here is sufficient to
	// exercise the canonical() → pep440VersionInRangeV seam: AffectsVersionV routes
	// by Ecosystem (PyPI → PEP 440), not by the range type stored in the advisory.
	rawJSON := []byte(`{
		"id": "PYPI-CANONICAL-SEAM-0001",
		"affected": [{
			"package": {"ecosystem": "PyPI", "name": "requests"},
			"ranges": [{
				"type": "SEMVER",
				"events": [{"introduced": "0"}, {"fixed": "2.28.2"}]
			}]
		}]
	}`)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "PYPI-CANONICAL-SEAM-0001.json"), rawJSON, 0o644))

	ds := &dirSource{dir: dir, sources: []string{"test-source"}}
	ctx := context.Background()
	pkg := Package{Ecosystem: EcosystemPyPI, Name: "requests"}

	// "2.28.0" is in [0, 2.28.2) → must be Affected, Incomplete=false.
	// canonical() turns "2.28.0" into "v2.28.0" before it reaches AffectsVersionV.
	results, err := ds.query(ctx, pkg, "2.28.0")
	require.NoError(t, err)
	require.Len(t, results, 1, "2.28.0 must match PyPI advisory [0, 2.28.2)")
	assert.False(t, results[0].Incomplete, "affected version must not be marked Incomplete")

	// "2.28.2" is the fixed version (exclusive upper bound) → must not match.
	results, err = ds.query(ctx, pkg, "2.28.2")
	require.NoError(t, err)
	assert.Empty(t, results, "2.28.2 (fixed) must not match")

	// "3.0.0" is above the range → must not match.
	results, err = ds.query(ctx, pkg, "3.0.0")
	require.NoError(t, err)
	assert.Empty(t, results, "3.0.0 (above range) must not match")
}
