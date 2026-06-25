package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseOSV_FixRefs verifies that Advisory.FixRefs collects GitHub commit
// URLs regardless of reference type — GHSA records label fix commits "WEB", not
// "FIX" — while non-commit URLs (blog, advisory, PR) are excluded even when
// typed "FIX". Result is sorted and deduplicated.
func TestParseOSV_FixRefs_MixedTypes(t *testing.T) {
	data := loadFixture(t, "GO-fixrefs-test.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// Fixture references: a WEB blog (non-commit), an ADVISORY (non-commit), a
	// WEB-typed commit (bbbb…), a FIX-typed commit (aaaa…), and a FIX-typed PR.
	// FixRefs must contain exactly the two commit URLs, sorted ascending: the
	// WEB-typed commit is captured (type-agnostic) and the FIX-typed PR is
	// dropped (not commit-shaped).
	want := []string{
		"https://github.com/example/fixrefpkg/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"https://github.com/example/fixrefpkg/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	assert.Equal(t, want, adv.FixRefs, "FixRefs should contain commit URLs of any reference type, sorted")
}

// TestParseOSV_FixRefs_NoReferences verifies that a record with no references
// array produces an empty (non-nil) FixRefs slice.
func TestParseOSV_FixRefs_NoReferences(t *testing.T) {
	data := loadFixture(t, "GO-2024-0002.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// GO-2024-0002 has no references block — FixRefs must be empty.
	assert.Empty(t, adv.FixRefs, "FixRefs should be empty when the record has no references")
}

// TestParseOSV_FixRefs_PullRequestExcluded verifies that GO-2024-0001, whose
// only FIX reference is a pull-request URL (not a commit), surfaces no FixRefs:
// a PR cannot be fetched as an immutable commit, so it is not collected.
func TestParseOSV_FixRefs_PullRequestExcluded(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	assert.Empty(t, adv.FixRefs, "a pull-request FIX reference is not a commit URL and must be excluded")
}
