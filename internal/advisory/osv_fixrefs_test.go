package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseOSV_FixRefs verifies that Advisory.FixRefs is populated with the
// URLs from OSV references[] entries whose type is "FIX", sorted and deduplicated,
// while WEB/ADVISORY/other-typed references are excluded.
func TestParseOSV_FixRefs_MixedTypes(t *testing.T) {
	data := loadFixture(t, "GO-fixrefs-test.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	// The fixture has two FIX URLs (aaaa…, bbbb…) plus a WEB and an ADVISORY URL.
	// FixRefs must contain exactly the two FIX URLs, sorted ascending.
	want := []string{
		"https://github.com/example/fixrefpkg/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"https://github.com/example/fixrefpkg/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	assert.Equal(t, want, adv.FixRefs, "FixRefs should contain only FIX-typed URLs, sorted")
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

// TestParseOSV_FixRefs_ExistingFixture verifies that GO-2024-0001 (which has
// one FIX reference) surfaces exactly that URL.
func TestParseOSV_FixRefs_ExistingFixture(t *testing.T) {
	data := loadFixture(t, "GO-2024-0001.json")

	adv, err := parseOSVRecord(data, EcosystemGo)
	require.NoError(t, err)

	want := []string{
		"https://github.com/example/vulnpkg/pull/1",
	}
	assert.Equal(t, want, adv.FixRefs, "FixRefs should contain the single FIX URL from GO-2024-0001")
}
