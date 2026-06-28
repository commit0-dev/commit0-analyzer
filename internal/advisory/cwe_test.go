package advisory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCWEEnricher_NormalizeDedupeSort verifies mixed-form ids are canonicalized,
// deduplicated, and sorted by numeric id ascending.
func TestCWEEnricher_NormalizeDedupeSort(t *testing.T) {
	t.Parallel()
	advs := []Advisory{{
		ID:   "GHSA-x",
		CWEs: []string{"CWE-89", "cwe-79", "79", " CWE-079 ", "CWE-22"},
	}}
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), advs))
	assert.Equal(t, []string{"CWE-22", "CWE-79", "CWE-89"}, advs[0].CWEs)
}

// TestCWEEnricher_UnknownIDKept verifies an id not in the bundled name table is
// kept (id-only), never dropped.
func TestCWEEnricher_UnknownIDKept(t *testing.T) {
	t.Parallel()
	advs := []Advisory{{
		ID:   "GHSA-x",
		CWEs: []string{"CWE-99999", "CWE-79"},
	}}
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), advs))
	assert.Equal(t, []string{"CWE-79", "CWE-99999"}, advs[0].CWEs)
}

// TestCWEEnricher_NonNumericResidueKept verifies a non-canonical token is upper-
// cased and retained, sorted after the numeric ids.
func TestCWEEnricher_NonNumericResidueKept(t *testing.T) {
	t.Parallel()
	advs := []Advisory{{
		ID:   "GHSA-x",
		CWEs: []string{"NVD-CWE-Other", "CWE-79", ""},
	}}
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), advs))
	assert.Equal(t, []string{"CWE-79", "NVD-CWE-OTHER"}, advs[0].CWEs)
}

// TestCWEEnricher_EmptyIsNil verifies no CWEs produces a nil slice (no error).
func TestCWEEnricher_EmptyIsNil(t *testing.T) {
	t.Parallel()
	advs := []Advisory{{ID: "GHSA-x"}}
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), advs))
	assert.Nil(t, advs[0].CWEs)
}

// TestCWEEnricher_Deterministic verifies the same input yields the same ordering
// regardless of input order.
func TestCWEEnricher_Deterministic(t *testing.T) {
	t.Parallel()
	a := []Advisory{{CWEs: []string{"CWE-89", "CWE-22", "CWE-79"}}}
	b := []Advisory{{CWEs: []string{"CWE-79", "CWE-89", "CWE-22"}}}
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), a))
	require.NoError(t, CWEEnricher{}.Enrich(context.Background(), b))
	assert.Equal(t, a[0].CWEs, b[0].CWEs)
}

// TestCWEName verifies the bundled table lookup and the not-found contract.
func TestCWEName(t *testing.T) {
	t.Parallel()
	name, ok := CWEName("CWE-79")
	require.True(t, ok)
	assert.Equal(t, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", name)

	// Normalization is applied before lookup.
	name2, ok2 := CWEName("79")
	require.True(t, ok2)
	assert.Equal(t, name, name2)

	_, ok3 := CWEName("CWE-99999")
	assert.False(t, ok3, "absent id must report not-found, not fabricate a name")
}
