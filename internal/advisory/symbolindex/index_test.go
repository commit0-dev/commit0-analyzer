package symbolindex_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/advisory/symbolindex"
)

// TestIndex_LoadSave_RoundTrip verifies that an index persisted to disk is
// loaded back with identical contents on the next Load call.
func TestIndex_LoadSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	idx := symbolindex.LoadIndex(dir)
	idx.Set("GHSA-0001", []string{"https://github.com/o/r/commit/abc1234"},
		[]advisory.Symbol{{Name: "foo"}, {Name: "bar"}})

	require.NoError(t, idx.Save())

	idx2 := symbolindex.LoadIndex(dir)
	syms, ok := idx2.Get("GHSA-0001", []string{"https://github.com/o/r/commit/abc1234"})
	require.True(t, ok, "entry must be found after reload")
	require.Len(t, syms, 2)
	assert.Equal(t, "foo", syms[0].Name)
	assert.Equal(t, "bar", syms[1].Name)
}

// TestIndex_MissingFile_TreatedAsEmpty verifies that a missing index file
// returns an empty index (not an error).
func TestIndex_MissingFile_TreatedAsEmpty(t *testing.T) {
	dir := t.TempDir()
	// Remove dir entirely to simulate a missing file scenario.
	require.NoError(t, os.RemoveAll(dir))

	idx := symbolindex.LoadIndex(dir)
	_, ok := idx.Get("GHSA-any", []string{"https://github.com/o/r/commit/abc"})
	assert.False(t, ok, "missing index file must return empty (not found)")
}

// TestIndex_CorruptFile_TreatedAsEmpty verifies that a corrupt/invalid index
// file is silently ignored (treated as empty), never panics.
func TestIndex_CorruptFile_TreatedAsEmpty(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "symbol-index.json")
	require.NoError(t, os.WriteFile(indexPath, []byte("not valid json !!!"), 0o644))

	idx := symbolindex.LoadIndex(dir)
	_, ok := idx.Get("GHSA-any", []string{"ref"})
	assert.False(t, ok, "corrupt index must be treated as empty")
}

// TestIndex_Get_StaleFixRefs_ReturnsMiss verifies the staleness guard:
// a cached entry with different FixRefs is treated as a miss.
func TestIndex_Get_StaleFixRefs_ReturnsMiss(t *testing.T) {
	dir := t.TempDir()

	idx := symbolindex.LoadIndex(dir)
	idx.Set("GHSA-stale-test", []string{"https://github.com/o/r/commit/oldsha"},
		[]advisory.Symbol{{Name: "oldSymbol"}})
	require.NoError(t, idx.Save())

	idx2 := symbolindex.LoadIndex(dir)
	_, ok := idx2.Get("GHSA-stale-test", []string{"https://github.com/o/r/commit/newsha"})
	assert.False(t, ok, "changed FixRefs must produce a cache miss (staleness guard)")
}

// TestIndex_Set_EmptySymbols_Persisted verifies that an empty symbol slice is
// persisted so repeat scans don't re-fetch a known-empty advisory.
func TestIndex_Set_EmptySymbols_Persisted(t *testing.T) {
	dir := t.TempDir()

	idx := symbolindex.LoadIndex(dir)
	idx.Set("GHSA-empty", []string{"https://github.com/o/r/commit/abc"},
		[]advisory.Symbol{}) // deliberately empty
	require.NoError(t, idx.Save())

	idx2 := symbolindex.LoadIndex(dir)
	syms, ok := idx2.Get("GHSA-empty", []string{"https://github.com/o/r/commit/abc"})
	assert.True(t, ok, "empty symbol result must be a hit (not a miss)")
	assert.Empty(t, syms, "empty symbol slice must round-trip correctly")
}

// TestIndex_Save_AtomicWrite verifies that saving the index does not leave a
// .tmp file behind on success.
func TestIndex_Save_AtomicWrite(t *testing.T) {
	dir := t.TempDir()

	idx := symbolindex.LoadIndex(dir)
	idx.Set("GHSA-atomic", []string{"ref"}, []advisory.Symbol{{Name: "x"}})
	require.NoError(t, idx.Save())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, filepath.Ext(e.Name()) == ".tmp",
			"no .tmp files should remain after a successful Save")
	}
}
