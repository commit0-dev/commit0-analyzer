// Package symbolindex provides a persistent cache of advisory → resolved symbol
// mappings so the symbol-fetch network roundtrip is paid once per advisory and
// subsequent scans are served from disk.
//
// Soundness contract (matches the broader pipeline rule):
// Symbol data is a precision enhancement; its absence is never an error. Load
// and Save therefore never return hard errors to callers — a missing or corrupt
// index file is treated as an empty index and the caller falls back to a fresh
// fetch.
package symbolindex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

const indexFileName = "symbol-index.json"

// indexEntry is the JSON-persisted shape for a single advisory's resolved data.
type indexEntry struct {
	// FixRefs is the sorted, joined FixRefs slice this entry was derived from.
	// It is used as the staleness key: if the advisory's current FixRefs differ,
	// the entry is treated as a miss and re-resolved.
	FixRefsKey string            `json:"fixRefsKey"`
	Symbols    []advisory.Symbol `json:"symbols"`
}

// Index is an in-memory map from advisory ID to its resolved symbols, backed
// by a single JSON file on disk. The zero value is not valid; use LoadIndex.
type Index struct {
	dir     string
	entries map[string]indexEntry // keyed by advisory ID
}

// LoadIndex reads the persisted index from dir. On any error (missing file,
// corrupt JSON) it returns an empty index — callers must not treat a load
// failure as fatal, because symbol data is optional.
func LoadIndex(dir string) *Index {
	idx := &Index{
		dir:     dir,
		entries: make(map[string]indexEntry),
	}

	data, err := os.ReadFile(filepath.Join(dir, indexFileName))
	if err != nil {
		return idx // missing file → empty index (not an error)
	}

	var raw map[string]indexEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return idx // corrupt file → empty index (not an error)
	}
	idx.entries = raw
	return idx
}

// fixRefsKey converts a FixRefs slice to a deterministic string key.
// The slice is sorted before joining so two slices with the same elements
// in different order produce the same key.
func fixRefsKey(fixRefs []string) string {
	cp := append([]string(nil), fixRefs...)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

// Get returns the cached symbols for the advisory identified by id, when the
// cached entry's FixRefs match the given fixRefs exactly (staleness guard).
// ok is false on a miss (unknown id, empty index, or changed FixRefs).
func (idx *Index) Get(id string, fixRefs []string) ([]advisory.Symbol, bool) {
	e, found := idx.entries[id]
	if !found {
		return nil, false
	}
	if e.FixRefsKey != fixRefsKey(fixRefs) {
		return nil, false // stale — FixRefs changed
	}
	return e.Symbols, true
}

// Set stores a resolved symbol list for the advisory id, keyed by fixRefs.
// An empty symbol slice is a valid entry (means "fetched but found nothing"),
// so subsequent scans don't refetch a known-empty advisory.
func (idx *Index) Set(id string, fixRefs []string, syms []advisory.Symbol) {
	stored := make([]advisory.Symbol, len(syms))
	copy(stored, syms)
	idx.entries[id] = indexEntry{
		FixRefsKey: fixRefsKey(fixRefs),
		Symbols:    stored,
	}
}

// Save atomically writes the index to {dir}/{indexFileName}.
// It returns the underlying error if the write fails; the resolver deliberately
// swallows it, because a missing or partially-written index simply causes the
// next scan to re-fetch, which is safe (and sound). The error is returned rather
// than hidden so callers that care (e.g. a debug path) can observe it.
func (idx *Index) Save() error {
	if err := os.MkdirAll(idx.dir, 0o755); err != nil {
		return err
	}

	data, err := json.Marshal(idx.entries)
	if err != nil {
		return err
	}

	dest := filepath.Join(idx.dir, indexFileName)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
