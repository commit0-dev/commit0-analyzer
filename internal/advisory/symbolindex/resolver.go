package symbolindex

import (
	"context"
	"sort"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
	"github.com/ducthinh993/anst-analyzer/internal/advisory/ghfetch"
	"github.com/ducthinh993/anst-analyzer/internal/advisory/symbolextract"
)

// Resolver orchestrates symbol resolution for a single scan: it checks the
// persistent index first, fetches from GitHub when needed, and writes results
// back to the index so repeat scans are network-free.
//
// Any individual fetch or extraction error degrades quietly to "no symbols for
// that ref" — it never aborts the overall scan or marks it incomplete.
type Resolver struct {
	index     *Index
	ghClient  *ghfetch.Client
	pluginBin string
	offline   bool
}

// NewResolver constructs a Resolver backed by the index in cacheDir.
// ghClient and pluginBin are the two external dependencies injected for
// fetching and extracting; offline=true suppresses all network access.
func NewResolver(cacheDir string, ghClient *ghfetch.Client, pluginBin string, offline bool) *Resolver {
	return &Resolver{
		index:     LoadIndex(cacheDir),
		ghClient:  ghClient,
		pluginBin: pluginBin,
		offline:   offline,
	}
}

// Resolve returns the resolved vulnerable symbols for adv.
//
// Decision tree:
//  1. Index hit (same FixRefs) → return cached symbols immediately.
//  2. offline=true + miss → return whatever the index has (empty if not cached).
//  3. online: for each FixRef, ghfetch.FetchFix → symbolextract.Extract.
//     Errors from either step degrade to "no symbols for that ref" (quiet).
//     The aggregate result (possibly empty) is persisted to the index.
//
// The caller must never treat an empty return as an error or scan incompleteness;
// it simply means symbol-level data is unavailable and the finding stays at
// PACKAGE_REACHABLE confidence.
func (r *Resolver) Resolve(ctx context.Context, adv *advisory.Advisory) []advisory.Symbol {
	if len(adv.FixRefs) == 0 {
		return nil
	}

	// Index hit: same FixRefs → return cached result immediately (no network).
	if syms, ok := r.index.Get(adv.ID, adv.FixRefs); ok {
		return nilToEmpty(syms)
	}

	// Offline miss: return empty; never fetch.
	if r.offline {
		return nil
	}

	// Online: fetch and extract symbols from each FixRef.
	seen := make(map[string]bool)
	var aggregate []advisory.Symbol

	for _, ref := range adv.FixRefs {
		fix, err := r.ghClient.FetchFix(ctx, ref)
		if err != nil || fix == nil {
			// Degrade quietly: unsupported URL, non-200, network error → skip.
			continue
		}

		syms, err := symbolextract.Extract(ctx, r.pluginBin, fix.Patch, fix.Files)
		if err != nil {
			// Degrade quietly: plugin error → skip this ref.
			continue
		}

		for _, s := range syms {
			if !seen[s.Name] {
				seen[s.Name] = true
				aggregate = append(aggregate, s)
			}
		}
	}

	// Sort for determinism.
	sort.Slice(aggregate, func(i, j int) bool {
		return aggregate[i].Name < aggregate[j].Name
	})

	// Persist even when empty so we don't refetch a known-dead advisory.
	// Save failure is intentionally swallowed: the next scan simply re-fetches.
	r.index.Set(adv.ID, adv.FixRefs, aggregate)
	_ = r.index.Save()

	return nilToEmpty(aggregate)
}

// nilToEmpty converts nil to an empty slice so callers can safely range over
// the result. A cached empty entry ([]Symbol{}) round-trips as non-nil but
// length-0; this helper normalises both to empty-but-non-nil when non-empty.
func nilToEmpty(syms []advisory.Symbol) []advisory.Symbol {
	if syms == nil {
		return []advisory.Symbol{}
	}
	return syms
}
