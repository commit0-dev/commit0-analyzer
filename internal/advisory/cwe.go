package advisory

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

// CWEEnricher normalizes, validates, de-duplicates, and stably sorts the CWE
// identifiers already collected on each advisory by the GHSA/NVD sources. It does
// no network I/O, so it never fails: it is purely a deterministic clean-up pass.
//
// An identifier that is not in the bundled name table is kept (id-only), never
// dropped — dropping a CWE would silently lose weakness context.
type CWEEnricher struct{}

// Name implements Enricher.
func (CWEEnricher) Name() string { return "cwe" }

// Enrich implements Enricher. It rewrites each advisory's CWEs slice to a
// normalized, deduplicated, deterministically ordered form.
func (CWEEnricher) Enrich(_ context.Context, advs []Advisory) error {
	for i := range advs {
		advs[i].CWEs = normalizeCWEs(advs[i].CWEs)
	}
	return nil
}

// normalizeCWEs canonicalizes each id to the "CWE-<n>" form where possible,
// drops empty entries, deduplicates, and sorts. Numeric ids sort ascending by
// their numeric value; any non-numeric residue sorts after, lexicographically.
func normalizeCWEs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	var out []string
	for _, raw := range ids {
		id := canonicalCWE(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(a, b int) bool {
		na, oka := cweNumber(out[a])
		nb, okb := cweNumber(out[b])
		switch {
		case oka && okb:
			if na != nb {
				return na < nb
			}
			return out[a] < out[b]
		case oka != okb:
			// Numeric (well-formed) ids sort before non-numeric residue.
			return oka
		default:
			return out[a] < out[b]
		}
	})
	return out
}

// canonicalCWE normalizes a single raw CWE token. Accepts "CWE-79", "cwe-79",
// "79", or " CWE-79 " and returns "CWE-79". A non-numeric but non-empty token is
// upper-cased and returned as-is (kept, never dropped). Empty → "".
func canonicalCWE(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	up := strings.ToUpper(s)
	digits := up
	if strings.HasPrefix(up, "CWE-") {
		digits = strings.TrimPrefix(up, "CWE-")
	} else if strings.HasPrefix(up, "CWE") {
		digits = strings.TrimPrefix(up, "CWE")
	}
	digits = strings.TrimSpace(digits)
	if digits != "" && isAllDigits(digits) {
		// Drop any leading zeros for a single canonical representation.
		n, err := strconv.Atoi(digits)
		if err == nil {
			return "CWE-" + strconv.Itoa(n)
		}
	}
	// Unrecognized form: keep the upper-cased token rather than dropping it.
	return up
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cweNumber extracts the numeric id from a canonical "CWE-<n>" string.
func cweNumber(id string) (int, bool) {
	if !strings.HasPrefix(id, "CWE-") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "CWE-"))
	if err != nil {
		return 0, false
	}
	return n, true
}

// CWEName returns the human-readable name for a canonical CWE id (e.g. "CWE-79")
// from the bundled static table. The second return is false for ids not in the
// table; callers must keep the id-only form rather than treating absence as an
// error.
func CWEName(id string) (string, bool) {
	name, ok := cweNames[canonicalCWE(id)]
	return name, ok
}
