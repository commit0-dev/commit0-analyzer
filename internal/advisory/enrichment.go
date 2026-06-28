package advisory

import (
	"context"
	"fmt"
	"strings"
)

// Enricher augments a batch of advisories with additional intelligence (CVSS
// detail, EPSS, KEV, CWE, etc.). Implementations mutate the advisories in place.
//
// Failure semantics ("unknown ≠ safe"): an enricher that cannot complete (a
// network, HTTP, rate-limit, or parse failure) returns a non-nil error. The
// caller MUST treat that as incomplete enrichment — never as "no enrichment, so
// clean". A nil return means the enricher ran to completion (which may include
// legitimately finding no signal for a given advisory).
//
// Implementations must be safe to call with partial data: an advisory missing a
// CVE alias, for instance, is simply left untouched rather than erroring.
type Enricher interface {
	// Name returns a stable identifier used in partial-failure reporting.
	Name() string
	// Enrich mutates the given advisories in place. The slice elements are
	// addressable, so implementations set fields via advs[i].Field = ....
	Enrich(ctx context.Context, advs []Advisory) error
}

// EnrichmentIncompleteError is returned by EnrichmentChain.Enrich when one or
// more enrichers fail. Like SourcesIncompleteError, it is NOT fatal: the caller
// should warn per failed enricher and mark the scan incomplete (drives exit 3),
// then proceed with whatever enrichment succeeded.
type EnrichmentIncompleteError struct {
	// FailedEnrichers lists the name of every enricher that returned an error,
	// in execution order.
	FailedEnrichers []string
	// Errors holds the per-enricher errors in the same order as FailedEnrichers.
	Errors []error
}

func (e *EnrichmentIncompleteError) Error() string {
	parts := make([]string, len(e.FailedEnrichers))
	for i, name := range e.FailedEnrichers {
		parts[i] = fmt.Sprintf("%s: %v", name, e.Errors[i])
	}
	return "advisory: one or more enrichers failed: " + strings.Join(parts, "; ")
}

// EnrichmentChain runs a sequence of enrichers over the same advisory batch.
//
// It runs every enricher even if an earlier one fails (a partial failure must
// not suppress the remaining signals), accumulates failures, and returns an
// *EnrichmentIncompleteError when any enricher failed. A chain with no failures
// returns nil. An empty chain is a successful no-op.
type EnrichmentChain []Enricher

// Enrich implements Enricher so chains compose. It mirrors MultiSource.Query's
// partial-failure aggregation.
func (c EnrichmentChain) Enrich(ctx context.Context, advs []Advisory) error {
	var (
		failedNames []string
		failedErrs  []error
	)

	for _, e := range c {
		if err := e.Enrich(ctx, advs); err != nil {
			failedNames = append(failedNames, e.Name())
			failedErrs = append(failedErrs, err)
			// Do not abort: keep running the remaining enrichers.
			continue
		}
	}

	if len(failedNames) > 0 {
		return &EnrichmentIncompleteError{
			FailedEnrichers: failedNames,
			Errors:          failedErrs,
		}
	}
	return nil
}

// Name implements Enricher so an EnrichmentChain can itself be nested in another
// chain. The name reflects that it is a composite.
func (c EnrichmentChain) Name() string { return "enrichment-chain" }
