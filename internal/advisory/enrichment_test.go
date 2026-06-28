package advisory

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEnricher is a test Enricher that either mutates advisories or fails.
type fakeEnricher struct {
	name    string
	err     error
	applied bool
	mutate  func(advs []Advisory)
}

func (f *fakeEnricher) Name() string { return f.name }

func (f *fakeEnricher) Enrich(_ context.Context, advs []Advisory) error {
	f.applied = true
	if f.mutate != nil {
		f.mutate(advs)
	}
	return f.err
}

// TestEnrichmentChain_AllSucceed verifies that a chain runs every enricher in
// order and returns nil when none fail; mutations are visible in place.
func TestEnrichmentChain_AllSucceed(t *testing.T) {
	t.Parallel()

	epss := &fakeEnricher{name: "epss", mutate: func(advs []Advisory) {
		for i := range advs {
			advs[i].EPSS = &EPSSScore{Probability: 0.5}
		}
	}}
	kev := &fakeEnricher{name: "kev", mutate: func(advs []Advisory) {
		for i := range advs {
			advs[i].KEV = &KEVEntry{Listed: true}
		}
	}}

	chain := EnrichmentChain{epss, kev}
	advs := []Advisory{{ID: "GO-1"}, {ID: "GO-2"}}

	err := chain.Enrich(context.Background(), advs)
	require.NoError(t, err)
	assert.True(t, epss.applied)
	assert.True(t, kev.applied)
	for _, a := range advs {
		require.NotNil(t, a.EPSS)
		assert.Equal(t, 0.5, a.EPSS.Probability)
		require.NotNil(t, a.KEV)
		assert.True(t, a.KEV.Listed)
	}
}

// TestEnrichmentChain_PartialFailureIsIncomplete verifies the core soundness
// invariant: a failing enricher does NOT abort the chain or get swallowed.
// Succeeding enrichers still run, and the chain returns an
// *EnrichmentIncompleteError listing the failed enrichers so the caller marks
// the scan incomplete (unknown ≠ safe), never "no enrichment = clean".
func TestEnrichmentChain_PartialFailureIsIncomplete(t *testing.T) {
	t.Parallel()

	boom := errors.New("epss API rate-limited")
	failing := &fakeEnricher{name: "epss", err: boom}
	succeeding := &fakeEnricher{name: "kev", mutate: func(advs []Advisory) {
		for i := range advs {
			advs[i].KEV = &KEVEntry{Listed: true}
		}
	}}

	chain := EnrichmentChain{failing, succeeding}
	advs := []Advisory{{ID: "GO-1"}}

	err := chain.Enrich(context.Background(), advs)
	require.Error(t, err)

	var incomplete *EnrichmentIncompleteError
	require.True(t, errors.As(err, &incomplete), "must be *EnrichmentIncompleteError")
	assert.Equal(t, []string{"epss"}, incomplete.FailedEnrichers)
	require.Len(t, incomplete.Errors, 1)
	assert.ErrorIs(t, incomplete.Errors[0], boom)

	// The succeeding enricher still ran and mutated the advisory.
	assert.True(t, succeeding.applied, "non-failing enricher must still run after a failure")
	require.NotNil(t, advs[0].KEV)
	assert.True(t, advs[0].KEV.Listed)
}

// TestEnrichmentChain_AllFail verifies every failure is aggregated, in order.
func TestEnrichmentChain_AllFail(t *testing.T) {
	t.Parallel()

	e1 := &fakeEnricher{name: "epss", err: errors.New("e1")}
	e2 := &fakeEnricher{name: "kev", err: errors.New("e2")}

	chain := EnrichmentChain{e1, e2}
	err := chain.Enrich(context.Background(), []Advisory{{ID: "GO-1"}})

	var incomplete *EnrichmentIncompleteError
	require.True(t, errors.As(err, &incomplete))
	assert.Equal(t, []string{"epss", "kev"}, incomplete.FailedEnrichers)
	assert.Len(t, incomplete.Errors, 2)
}

// TestEnrichmentChain_Empty verifies an empty chain is a successful no-op.
func TestEnrichmentChain_Empty(t *testing.T) {
	t.Parallel()

	var chain EnrichmentChain
	err := chain.Enrich(context.Background(), []Advisory{{ID: "GO-1"}})
	assert.NoError(t, err)
}
