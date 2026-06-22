package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// TestStampSources verifies that advisory source attribution is propagated onto
// findings' properties["sources"], that synthetic findings (no advisory) are
// skipped, and that an unmapped advisory ID leaves the finding untouched.
func TestStampSources(t *testing.T) {
	sourcesByID := map[string][]string{
		"GO-2024-0001": {"go-vuln-db", "osv.dev"},
		"GO-2024-0002": {"osv.dev"},
	}

	findings := []*anstv1.Finding{
		{Advisory: &anstv1.AdvisoryRef{Id: "GO-2024-0001"}},                                                 // both sources
		{Advisory: &anstv1.AdvisoryRef{Id: "GO-2024-0002"}, Properties: map[string]string{"goos": "linux"}}, // existing props preserved
		{Advisory: &anstv1.AdvisoryRef{Id: "GO-9999-9999"}},                                                 // unmapped → untouched
		{Module: "synthetic-plugin-error"},                                                                  // nil advisory → skipped
	}

	stampSources(findings, sourcesByID)

	assert.Equal(t, "go-vuln-db,osv.dev", findings[0].GetProperties()["sources"],
		"merged multi-source attribution must be stamped")

	assert.Equal(t, "osv.dev", findings[1].GetProperties()["sources"])
	assert.Equal(t, "linux", findings[1].GetProperties()["goos"],
		"existing properties must be preserved")

	_, ok := findings[2].GetProperties()["sources"]
	assert.False(t, ok, "unmapped advisory ID must not get a sources property")

	assert.Nil(t, findings[3].GetProperties(),
		"synthetic finding with no advisory must be left untouched (no panic, no props)")
}
