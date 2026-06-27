package advisory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestNuGetOSVProbe_EmpiricalVersionMatching probes the live NuGet OSV cache
// to verify that the version-range comparison correctly identifies affected /
// not-affected / undecidable for a representative set of packages and versions.
//
// Run with: go test ./internal/advisory/ -run TestNuGetOSVProbe_EmpiricalVersionMatching -v
//
// Skip automatically when the NuGet cache is absent (CI without warm cache).
func TestNuGetOSVProbe_EmpiricalVersionMatching(t *testing.T) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("cannot locate user cache dir: %v", err)
	}
	osvCacheDir := filepath.Join(cacheDir, "anst-analyzer", "osv")
	nugetCacheDir := filepath.Join(osvCacheDir, "NuGet")
	if _, statErr := os.Stat(nugetCacheDir); statErr != nil {
		t.Skipf("NuGet OSV cache not present at %s; skipping empirical probe", nugetCacheDir)
	}

	src := NewOSVBundleSource(osvCacheDir)
	ctx := context.Background()

	cases := []struct {
		name    string
		version string
		// wantAffected: "affected", "not-affected", "undecidable"
		wantAffected string
	}{
		{"Newtonsoft.Json", "12.0.3", "affected"},    // < 13.0.1 fixed
		{"Newtonsoft.Json", "13.0.3", "not-affected"}, // >= 13.0.1
		{"SharpCompress", "0.30.1", "affected"},       // <= 0.47.4 last_affected
		{"SharpCompress", "0.48.0", "not-affected"},   // > 0.47.4
		{"xunit", "2.4.1", "not-affected"},            // known-clean test dep
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s@%s", tc.name, tc.version), func(t *testing.T) {
			pkg := Package{Ecosystem: EcosystemNuGet, Name: tc.name}
			advs, err := src.Query(ctx, pkg, tc.version)
			if err != nil {
				t.Fatalf("Query error: %v", err)
			}

			var got string
			switch {
			case len(advs) == 0:
				got = "not-affected"
			default:
				// any Incomplete advisory → undecidable
				allIncomplete := true
				for _, a := range advs {
					if !a.Incomplete {
						allIncomplete = false
					}
				}
				if allIncomplete && len(advs) > 0 {
					got = "undecidable"
				} else {
					got = "affected"
				}
			}

			// Log every matched advisory for the human-readable report.
			for _, a := range advs {
				status := "AFFECTED"
				if a.Incomplete {
					status = "UNDECIDABLE"
				}
				t.Logf("  %s → %s (severity=%v incomplete=%v)", status, a.ID, a.Severity, a.Incomplete)
			}
			if len(advs) == 0 {
				t.Logf("  NOT_AFFECTED (no advisory matched)")
			}

			if got != tc.wantAffected {
				t.Errorf("mismatch: got %q, want %q", got, tc.wantAffected)
			}
		})
	}
}
