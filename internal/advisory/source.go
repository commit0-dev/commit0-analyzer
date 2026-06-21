package advisory

import "context"

// Source is the seam through which advisory backends plug into the resolution
// pipeline. The MVP provides only one implementation: [goVulnDBClient] (the Go
// vulnerability database). Future sources — OSV.dev, GHSA — will implement this
// interface and be composed via a merge layer (roadmap, not MVP).
//
// Contract:
//   - Query must be safe to call concurrently from multiple goroutines.
//   - Query returns only advisories whose affected version ranges include version.
//   - An empty result is NOT an error; it means the module@version is clean per
//     this source. "No advisory found" is distinct from "query failed" — callers
//     must treat a non-nil error as unknown, not safe.
//   - Every returned Advisory must carry source attribution in Advisory.Sources.
type Source interface {
	// Query returns all advisories that affect modulePath at the given version.
	// version must be a canonical semver string (e.g. "v1.2.3").
	Query(ctx context.Context, modulePath, version string) ([]Advisory, error)
}
