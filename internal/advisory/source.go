package advisory

import "context"

// EcosystemGo is the canonical ecosystem tag for Go modules, matching the OSV
// schema value used by https://vuln.go.dev and https://osv.dev.
const EcosystemGo = "Go"

// EcosystemNPM is the canonical ecosystem tag for npm packages, matching the
// OSV schema value used by https://osv.dev (the npm/all.zip bundle).
const EcosystemNPM = "npm"

// EcosystemCratesIO is the canonical ecosystem tag for Rust crates, matching
// the OSV schema value used by https://osv.dev (the crates.io/all.zip bundle)
// and the RustSec advisory database.
const EcosystemCratesIO = "crates.io"

// EcosystemPyPI is the canonical ecosystem tag for Python packages, matching
// the OSV schema value used by https://osv.dev (the PyPI/all.zip bundle).
const EcosystemPyPI = "PyPI"

// EcosystemMaven is the canonical ecosystem tag for Maven (Java/JVM) packages,
// matching the OSV schema value used by https://osv.dev (the Maven/all.zip bundle).
const EcosystemMaven = "Maven"

// EcosystemNuGet is the canonical ecosystem tag for .NET/NuGet packages, matching
// the OSV schema value used by https://osv.dev (the NuGet/all.zip bundle).
const EcosystemNuGet = "NuGet"

// EcosystemPackagist is the canonical ecosystem tag for PHP/Composer packages,
// matching the OSV schema value used by https://osv.dev (the Packagist/all.zip bundle).
const EcosystemPackagist = "Packagist"

// EcosystemRubyGems is the canonical ecosystem tag for Ruby gems, matching the
// OSV schema value used by https://osv.dev (the RubyGems/all.zip bundle).
const EcosystemRubyGems = "RubyGems"

// EcosystemHex is the canonical ecosystem tag for Elixir/Erlang packages on
// Hex.pm, matching the OSV schema value used by https://osv.dev (the Hex/all.zip bundle).
const EcosystemHex = "Hex"

// EcosystemPub is the canonical ecosystem tag for Dart/Flutter packages on
// pub.dev, matching the OSV schema value used by https://osv.dev (the Pub/all.zip bundle).
const EcosystemPub = "Pub"

// Package identifies a package within a specific language ecosystem.
// It is the unit of identity passed to Source.Query so that a single source
// implementation can serve multiple ecosystems or decline to handle ecosystems
// it does not cover.
type Package struct {
	// Ecosystem is the language ecosystem, e.g. EcosystemGo ("Go"), "npm", "PyPI".
	Ecosystem string
	// Name is the ecosystem-specific package name or module path.
	// For Go this is the module path (e.g. "github.com/foo/bar").
	Name string
}

// Source is the seam through which advisory backends plug into the resolution
// pipeline. The MVP provides only one implementation: [goVulnDBClient] (the Go
// vulnerability database). Future sources — OSV.dev, GHSA — will implement this
// interface and be composed via a merge layer (roadmap, not MVP).
//
// Contract:
//   - Query must be safe to call concurrently from multiple goroutines.
//   - Query returns only advisories whose affected version ranges include version.
//   - An empty result is NOT an error; it means the package@version is clean per
//     this source, or that the source does not cover pkg.Ecosystem. "No advisory
//     found" is distinct from "query failed" — callers must treat a non-nil error
//     as unknown, not safe.
//   - Every returned Advisory must carry source attribution in Advisory.Sources.
//   - An implementation may serve one or more ecosystems and MUST return
//     (nil, nil) for ecosystems it does not cover.
type Source interface {
	// Query returns all advisories that affect pkg at the given version.
	// version must be a canonical semver string (e.g. "v1.2.3").
	// Returns (nil, nil) when pkg.Ecosystem is not served by this source.
	Query(ctx context.Context, pkg Package, version string) ([]Advisory, error)
}
