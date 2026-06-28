package parity

import "os/exec"

// CorpusEntry is one real repository the harness scans. Paths are resolved at
// run time relative to a checkout root supplied by the runner; the manifest keeps
// only stable identity + which comparators apply, so the corpus is reproducible
// and auditable without bundling third-party source.
type CorpusEntry struct {
	// Name is the stable identifier used in the report.
	Name string
	// Language is the primary ecosystem (drives which comparators apply).
	Language string
	// Repo is the upstream git URL the corpus is pinned against.
	Repo string
	// Ref is the pinned commit/tag for reproducibility.
	Ref string
	// Comparators lists which external tools are meaningful for this entry.
	Comparators []string
	// Note explains what this entry exercises (e.g. a known KEV dependency).
	Note string
	// KnownKEVID, when set, is a vulnerability identifier (CVE/GHSA) this entry is
	// known to contain that is listed in CISA's KEV catalog. The harness asserts
	// the corresponding anst finding carries the KEV flag and the top risk tier
	// (empirical non-negotiable). Empty means the entry has no KEV oracle.
	KnownKEVID string
}

// Comparator is one external tool the harness measures anst against, pinned to a
// version for reproducibility. JSONArgs produces machine-readable output on
// stdout; the runner appends the scan target.
type Comparator struct {
	Name          string
	Binary        string
	PinnedVersion string
	JSONArgs      []string
}

// Corpus returns the fixed corpus manifest. It is intentionally small and
// real-world: this repo (Go, self-scan), litellm (Python), a Log4Shell-era Maven
// fixture (JVM, exercises a known-KEV dependency), and an npm monorepo. Each
// entry records which comparators apply so the runner never claims parity against
// a tool that does not cover the ecosystem.
func Corpus() []CorpusEntry {
	return []CorpusEntry{
		{
			Name:        "anst-analyzer",
			Language:    "go",
			Repo:        "github.com/ducthinh993/anst-analyzer",
			Ref:         "faa7ed3a5e4527eb6a075741a7b744fb13c3191a",
			Comparators: []string{ToolOSVScanner, ToolGovulncheck, ToolGrype, ToolTrivy},
			Note:        "self-scan; Go reachability suppression vs govulncheck symbol parity",
		},
		{
			Name:        "litellm",
			Language:    "python",
			Repo:        "github.com/BerriAI/litellm",
			Ref:         "v1.40.0",
			Comparators: []string{ToolOSVScanner, ToolGrype, ToolTrivy},
			Note:        "real Python deps; ECOSYSTEM-range + multi-package OSV record stress",
		},
		{
			Name:        "log4shell-maven",
			Language:    "java",
			Repo:        "github.com/christophetd/log4shell-vulnerable-app",
			Ref:         "c962aabb31a6af0a77f0e9bbc7100e175c7c04e1",
			Comparators: []string{ToolOSVScanner, ToolGrype, ToolTrivy},
			Note:        "known-KEV dependency (CVE-2021-44228); asserts KEV flag + top risk tier",
			KnownKEVID:  "CVE-2021-44228",
		},
		{
			Name:        "npm-monorepo",
			Language:    "js",
			Repo:        "github.com/vercel/turbo",
			Ref:         "v1.13.0",
			Comparators: []string{ToolOSVScanner, ToolGrype, ToolTrivy},
			Note:        "npm workspace; import-graph reachability vs install-only scanners",
		},
	}
}

// Comparators returns the pinned comparator definitions. Versions are pinned so a
// re-run on the same corpus is reproducible; the runner records the actually
// observed version alongside the pin and skips (never silently claims parity for)
// any comparator whose binary is absent.
func Comparators() []Comparator {
	return []Comparator{
		{
			Name:          ToolOSVScanner,
			Binary:        "osv-scanner",
			PinnedVersion: "1.7.4",
			JSONArgs:      []string{"--format", "json"},
		},
		{
			Name:          ToolGrype,
			Binary:        "grype",
			PinnedVersion: "0.74.0",
			JSONArgs:      []string{"-o", "json"},
		},
		{
			Name:          ToolTrivy,
			Binary:        "trivy",
			PinnedVersion: "0.50.0",
			JSONArgs:      []string{"fs", "--format", "json"},
		},
		{
			Name:          ToolGovulncheck,
			Binary:        "govulncheck",
			PinnedVersion: "1.1.1",
			JSONArgs:      []string{"-json"},
		},
	}
}

// Available reports whether a comparator binary is on PATH. The runner uses this
// to skip (and note) absent comparators rather than silently claim parity.
func Available(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// ComparatorByName returns the pinned definition for a comparator name, or
// (Comparator{}, false) when unknown.
func ComparatorByName(name string) (Comparator, bool) {
	for _, c := range Comparators() {
		if c.Name == name {
			return c, true
		}
	}
	return Comparator{}, false
}
