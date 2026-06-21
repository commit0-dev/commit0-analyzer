package engine_test

// Integration tests for the Go reachability engine.
// These tests run Analyze against hermetic fixture modules under testdata/mods/.
// All fixtures use relative `replace` directives — no network required.
//
// TDD cases covered:
//   1. GATE G1 — direct-call: SYMBOL_REACHABLE with concrete path
//   2. no-call: NOT_REACHABLE, no path
//   3. transitive: SYMBOL_REACHABLE, ordered path main→Helper→VulnerableFunc
//   4. iface-dispatch: SYMBOL_REACHABLE via VTA (not UNKNOWN)
//   5. reflect-call: UNKNOWN because BFS found no edge (reflection fallback)
//   6. pkg-level: PACKAGE_REACHABLE when SymbolLevel=false; NOT_REACHABLE for unimported module
//   7. determinism: byte-identical findings across N runs when two equal-length paths exist

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	"github.com/ducthinh993/anst-analyzer/plugins/go-reachability/internal/engine"
)

// fixtureDir returns the absolute path to a fixture module directory.
// It resolves relative to this test file's location.
func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	// This file lives at plugins/go-reachability/internal/engine/
	// Fixtures are at   plugins/go-reachability/testdata/mods/<name>
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "mods", name)
	abs, err := filepath.Abs(dir)
	require.NoError(t, err, "fixture dir must resolve")
	return abs
}

// vulnAdvisory builds a symbol-level advisory targeting VulnerableFunc in vulnlib.
func vulnAdvisory(symbolName string) *anstv1.Advisory {
	return &anstv1.Advisory{
		Id:          "TEST-VULN-001",
		Module:      "example.com/vulnlib",
		SymbolLevel: true,
		Symbols: []*anstv1.Symbol{
			{
				Package: "example.com/vulnlib",
				Name:    symbolName,
			},
		},
	}
}

// findingForAdvisory returns the first finding matching the advisory ID.
// Fails the test if no such finding is present.
func findingForAdvisory(t *testing.T, findings []*anstv1.Finding, advID string) *anstv1.Finding {
	t.Helper()
	for _, f := range findings {
		if f.GetAdvisory().GetId() == advID {
			return f
		}
	}
	t.Fatalf("no finding for advisory %q; got %d findings total", advID, len(findings))
	return nil
}

// pathSymbols extracts the ordered symbol strings from a ReachabilityPath.
func pathSymbols(path *anstv1.ReachabilityPath) []string {
	if path == nil {
		return nil
	}
	syms := make([]string, 0, len(path.GetSteps()))
	for _, step := range path.GetSteps() {
		syms = append(syms, step.GetSymbol())
	}
	return syms
}

// ─── TDD 1 / GATE G1 ──────────────────────────────────────────────────────────

// TestDirectCall_G1 is the Gate G1 test: main → VulnerableFunc must yield
// CONFIDENCE_SYMBOL_REACHABLE with a non-nil path whose first step is main.main
// and last step is VulnerableFunc.
func TestDirectCall_G1(t *testing.T) {
	modRoot := fixtureDir(t, "direct-call")
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err, "Analyze must not return a hard error")
	require.NotEmpty(t, findings, "must produce at least one finding")

	f := findingForAdvisory(t, findings, "TEST-VULN-001")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		f.GetConfidence(),
		"direct-call fixture must be SYMBOL_REACHABLE",
	)

	require.NotNil(t, f.GetPath(), "SYMBOL_REACHABLE finding must have a non-nil Path")
	steps := f.GetPath().GetSteps()
	require.GreaterOrEqual(t, len(steps), 1, "path must have at least 1 step")

	// Gate G1: log the full path for the acceptance report.
	syms := pathSymbols(f.GetPath())
	t.Logf("GATE G1 path: %s", strings.Join(syms, " → "))

	// The last step must be VulnerableFunc.
	last := steps[len(steps)-1].GetSymbol()
	assert.Contains(t, last, "VulnerableFunc",
		"last path step must be VulnerableFunc; got %q", last)

	// The first step must be an entry point (main.main).
	first := steps[0].GetSymbol()
	assert.Contains(t, first, "main",
		"first path step must be an entry point (main.main); got %q", first)

	// Path must make sense end-to-end (symbols are non-empty).
	for i, s := range steps {
		assert.NotEmpty(t, s.GetSymbol(), "step %d must have a non-empty Symbol", i)
	}
}

// ─── TDD 2 — no-call ──────────────────────────────────────────────────────────

// TestNoCall_NotReachable asserts that a module that imports vulnlib but never
// calls VulnerableFunc produces CONFIDENCE_NOT_REACHABLE with no path.
func TestNoCall_NotReachable(t *testing.T) {
	modRoot := fixtureDir(t, "no-call")
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findingForAdvisory(t, findings, "TEST-VULN-001")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		f.GetConfidence(),
		"no-call fixture must be NOT_REACHABLE",
	)
	assert.Nil(t, f.GetPath(), "NOT_REACHABLE finding must have nil Path")
}

// ─── TDD 3 — transitive ───────────────────────────────────────────────────────

// TestTransitive_OrderedPath verifies that main → Helper → VulnerableFunc
// produces SYMBOL_REACHABLE with steps in that exact order.
func TestTransitive_OrderedPath(t *testing.T) {
	modRoot := fixtureDir(t, "transitive")
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findingForAdvisory(t, findings, "TEST-VULN-001")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		f.GetConfidence(),
		"transitive fixture must be SYMBOL_REACHABLE",
	)

	require.NotNil(t, f.GetPath(), "SYMBOL_REACHABLE finding must have a path")
	steps := f.GetPath().GetSteps()

	// We expect at least 3 steps: main.main → Helper → VulnerableFunc.
	require.GreaterOrEqual(t, len(steps), 3,
		"transitive path must have ≥3 steps (main→Helper→VulnerableFunc); got %d: %v",
		len(steps), pathSymbols(f.GetPath()))

	// Verify ordering: first is main.main, an intermediate step contains "Helper",
	// last contains "VulnerableFunc".
	syms := pathSymbols(f.GetPath())
	t.Logf("transitive path: %s", strings.Join(syms, " → "))

	first := steps[0].GetSymbol()
	assert.Contains(t, first, "main",
		"first step must be main.main; got %q", first)

	last := steps[len(steps)-1].GetSymbol()
	assert.Contains(t, last, "VulnerableFunc",
		"last step must be VulnerableFunc; got %q", last)

	// At least one intermediate step must contain "Helper".
	foundHelper := false
	for _, step := range steps[1 : len(steps)-1] {
		if strings.Contains(step.GetSymbol(), "Helper") {
			foundHelper = true
			break
		}
	}
	assert.True(t, foundHelper,
		"transitive path must include Helper between main and VulnerableFunc; steps: %v", syms)

	// Verify strict prefix ordering: main appears before Helper, Helper before VulnerableFunc.
	mainIdx, helperIdx, vulnIdx := -1, -1, -1
	for i, step := range steps {
		sym := step.GetSymbol()
		if mainIdx == -1 && strings.Contains(sym, "main") {
			mainIdx = i
		}
		if helperIdx == -1 && strings.Contains(sym, "Helper") {
			helperIdx = i
		}
		if vulnIdx == -1 && strings.Contains(sym, "VulnerableFunc") {
			vulnIdx = i
		}
	}
	require.NotEqual(t, -1, mainIdx, "main step not found in path")
	require.NotEqual(t, -1, helperIdx, "Helper step not found in path")
	require.NotEqual(t, -1, vulnIdx, "VulnerableFunc step not found in path")

	assert.Less(t, mainIdx, helperIdx,
		"main must appear before Helper in path; steps: %v", syms)
	assert.Less(t, helperIdx, vulnIdx,
		"Helper must appear before VulnerableFunc in path; steps: %v", syms)
}

// ─── TDD 4 — iface-dispatch ───────────────────────────────────────────────────

// TestIfaceDispatch_SymbolReachable asserts that VTA resolves the concrete
// VulnDoer.Do → VulnerableFunc call through a Doer interface dispatch.
// The finding MUST be SYMBOL_REACHABLE, not UNKNOWN.
func TestIfaceDispatch_SymbolReachable(t *testing.T) {
	modRoot := fixtureDir(t, "iface-dispatch")

	// The method symbol on VulnDoer that calls VulnerableFunc is "VulnDoer.Do".
	// resolve.go Case 2 handles "TypeName.MethodName" (value receiver).
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findingForAdvisory(t, findings, "TEST-VULN-001")
	// Red-team invariant: interface dispatch via in-program allocation must not
	// produce UNKNOWN when VTA is the default builder.
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		f.GetConfidence(),
		"VTA must resolve VulnDoer.Do()→VulnerableFunc; UNKNOWN would mean a VTA regression; got: %s",
		f.GetConfidence(),
	)
	require.NotNil(t, f.GetPath(),
		"SYMBOL_REACHABLE finding must have a path; confidence=%s", f.GetConfidence())
	assert.GreaterOrEqual(t, len(f.GetPath().GetSteps()), 1,
		"path must have ≥1 step")

	syms := pathSymbols(f.GetPath())
	t.Logf("iface-dispatch path: %s", strings.Join(syms, " → "))
}

// ─── TDD 5 — reflect-call ─────────────────────────────────────────────────────

// TestReflectCall_Unknown asserts that VulnerableFunc passed to reflect.ValueOf
// produces CONFIDENCE_UNKNOWN because:
//   (a) VulnerableFunc is address-taken (used as function value), and
//   (b) the reachable subgraph includes a reflect.Value.Call* invocation,
//       so BFSReachable finds no direct edge but the engine correctly escalates
//       to UNKNOWN rather than NOT_REACHABLE.
func TestReflectCall_Unknown(t *testing.T) {
	modRoot := fixtureDir(t, "reflect-call")
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findingForAdvisory(t, findings, "TEST-VULN-001")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_UNKNOWN,
		f.GetConfidence(),
		"reflect-call fixture must be UNKNOWN (reflection fallback, not a resolution failure); got: %s",
		f.GetConfidence(),
	)
	// Invariant: no path on UNKNOWN.
	assert.Nil(t, f.GetPath(),
		"UNKNOWN finding must have nil Path (no graph edge means no path)")

	// The finding must not carry a resolution_error property — the symbol was
	// resolved correctly; it's the absence of a BFS edge (+ reflect+addr-taken)
	// that triggered UNKNOWN, not a lookup failure.
	props := f.GetProperties()
	assert.NotContains(t, props, "resolution_error",
		"UNKNOWN from reflect should not have resolution_error; this would indicate a symbol-lookup failure instead of the reflect fallback")
}

// ─── TDD 6 — pkg-level ────────────────────────────────────────────────────────

// TestPkgLevel_PackageReachable verifies that a package-level advisory
// (SymbolLevel=false) against an imported package yields PACKAGE_REACHABLE.
// Also verifies that an unimported module path yields NOT_REACHABLE.
func TestPkgLevel_PackageReachable(t *testing.T) {
	modRoot := fixtureDir(t, "pkg-level")

	// Case A: SymbolLevel=false, package IS imported → PACKAGE_REACHABLE.
	pkgAdvisory := &anstv1.Advisory{
		Id:          "TEST-PKG-001",
		Module:      "example.com/vulnlib",
		SymbolLevel: false,
		Symbols: []*anstv1.Symbol{
			{Package: "example.com/vulnlib", Name: "VulnerableFunc"},
		},
	}

	// Case B: SymbolLevel=false, module is NOT imported → NOT_REACHABLE.
	unimportedAdvisory := &anstv1.Advisory{
		Id:          "TEST-PKG-002",
		Module:      "example.com/not-imported-at-all",
		SymbolLevel: false,
		Symbols: []*anstv1.Symbol{
			{Package: "example.com/not-imported-at-all", Name: "SomeFunc"},
		},
	}

	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{pkgAdvisory, unimportedAdvisory},
	}

	findings, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.Len(t, findings, 2, "must get one finding per advisory")

	// Case A assertion.
	fa := findingForAdvisory(t, findings, "TEST-PKG-001")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		fa.GetConfidence(),
		"imported package with SymbolLevel=false must be PACKAGE_REACHABLE",
	)
	assert.Nil(t, fa.GetPath(), "PACKAGE_REACHABLE must have nil Path")

	// Case B assertion.
	fb := findingForAdvisory(t, findings, "TEST-PKG-002")
	assert.Equal(t,
		anstv1.Confidence_CONFIDENCE_NOT_REACHABLE,
		fb.GetConfidence(),
		"unimported module with SymbolLevel=false must be NOT_REACHABLE",
	)
	assert.Nil(t, fb.GetPath(), "NOT_REACHABLE must have nil Path")
}

// ─── TDD 7 — determinism ──────────────────────────────────────────────────────

// TestDeterminism verifies that Analyze produces identical confidence and
// call-path step sequences across N runs when two equal-length paths to
// VulnerableFunc exist (PathA and PathB in the fixture, both one hop from main).
//
// Note on proto.Marshal: the Finding.Properties field is a map[string]string,
// and proto3 map field serialization order is intentionally non-deterministic
// across calls. We therefore compare structured fields — confidence, path symbol
// sequence, and path length — rather than raw proto bytes. This correctly tests
// what the spec requires: the chosen call path (BFS tie-break output) is stable,
// not the incidental serialization order of metadata properties.
func TestDeterminism(t *testing.T) {
	modRoot := fixtureDir(t, "determinism")
	req := &anstv1.AnalyzeRequest{
		ModuleRoot: modRoot,
		Advisories: []*anstv1.Advisory{vulnAdvisory("VulnerableFunc")},
	}

	const runs = 20

	// Run once to get the reference result.
	ref, err := engine.Analyze(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotEmpty(t, ref)

	// The reference finding must be SYMBOL_REACHABLE — tie-break is only
	// exercised when there IS a reachable path.
	fRef := findingForAdvisory(t, ref, "TEST-VULN-001")
	require.Equal(t,
		anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		fRef.GetConfidence(),
		"determinism fixture must be SYMBOL_REACHABLE to exercise the BFS tie-break",
	)
	require.NotNil(t, fRef.GetPath(),
		"SYMBOL_REACHABLE finding must have a non-nil path")

	refSyms := pathSymbols(fRef.GetPath())
	t.Logf("determinism reference path: %s", strings.Join(refSyms, " → "))

	// Confirm the fixture exercises two equal-length candidates: via PathA or
	// PathB (both are exactly 1 hop from main.main to VulnerableFunc via an
	// intermediate function). The BFS lexicographic tie-break must always pick
	// the same one.
	require.GreaterOrEqual(t, len(fRef.GetPath().GetSteps()), 2,
		"determinism fixture path must traverse at least 2 steps (main→PathX→Vuln)")

	// Verify the chosen intermediate is either PathA or PathB (not some other path).
	steps := fRef.GetPath().GetSteps()
	if len(steps) >= 2 {
		intermediate := steps[len(steps)-2].GetSymbol()
		hasPathAB := strings.Contains(intermediate, "PathA") || strings.Contains(intermediate, "PathB")
		assert.True(t, hasPathAB,
			"determinism tie-break must select PathA or PathB; got intermediate %q in path %v",
			intermediate, refSyms)
	}

	for i := 0; i < runs; i++ {
		got, err := engine.Analyze(context.Background(), req, nil)
		require.NoError(t, err, "run %d: Analyze must not error", i+1)
		require.NotEmpty(t, got, "run %d: must produce findings", i+1)

		fGot := findingForAdvisory(t, got, "TEST-VULN-001")

		// Confidence must be identical.
		assert.Equal(t, fRef.GetConfidence(), fGot.GetConfidence(),
			"run %d: confidence must be identical", i+1)

		// Path must be non-nil and have the same length.
		require.NotNil(t, fGot.GetPath(), "run %d: path must be non-nil", i+1)
		gotSyms := pathSymbols(fGot.GetPath())
		require.Len(t, gotSyms, len(refSyms),
			"run %d: path length must be identical", i+1)

		// Each step symbol must match exactly.
		for si := range refSyms {
			if refSyms[si] != gotSyms[si] {
				t.Errorf("run %d step %d: symbol mismatch\n  want: %q\n   got: %q\n  ref path: %v\n  got path: %v",
					i+1, si, refSyms[si], gotSyms[si], refSyms, gotSyms)
			}
		}
	}
}

// ─── invariants: no path on non-SYMBOL_REACHABLE ─────────────────────────────

// TestNoPathOnNonSymbolReachable checks the cross-cutting invariant that
// Path is nil whenever Confidence != SYMBOL_REACHABLE. This catches engine
// regressions that accidentally attach a path to UNKNOWN or NOT_REACHABLE findings.
func TestNoPathOnNonSymbolReachable(t *testing.T) {
	cases := []struct {
		fixture string
		adv     *anstv1.Advisory
	}{
		{
			fixture: "no-call",
			adv:     vulnAdvisory("VulnerableFunc"),
		},
		{
			fixture: "reflect-call",
			adv:     vulnAdvisory("VulnerableFunc"),
		},
		{
			fixture: "pkg-level",
			adv: &anstv1.Advisory{
				Id:          "TEST-INVARIANT-PKG",
				Module:      "example.com/vulnlib",
				SymbolLevel: false,
				Symbols: []*anstv1.Symbol{
					{Package: "example.com/vulnlib", Name: "VulnerableFunc"},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("fixture=%s", tc.fixture), func(t *testing.T) {
			modRoot := fixtureDir(t, tc.fixture)
			req := &anstv1.AnalyzeRequest{
				ModuleRoot: modRoot,
				Advisories: []*anstv1.Advisory{tc.adv},
			}
			findings, err := engine.Analyze(context.Background(), req, nil)
			require.NoError(t, err)
			for _, f := range findings {
				if f.GetConfidence() != anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE {
					assert.Nil(t, f.GetPath(),
						"fixture %s: finding confidence=%s must have nil Path",
						tc.fixture, f.GetConfidence())
				}
			}
		})
	}
}
