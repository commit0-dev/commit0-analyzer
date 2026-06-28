package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ── registry helpers ──────────────────────────────────────────────────────────

// withCleanRegistry saves the global registry, clears it, calls fn, then
// restores the original state. Use in tests that register temporary adapters
// to avoid leaking state into other test cases.
func withCleanRegistry(t *testing.T, fn func()) {
	t.Helper()
	saved := laneARegistry
	laneARegistry = nil
	defer func() { laneARegistry = saved }()
	fn()
}

// ── RegisterLaneAAdapter + LaneAAdapters ─────────────────────────────────────

// TestRegisterLaneAAdapter_SingleAdapter verifies that a registered adapter
// appears in the LaneAAdapters snapshot.
func TestRegisterLaneAAdapter_SingleAdapter(t *testing.T) {
	withCleanRegistry(t, func() {
		a := LaneAAdapter{
			Ecosystem:     advisory.EcosystemMaven,
			Language:      "java",
			DetectFiles:   []string{"pom.xml"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		}
		RegisterLaneAAdapter(a)

		adapters := LaneAAdapters()
		require.Len(t, adapters, 1, "exactly one adapter should be registered")
		assert.Equal(t, advisory.EcosystemMaven, adapters[0].Ecosystem)
		assert.Equal(t, "java", adapters[0].Language)
		assert.Equal(t, []string{"pom.xml"}, adapters[0].DetectFiles)
	})
}

// TestRegisterLaneAAdapter_MultipleAdapters verifies that multiple adapters
// sharing the same known Language are registered in insertion order.
// (Multiple adapters per Language is permitted by the registry; useful when
// a single language ecosystem has several lockfile variants, e.g. Maven and
// Gradle once both have real parsers.)
func TestRegisterLaneAAdapter_MultipleAdapters(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterLaneAAdapter(LaneAAdapter{Ecosystem: "Maven-A", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})
		RegisterLaneAAdapter(LaneAAdapter{Ecosystem: "Maven-B", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})
		RegisterLaneAAdapter(LaneAAdapter{Ecosystem: "Maven-C", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})

		adapters := LaneAAdapters()
		require.Len(t, adapters, 3)
		assert.Equal(t, "Maven-A", adapters[0].Ecosystem)
		assert.Equal(t, "Maven-B", adapters[1].Ecosystem)
		assert.Equal(t, "Maven-C", adapters[2].Ecosystem)
	})
}

// TestLaneAAdapters_ReturnsSnapshot verifies that mutating the returned slice
// does not affect the registry (the returned value is a copy, not a reference).
func TestLaneAAdapters_ReturnsSnapshot(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterLaneAAdapter(LaneAAdapter{
			Ecosystem:     "Maven-Original",
			Language:      "java",
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		})

		snap1 := LaneAAdapters()
		require.Len(t, snap1, 1)

		// Mutate the snapshot.
		snap1[0].Ecosystem = "Maven-Mutated"

		// A fresh call must reflect the original registry, not the mutation.
		snap2 := LaneAAdapters()
		require.Len(t, snap2, 1)
		assert.Equal(t, "Maven-Original", snap2[0].Ecosystem,
			"LaneAAdapters must return a copy; mutations must not affect the registry")
	})
}

// ── laneAAdapterActive ────────────────────────────────────────────────────────

// TestLaneAAdapterActive_Java_WhenHasJava verifies that the Java adapter is
// active when eco.hasJava is true.
func TestLaneAAdapterActive_Java_WhenHasJava(t *testing.T) {
	eco := ecosystems{hasJava: true}
	assert.True(t, laneAAdapterActive("java", eco),
		"laneAAdapterActive(java) must be true when eco.hasJava=true")
}

// TestLaneAAdapterActive_Java_WhenNotHasJava verifies that the Java adapter
// is inactive when eco.hasJava is false.
func TestLaneAAdapterActive_Java_WhenNotHasJava(t *testing.T) {
	eco := ecosystems{hasJava: false}
	assert.False(t, laneAAdapterActive("java", eco),
		"laneAAdapterActive(java) must be false when eco.hasJava=false")
}

// TestLaneAAdapterActive_UnknownLanguage verifies that an unregistered language
// key returns false regardless of the ecosystem detection state.
func TestLaneAAdapterActive_UnknownLanguage(t *testing.T) {
	eco := ecosystems{hasGo: true, hasJS: true, hasRust: true, hasPython: true, hasJava: true}
	assert.False(t, laneAAdapterActive("nuget", eco),
		"unregistered language must return false even when all ecosystems are detected")
	assert.False(t, laneAAdapterActive("", eco),
		"empty language key must return false")
}

// TestLaneAAdapterActive_JavaNotActivatedByOtherFlags verifies that the Java
// active check is not triggered by other ecosystem flags (no cross-contamination).
func TestLaneAAdapterActive_JavaNotActivatedByOtherFlags(t *testing.T) {
	eco := ecosystems{hasGo: true, hasJS: true, hasRust: true, hasPython: true, hasJava: false}
	assert.False(t, laneAAdapterActive("java", eco),
		"Java active check must not be triggered by Go/JS/Rust/Python flags")
}

// ── setLaneAFlag / clearLaneAFlag ─────────────────────────────────────────────

// TestSetLaneAFlag_Java verifies that setLaneAFlag("java") sets eco.hasJava.
func TestSetLaneAFlag_Java(t *testing.T) {
	var e ecosystems
	assert.False(t, e.hasJava, "precondition: hasJava starts false")
	setLaneAFlag(&e, "java")
	assert.True(t, e.hasJava, "setLaneAFlag(java) must set hasJava=true")
}

// TestSetLaneAFlag_UnknownLang verifies that setLaneAFlag with an unknown
// language is a no-op and does not panic.
func TestSetLaneAFlag_UnknownLang(t *testing.T) {
	e := ecosystems{hasGo: true}
	setLaneAFlag(&e, "nuget") // must not panic
	assert.True(t, e.hasGo, "setLaneAFlag with unknown language must not alter other flags")
}

// TestClearLaneAFlag_Java verifies that clearLaneAFlag("java") clears eco.hasJava.
func TestClearLaneAFlag_Java(t *testing.T) {
	e := ecosystems{hasJava: true}
	assert.True(t, e.hasJava, "precondition: hasJava starts true")
	clearLaneAFlag(&e, "java")
	assert.False(t, e.hasJava, "clearLaneAFlag(java) must set hasJava=false")
}

// TestClearLaneAFlag_Java_DoesNotAffectOtherFlags verifies that clearing Java
// does not disturb other ecosystem flags.
func TestClearLaneAFlag_Java_DoesNotAffectOtherFlags(t *testing.T) {
	e := ecosystems{hasGo: true, hasJS: true, hasRust: true, hasPython: true, hasJava: true}
	clearLaneAFlag(&e, "java")
	assert.True(t, e.hasGo, "Go flag must be unaffected by clearLaneAFlag(java)")
	assert.True(t, e.hasJS, "JS flag must be unaffected by clearLaneAFlag(java)")
	assert.True(t, e.hasRust, "Rust flag must be unaffected by clearLaneAFlag(java)")
	assert.True(t, e.hasPython, "Python flag must be unaffected by clearLaneAFlag(java)")
	assert.False(t, e.hasJava, "Java flag must be cleared")
}

// TestClearLaneAFlag_UnknownLang verifies that clearLaneAFlag with an unknown
// language is a no-op and does not panic.
func TestClearLaneAFlag_UnknownLang(t *testing.T) {
	e := ecosystems{hasJava: true}
	clearLaneAFlag(&e, "nuget") // must not panic
	assert.True(t, e.hasJava, "clearLaneAFlag with unknown language must not alter other flags")
}

// ── Java adapter (registered by init()) ──────────────────────────────────────

// TestJavaAdapter_IsRegistered verifies that the Java adapter is present in the
// global registry after package init.
func TestJavaAdapter_IsRegistered(t *testing.T) {
	var javaAdapter *LaneAAdapter
	for _, a := range LaneAAdapters() {
		if a.Language == "java" {
			a := a // capture
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered by init()")
	assert.Equal(t, advisory.EcosystemMaven, javaAdapter.Ecosystem,
		"Java adapter must declare the Maven OSV ecosystem")
}

// TestJavaAdapter_DetectFiles verifies that the Java adapter lists the expected
// Maven and Gradle manifest files for zero-config auto-detection.
func TestJavaAdapter_DetectFiles(t *testing.T) {
	var javaAdapter *LaneAAdapter
	for _, a := range LaneAAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")

	// gradle.lockfile must be included so that a project root containing only
	// gradle.lockfile (no build.gradle co-located) is detected as a Java project.
	expected := []string{"pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts"}
	assert.Equal(t, expected, javaAdapter.DetectFiles,
		"Java adapter must detect pom.xml, gradle.lockfile, build.gradle, and build.gradle.kts")
}

// TestJavaAdapter_ParseLockfile_PomOnly_ReturnsIncomplete verifies that when
// only pom.xml is present (no gradle.lockfile), ParseLockfile returns
// complete=false. The full Maven transitive closure requires running
// `mvn help:effective-pom` (ACE risk on untrusted repos) — so we degrade to
// incomplete. The caller sets incomplete=true and warns ("unknown ≠ safe").
func TestJavaAdapter_ParseLockfile_PomOnly_ReturnsIncomplete(t *testing.T) {
	dir := t.TempDir()
	// Create a realistic pom.xml so the adapter has a "real" project root.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(`<?xml version="1.0"?><project/>`), 0o644))

	var javaAdapter *LaneAAdapter
	for _, a := range LaneAAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")
	require.NotNil(t, javaAdapter.ParseLockfile, "Java adapter must provide a ParseLockfile func")

	deps, complete, err := javaAdapter.ParseLockfile(dir)
	assert.NoError(t, err, "pom.xml-only parse must not error (clean degrade)")
	assert.False(t, complete,
		"pom.xml-only → complete=false (transitive closure requires running mvn; ACE risk); "+
			"this is an intentional degrade, not a Phase-0 stub — the real adapter is present "+
			"but cannot produce a complete closure without a gradle.lockfile")
	assert.Nil(t, deps,
		"LaneAAdapter contract: NEVER return a partial closure with complete=false; "+
			"a partial dep list would produce false NOT_REACHABLE for missing transitives")
}

// TestJavaAdapter_ParseLockfile_NoSubprocess verifies that ParseLockfile does
// not try to spawn a build tool on an empty temp dir. This is the ACE-safety
// check: even without any pom.xml / Gradle files present, the adapter must not
// attempt to run mvn, gradle, or any other executable.
func TestJavaAdapter_ParseLockfile_NoSubprocess(t *testing.T) {
	dir := t.TempDir() // no pom.xml, no Gradle files — intentionally empty

	var javaAdapter *LaneAAdapter
	for _, a := range LaneAAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")

	// If ParseLockfile tries to run a subprocess and fails, it would likely return
	// a non-nil error. A pure-Go static parser must succeed (no error) regardless
	// of project content.
	_, complete, err := javaAdapter.ParseLockfile(dir)
	assert.NoError(t, err, "adapter must not spawn a subprocess (ACE-safety)")
	assert.False(t, complete, "empty dir → complete=false (no gradle.lockfile to parse)")
}

// ── detectEcosystems + registry integration ───────────────────────────────────

// TestDetectEcosystems_JavaViaPomXML_RegistryDriven verifies that detectEcosystems
// sets eco.hasJava when pom.xml is present, and that this detection is driven by
// the Java adapter's DetectFiles (not hardcoded in detectEcosystems).
// This is the integration proof for the table-driven detection refactor.
func TestDetectEcosystems_JavaViaPomXML_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("{}"), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.hasJava,
		"pom.xml present → eco.hasJava must be true (registry-driven detection)")
	assert.False(t, eco.hasGo, "no go.mod → Go must not be detected")
}

// TestDetectEcosystems_NoJavaManifests_RegistryDriven verifies that no Java
// manifest → hasJava=false even after the registry-driven refactor.
func TestDetectEcosystems_NoJavaManifests_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	// Only a go.mod is present — no Java manifest.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m"), 0o644))

	eco := detectEcosystems(dir)
	assert.False(t, eco.hasJava,
		"no Java manifest → eco.hasJava must be false after registry-driven detection refactor")
	assert.True(t, eco.hasGo, "go.mod present → Go must be detected")
}

// TestDetectEcosystems_PolyglotWithJavaAndGo_RegistryDriven verifies that a
// polyglot repo with both go.mod and pom.xml detects both ecosystems. This is
// the zero-config acceptance test for the registry integration.
func TestDetectEcosystems_PolyglotWithJavaAndGo_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("{}"), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.hasGo, "go.mod → Go detected")
	assert.True(t, eco.hasJava, "pom.xml → Java detected via registry")
}

// ── ResolvedDep ───────────────────────────────────────────────────────────────

// TestResolvedDep_ZeroValue verifies that the zero value of ResolvedDep is safe
// (no required fields panic on use). The gate treats empty DepType as runtime.
func TestResolvedDep_ZeroValue(t *testing.T) {
	var d ResolvedDep
	assert.Equal(t, "", d.Name, "zero Name is empty string")
	assert.Equal(t, "", d.Version, "zero Version is empty string")
	assert.Equal(t, "", d.DepType,
		"zero DepType is empty string (gate treats this as runtime — conservative)")
}

// ── mergeDepType ─────────────────────────────────────────────────────────────

// TestMergeDepType_EmptyDepType_TreatedAsRuntime is the key invariant:
// an empty dep-type MUST be promoted to "runtime" before comparison.
// Failing to do so allows a prior "dev" entry to survive, suppressing a
// runtime-reachable vulnerability through the dev_only gate (false-clean pass).
func TestMergeDepType_EmptyDepType_TreatedAsRuntime(t *testing.T) {
	m := map[string]string{"VULN-1": "dev"} // advisory already tagged dev
	mergeDepType(m, "VULN-1", "")            // empty dep-type = unknown
	assert.Equal(t, "runtime", m["VULN-1"],
		"empty dep-type must promote to runtime (unknown dep-type ≠ safe; "+
			"must not leave advisory tagged dev when an unknown-type dep matches it)")
}

// TestMergeDepType_RuntimeWinsOverDev verifies that "runtime" overwrites an
// existing "dev" entry. The same advisory matched by a dev dep and then a
// runtime dep must end up tagged runtime.
func TestMergeDepType_RuntimeWinsOverDev(t *testing.T) {
	m := map[string]string{"VULN-1": "dev"}
	mergeDepType(m, "VULN-1", "runtime")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime dep-type must overwrite existing dev entry")
}

// TestMergeDepType_RuntimeWinsOverTest verifies that "runtime" overwrites
// an existing "test" entry (same as dev).
func TestMergeDepType_RuntimeWinsOverTest(t *testing.T) {
	m := map[string]string{"VULN-1": "test"}
	mergeDepType(m, "VULN-1", "runtime")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime dep-type must overwrite existing test entry")
}

// TestMergeDepType_RuntimeNotDowngradedByDev verifies that once an advisory
// is tagged "runtime", a subsequent "dev" dep cannot downgrade it.
func TestMergeDepType_RuntimeNotDowngradedByDev(t *testing.T) {
	m := map[string]string{"VULN-1": "runtime"}
	mergeDepType(m, "VULN-1", "dev")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime must not be downgraded to dev")
}

// TestMergeDepType_RuntimeNotDowngradedByEmpty verifies that once an advisory
// is tagged "runtime", a subsequent empty dep-type cannot downgrade it.
// (An empty dep would also become "runtime", so this is a no-op — but the
// map must remain "runtime" regardless.)
func TestMergeDepType_RuntimeNotDowngradedByEmpty(t *testing.T) {
	m := map[string]string{"VULN-1": "runtime"}
	mergeDepType(m, "VULN-1", "")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime must not be changed by an empty dep-type")
}

// TestMergeDepType_DevStoredOnFirstSeen verifies that "dev" is stored when
// the advisory has no prior entry.
func TestMergeDepType_DevStoredOnFirstSeen(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "dev")
	assert.Equal(t, "dev", m["VULN-1"],
		"dev dep-type must be stored when advisory has no prior entry")
}

// TestMergeDepType_TestStoredOnFirstSeen verifies that "test" is stored when
// the advisory has no prior entry.
func TestMergeDepType_TestStoredOnFirstSeen(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "test")
	assert.Equal(t, "test", m["VULN-1"],
		"test dep-type must be stored when advisory has no prior entry")
}

// TestMergeDepType_FirstNonRuntimeNotOverwrittenByLaterNonRuntime verifies
// that a second non-runtime dep type does not overwrite the first.
func TestMergeDepType_FirstNonRuntimeNotOverwrittenByLaterNonRuntime(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "dev")
	mergeDepType(m, "VULN-1", "test") // should not overwrite "dev"
	assert.Equal(t, "dev", m["VULN-1"],
		"a second non-runtime dep-type must not overwrite the first non-runtime entry")
}

// TestMergeDepType_MultipleAdvisories verifies that mergeDepType maintains
// independent state per advisory ID (no cross-contamination).
func TestMergeDepType_MultipleAdvisories(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-A", "dev")
	mergeDepType(m, "VULN-B", "runtime")
	mergeDepType(m, "VULN-C", "")
	assert.Equal(t, "dev", m["VULN-A"], "VULN-A must be dev")
	assert.Equal(t, "runtime", m["VULN-B"], "VULN-B must be runtime")
	assert.Equal(t, "runtime", m["VULN-C"],
		"VULN-C must be runtime (empty dep-type promoted)")
}

// ── NormalizeName ─────────────────────────────────────────────────────────────

// TestLaneAAdapter_NormalizeName_NilIsIdentity verifies that when NormalizeName
// is nil, the adapter does not transform the package name. Maven coordinates
// are case-sensitive; lowercasing an artifactId would miss OSV records.
func TestLaneAAdapter_NormalizeName_NilIsIdentity(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterLaneAAdapter(LaneAAdapter{
			Ecosystem:     "Maven",
			Language:      "java",
			DetectFiles:   []string{"pom.xml"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
			NormalizeName: nil, // explicitly nil
		})
		adapters := LaneAAdapters()
		require.Len(t, adapters, 1)
		assert.Nil(t, adapters[0].NormalizeName,
			"nil NormalizeName means identity; caller must use dep.Name as-is for Maven")
	})
}

// TestLaneAAdapter_NormalizeName_FuncIsCalledWithDepName verifies that a
// non-nil NormalizeName function is stored and can be invoked. This proves
// the field is wired correctly for future adapters (e.g. PyPI).
func TestLaneAAdapter_NormalizeName_FuncIsCalledWithDepName(t *testing.T) {
	withCleanRegistry(t, func() {
		var calledWith string
		RegisterLaneAAdapter(LaneAAdapter{
			Ecosystem:   "Maven",
			Language:    "java",
			DetectFiles: []string{"pom.xml"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) {
				return nil, true, nil
			},
			NormalizeName: func(name string) string {
				calledWith = name
				return "normalized:" + name
			},
		})
		adapters := LaneAAdapters()
		require.Len(t, adapters, 1)
		require.NotNil(t, adapters[0].NormalizeName)
		result := adapters[0].NormalizeName("Com.Example:MyLib")
		assert.Equal(t, "normalized:Com.Example:MyLib", result)
		assert.Equal(t, "Com.Example:MyLib", calledWith,
			"NormalizeName must be called with the exact name from the lockfile")
	})
}

// ── RegisterLaneAAdapter panic on unknown language ─────────────────────────

// TestRegisterLaneAAdapter_PanicsOnUnknownLanguage verifies that registering
// an adapter whose Language is not handled by setLaneAFlag panics at init time.
// This prevents the "silent no-op detection trap": an adapter with an
// unhandled language is detected (DetectFiles match) but never runs, with no
// warning to the operator.
func TestRegisterLaneAAdapter_PanicsOnUnknownLanguage(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.Panics(t, func() {
			RegisterLaneAAdapter(LaneAAdapter{
				Ecosystem:     "NuGet",
				Language:      "nuget", // not in setLaneAFlag switch
				DetectFiles:   []string{"*.csproj"},
				ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
			})
		}, "registering an adapter with an unhandled Language must panic at init time "+
			"(prevents silent coverage gap)")
	})
}

// TestRegisterLaneAAdapter_JavaDoesNotPanic verifies that the Java adapter
// (a known language) registers without panic.
func TestRegisterLaneAAdapter_JavaDoesNotPanic(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.NotPanics(t, func() {
			RegisterLaneAAdapter(LaneAAdapter{
				Ecosystem:     "Maven",
				Language:      "java",
				DetectFiles:   []string{"pom.xml"},
				ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
			})
		}, "java is a known language; RegisterLaneAAdapter must not panic")
	})
}

// ── laneALanguageKnown ────────────────────────────────────────────────────────

// TestLaneALanguageKnown_JavaIsKnown verifies that "java" is a known language.
func TestLaneALanguageKnown_JavaIsKnown(t *testing.T) {
	assert.True(t, laneALanguageKnown("java"),
		"java must be a known language (has a case in setLaneAFlag)")
}

// TestLaneALanguageKnown_UnknownLanguage verifies that unknown languages
// return false.
func TestLaneALanguageKnown_UnknownLanguage(t *testing.T) {
	assert.False(t, laneALanguageKnown("nuget"),
		"nuget is not in the setLaneAFlag switch; must return false")
	assert.False(t, laneALanguageKnown(""),
		"empty string is not a known language")
	assert.False(t, laneALanguageKnown("python"),
		"python is not a Lane-A language (uses the plugin path); must return false")
}
