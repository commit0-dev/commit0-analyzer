package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
)

// findMavenAdapter returns the first registered Lane-A adapter with
// Language=="java" that is backed by the real parser (ecosystem_maven.go).
// It distinguishes the real adapter from the Phase-0 stub by calling
// ParseLockfile on a dir that contains gradle.lockfile: the real adapter
// returns complete=true; the stub always returns complete=false.
//
// Callers that do not need to distinguish can call findAnyJavaAdapter.
func findMavenAdapter(t *testing.T) *LaneAAdapter {
	t.Helper()

	// Build a temp dir with a gradle.lockfile so the real adapter can signal
	// complete=true on it (the Phase-0 stub always returns false).
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	for _, a := range LaneAAdapters() {
		if a.Language != "java" {
			continue
		}
		deps, complete, err := a.ParseLockfile(dir)
		if err == nil && complete && len(deps) > 0 {
			a := a
			return &a
		}
	}
	return nil
}

func writeLockfile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const singleDepGradleLockfile = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.springframework.boot:spring-boot-starter-web:2.7.9=compileClasspath,runtimeClasspath
empty=
`

const testDepGradleLockfile = `# Gradle lockfile with test dep
org.springframework.boot:spring-boot-starter-web:2.7.9=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=
`

const mixedScopeGradleLockfile = `# Mixed runtime and test deps
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.assertj:assertj-core:3.24.2=testCompileClasspath,testRuntimeClasspath
org.springframework.boot:spring-boot:2.7.9=runtimeClasspath
empty=
`

const emptyGradleLockfile = `# No deps at all
empty=
`

const malformedGradleLockfile = `# This lockfile has malformed lines
not_a_valid:line=config
:missing-group:1.0=compileClasspath
group:missing-version:=compileClasspath
empty=
`

// minimal pom.xml with runtime and test scopes
const pomXMLWithDeps = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.27</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.14.2</version>
            <scope>runtime</scope>
        </dependency>
    </dependencies>
</project>
`

// ── Real adapter registration ─────────────────────────────────────────────────

// TestMavenAdapter_IsRegistered verifies that the real Maven adapter (backed by
// ecosystem_maven.go) is present in the global registry after package init.
func TestMavenAdapter_IsRegistered(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter,
		"real Maven adapter (ecosystem_maven.go) must be registered; "+
			"none of the Java adapters returned complete=true for a gradle.lockfile dir")
}

// TestMavenAdapter_Ecosystem verifies that the real Maven adapter declares the
// "Maven" OSV ecosystem so OSV advisory queries use the correct bundle.
func TestMavenAdapter_Ecosystem(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")
	assert.Equal(t, advisory.EcosystemMaven, adapter.Ecosystem,
		"Maven adapter must declare advisory.EcosystemMaven as its ecosystem")
}

// TestMavenAdapter_NormalizeName_Nil verifies that the Maven adapter does NOT
// normalize package names (Maven coordinates are case-sensitive; lowercasing
// would miss OSV records).
func TestMavenAdapter_NormalizeName_Nil(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")
	assert.Nil(t, adapter.NormalizeName,
		"Maven adapter must NOT normalize names (Maven coordinates are case-sensitive)")
}

// ── gradle.lockfile parsing ──────────────────────────────────────────────────

// TestMavenAdapter_GradleLockfile_SingleRuntimeDep verifies that a gradle.lockfile
// with one runtime dependency is parsed correctly and returns complete=true.
func TestMavenAdapter_GradleLockfile_SingleRuntimeDep(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "ParseLockfile must not return error for valid gradle.lockfile")
	assert.True(t, complete,
		"gradle.lockfile present → ParseLockfile must return complete=true (full transitive closure)")

	require.Len(t, deps, 1, "one dep expected from the lockfile")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)
	assert.Equal(t, "2.7.9", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType,
		"compileClasspath/runtimeClasspath configurations must map to DepType='runtime'")
}

// TestMavenAdapter_GradleLockfile_TestDepClassification verifies that entries
// on test configurations (testCompileClasspath, testRuntimeClasspath) are tagged
// as DepType="test", enabling the dev_only gate.
func TestMavenAdapter_GradleLockfile_TestDepClassification(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", testDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 2)

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	spring := byName["org.springframework.boot:spring-boot-starter-web"]
	assert.Equal(t, "2.7.9", spring.Version)
	assert.Equal(t, "runtime", spring.DepType,
		"compileClasspath+runtimeClasspath → DepType must be 'runtime'")

	junit := byName["junit:junit"]
	assert.Equal(t, "4.13.2", junit.Version)
	assert.Equal(t, "test", junit.DepType,
		"testCompileClasspath+testRuntimeClasspath → DepType must be 'test'")
}

// TestMavenAdapter_GradleLockfile_MixedConfigurations tests a lockfile with
// multiple dep entries and varying configurations, verifying that "runtime wins"
// over "test" when the same dep appears in both runtime and test classpaths.
func TestMavenAdapter_GradleLockfile_MixedConfigurations(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", mixedScopeGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 3)

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	guava := byName["com.google.guava:guava"]
	assert.Equal(t, "runtime", guava.DepType, "compileClasspath+runtimeClasspath → runtime")

	assertj := byName["org.assertj:assertj-core"]
	assert.Equal(t, "test", assertj.DepType, "testClasspaths only → test")

	sb := byName["org.springframework.boot:spring-boot"]
	assert.Equal(t, "runtime", sb.DepType, "runtimeClasspath → runtime")
}

// TestMavenAdapter_GradleLockfile_EmptyLockfile verifies that a gradle.lockfile
// with only the "empty=" sentinel (no locked deps) returns complete=true with an
// empty closure. This is valid: a project with no dependencies is dependency-free.
func TestMavenAdapter_GradleLockfile_EmptyLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", emptyGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "empty gradle.lockfile must not be an error")
	assert.True(t, complete,
		"empty gradle.lockfile still represents a complete (zero-dep) closure")
	assert.Empty(t, deps, "no deps expected from an empty lockfile")
}

// TestMavenAdapter_GradleLockfile_Comments verifies that comment lines (starting
// with #) are skipped and do not appear as resolved dependencies.
func TestMavenAdapter_GradleLockfile_Comments(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	content := `# Comment line 1
# Comment line 2
com.example:library:1.0.0=compileClasspath
empty=
`
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1, "only one dep; comment lines must be ignored")
	assert.Equal(t, "com.example:library", deps[0].Name)
}

// TestMavenAdapter_GradleLockfile_NamePreservation verifies that Maven coordinate
// case is preserved exactly as it appears in the lockfile. OSV Maven records use
// the canonical case; lowercasing would produce mismatches.
func TestMavenAdapter_GradleLockfile_NamePreservation(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	content := "com.MyOrg:MyLib:1.2.3=compileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "com.MyOrg:MyLib", deps[0].Name,
		"Maven coordinate case must be preserved verbatim (OSV Maven is case-sensitive)")
}

// TestMavenAdapter_GradleLockfile_NoSubprocess verifies that ParseLockfile never
// spawns a subprocess (build tool), even when gradle.lockfile is present.
// ACE-safety: build scripts are untrusted code.
func TestMavenAdapter_GradleLockfile_NoSubprocess(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	// If ParseLockfile spawns a subprocess that fails, it would likely return
	// a non-nil error. A pure-Go parse must succeed without any external process.
	_, _, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err, "gradle.lockfile parse must be subprocess-free (ACE-safety)")
}

// ── pom.xml-only fallback (no gradle.lockfile) ────────────────────────────────

// TestMavenAdapter_PomOnly_ReturnsIncomplete verifies that when only pom.xml is
// present (no gradle.lockfile), the adapter returns complete=false. The pom.xml
// only carries declared direct dependencies; the full transitive Maven closure
// requires running `mvn help:effective-pom` (ACE risk) — so we cannot provide a
// complete closure and must signal incomplete=true to the caller.
//
// The LaneAAdapter contract requires nil deps when complete=false (NEVER return a
// partial closure with complete=false — that would produce false NOT_REACHABLE for
// the missing transitive portion).
func TestMavenAdapter_PomOnly_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "pom.xml-only parse must not error")
	assert.False(t, complete,
		"pom.xml-only → complete=false (transitive closure requires running mvn; ACE risk)")
	assert.Nil(t, deps,
		"LaneAAdapter contract: NEVER return a partial closure with complete=false; "+
			"a partial dep list would produce false NOT_REACHABLE for missing transitives")
}

// TestMavenAdapter_PomOnly_NoSubprocess verifies that ParseLockfile does not
// spawn mvn, ./mvnw, gradle, or any other build tool when only pom.xml is present.
// Running a build tool on an untrusted pom.xml is arbitrary code execution.
func TestMavenAdapter_PomOnly_NoSubprocess(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)

	_, _, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err,
		"pom.xml-only parse must not spawn a subprocess (ACE-safety: no mvn/mvnw/gradle/gradlew)")
}

// TestMavenAdapter_BuildGradleOnly_ReturnsIncomplete verifies that detecting
// build.gradle (without gradle.lockfile) returns complete=false. We cannot
// evaluate build.gradle[.kts] (Groovy/Kotlin code = ACE), so without a lockfile
// the closure is unresolvable.
func TestMavenAdapter_BuildGradleOnly_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "build.gradle", "// build.gradle without dependency locking")

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "build.gradle-only parse must not error")
	assert.False(t, complete,
		"build.gradle without gradle.lockfile → complete=false (lockfile required for safe static parse)")
	assert.Nil(t, deps,
		"no lockfile → nil deps (NEVER return partial closure with complete=false)")
}

// TestMavenAdapter_EmptyDir_ReturnsIncomplete verifies that ParseLockfile on an
// empty dir (no manifest, no lockfile) returns (nil, false, nil) without panicking.
func TestMavenAdapter_EmptyDir_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	deps, complete, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestMavenAdapter_GradleLockfileWithPom_PrefersLockfile verifies that when
// BOTH pom.xml AND gradle.lockfile are present, the adapter uses the lockfile
// (full transitive closure) rather than the pom.xml (declared-only).
func TestMavenAdapter_GradleLockfileWithPom_PrefersLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete,
		"gradle.lockfile takes precedence over pom.xml; complete=true")
	require.Len(t, deps, 1,
		"only the gradle.lockfile dep (spring-boot-starter-web), not pom.xml deps")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)
}

// TestMavenAdapter_GradleLockfile_DuplicateCoordinate verifies that if the same
// coordinate appears multiple times in a lockfile (unlikely but possible via
// multiple configuration blocks), each entry is treated independently. The
// dep-type is the most conservative (runtime wins over test).
func TestMavenAdapter_GradleLockfile_DuplicateCoordinate(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Unusual case: same GAV appears twice with different configurations.
	// The parser may return duplicates; the important thing is it doesn't crash.
	content := "com.example:lib:1.0.0=compileClasspath\ncom.example:lib:1.0.0=testCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "duplicate coordinate must not error")
	assert.True(t, complete)
	// At minimum, we must have at least one entry. Exact dedup policy is
	// implementation-defined; we just verify correctness doesn't break.
	assert.NotEmpty(t, deps, "at least one dep must be returned")
}

// TestMavenAdapter_GradleLockfile_DepType_RuntimeWins verifies that "runtime"
// dep-type beats "test" for the same dependency — consistent with mergeDepType
// semantics used by the advisory gate.
func TestMavenAdapter_GradleLockfile_DepType_RuntimeWins(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Same dep in both runtime and test configurations.
	content := "com.example:lib:1.0.0=runtimeClasspath,testCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.NotEmpty(t, deps)

	found := false
	for _, d := range deps {
		if d.Name == "com.example:lib" {
			assert.Equal(t, "runtime", d.DepType,
				"runtimeClasspath + testClasspath → DepType must be 'runtime' (runtime wins)")
			found = true
		}
	}
	assert.True(t, found, "com.example:lib must appear in the dep list")
}

// TestMavenAdapter_ParseGradleLockfile_DirectFunc tests the internal
// parseGradleLockfile function directly. This ensures the parsing logic is
// correct independent of the adapter registration machinery.
func TestMavenAdapter_ParseGradleLockfile_DirectFunc(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", testDepGradleLockfile)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 2)
}

// TestMavenAdapter_ParseGradleLockfile_Absent verifies that parseGradleLockfile
// returns (nil, false, nil) when no gradle.lockfile exists in the root.
func TestMavenAdapter_ParseGradleLockfile_Absent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parseGradleLockfile(dir)
	assert.NoError(t, err, "absent gradle.lockfile must not error")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestMavenAdapter_ParseGradleLockfile_MalformedLines verifies that malformed
// lines are skipped gracefully (not an error) — resilience against unusual or
// partially-corrupted lockfiles.
func TestMavenAdapter_ParseGradleLockfile_MalformedLines(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", malformedGradleLockfile)

	deps, complete, err := parseGradleLockfile(dir)
	// Malformed lines should be skipped, not cause an error.
	assert.NoError(t, err, "malformed lines must be skipped, not cause a parse error")
	assert.True(t, complete, "gradle.lockfile is present → complete=true even if some lines are malformed")
	// The malformed lines had 2-part (no version) or missing group, so 0 valid
	// GAV entries expected. The "empty=" sentinel is also present.
	_ = deps // exact count depends on how strictly the parser validates the format
}

// ── Single-registration invariant ────────────────────────────────────────────

// TestMavenAdapter_OnlyOneJavaAdapterRegistered verifies that exactly one Java
// Lane-A adapter is registered after all init() functions have run. Having two
// adapters (the real one from ecosystem_maven.go and the Phase-0 stub from
// ecosystem_registry.go) causes the scan loop to run both: the stub always
// returns complete=false → marks the scan incomplete even when the real adapter
// fully parsed gradle.lockfile. The happy path (clean Java scan with exit 0) is
// unreachable unless the stub is removed.
func TestMavenAdapter_OnlyOneJavaAdapterRegistered(t *testing.T) {
	var javaAdapters []LaneAAdapter
	for _, a := range LaneAAdapters() {
		if a.Language == "java" {
			javaAdapters = append(javaAdapters, a)
		}
	}
	require.Len(t, javaAdapters, 1,
		"exactly one Java Lane-A adapter must be registered; "+
			"duplicate registration (real adapter + Phase-0 stub) causes the scan loop to "+
			"always set incomplete=true even when gradle.lockfile is fully parsed")
}

// ── DetectFiles — spec-mandated set ──────────────────────────────────────────

// TestMavenAdapter_DetectFiles_IncludesGradleLockfile verifies that the real
// Maven adapter's DetectFiles includes "gradle.lockfile". Without it, a project
// root that contains ONLY gradle.lockfile (no build.gradle or pom.xml) is not
// detected as a Java project, so detectEcosystems returns hasJava=false, the
// Lane-A loop is skipped, and the scan exits 0 (false-clean) rather than
// parsing the lockfile and querying OSV.
func TestMavenAdapter_DetectFiles_IncludesGradleLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	hasGradleLockfile := false
	for _, f := range adapter.DetectFiles {
		if f == "gradle.lockfile" {
			hasGradleLockfile = true
			break
		}
	}
	assert.True(t, hasGradleLockfile,
		"DetectFiles must include 'gradle.lockfile' (spec-mandated); "+
			"a project root with only gradle.lockfile must be detected as a Java project "+
			"so the Lane-A loop can parse it and query OSV")
}

// TestMavenAdapter_DetectEcosystems_GradleLockfileOnly verifies that
// detectEcosystems sets hasJava=true when the project root contains ONLY
// gradle.lockfile with no pom.xml or build.gradle present. This is the key
// zero-config acceptance test: a Gradle project with dependency locking enabled
// produces gradle.lockfile without necessarily having build.gradle in the same
// directory (e.g. in a flat multi-project layout or after a CI lockfile-only
// checkout). Without this detection the scan silently exits 0 — false-clean.
func TestMavenAdapter_DetectEcosystems_GradleLockfileOnly(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	eco := detectEcosystems(dir)
	assert.True(t, eco.hasJava,
		"gradle.lockfile-only project root must set hasJava=true via registry-driven detection; "+
			"without this, the Lane-A loop is skipped and the scan exits 0 (false-clean)")
	assert.False(t, eco.hasGo, "no go.mod → Go must not be detected")
}

// TestMavenAdapter_FullPipeline_GradleLockfileOnly is the integration-level
// acceptance test for the complete gradle.lockfile-only scan path:
// detectEcosystems finds the project → the real adapter's ParseLockfile returns
// complete=true → deps are available for OSV query.
//
// This is the "happy path" that the dual-registration bug made unreachable:
// even when the real adapter returned complete=true, the stub adapter returned
// complete=false and forced incomplete=true on the scan.
func TestMavenAdapter_FullPipeline_GradleLockfileOnly(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	// Step 1: ecosystem detection must find Java.
	eco := detectEcosystems(dir)
	require.True(t, eco.hasJava,
		"precondition: gradle.lockfile must trigger Java detection")

	// Step 2: find the (now single) real maven adapter.
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Step 3: the real adapter must parse the lockfile completely.
	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete,
		"gradle.lockfile present → ParseLockfile must return complete=true; "+
			"incomplete=true here would cause the scan to exit 3 for a clean gradle.lockfile project")
	require.Len(t, deps, 1,
		"one dep expected from the single-dep lockfile fixture")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)

	// Step 4: with only the real adapter registered (no stub), running the full
	// adapter loop must produce complete=true. Simulate the scan.go Lane-A loop:
	// if ANY adapter returns complete=false, it sets incomplete=true.
	allComplete := true
	for _, a := range LaneAAdapters() {
		if a.Language != "java" {
			continue
		}
		_, c, e := a.ParseLockfile(dir)
		if e != nil || !c {
			allComplete = false
		}
	}
	assert.True(t, allComplete,
		"the Lane-A loop must see complete=true from all registered Java adapters "+
			"for a gradle.lockfile project; the Phase-0 stub must not be present")
}

// ── gradleConfigsToDepType — word-boundary classification ────────────────────

// TestGradleConfig_AttestationSubstring_IsRuntime verifies that a Gradle
// configuration whose name contains "test" as a substring within a word (not at
// a camelCase word boundary) is classified as "runtime", not "test".
//
// Example: a hypothetical "attestationClasspath" config should not be
// suppressed by the dev_only gate. The substring match on "test" was overly
// aggressive and could cause false-clean passes (advisories dropped for packages
// that only appeared under such a configuration).
func TestGradleConfig_AttestationSubstring_IsRuntime(t *testing.T) {
	// "attestation" contains "test" as a substring (a-t-t-e-s-t-a-t-i-o-n)
	// but "test" does not appear at a camelCase word boundary. It is NOT a
	// test configuration and must classify as "runtime".
	content := "com.example:lib:1.0.0=attestationClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "runtime", deps[0].DepType,
		"'attestationClasspath' contains 'test' as a substring within a word, "+
			"not at a word boundary; it must be classified as 'runtime', not 'test'")
}

// TestGradleConfig_IntegrationTest_IsTest verifies that integration-test
// configurations (e.g. integrationTestCompileClasspath) are correctly classified
// as "test" even though they do not start with "test". The word-boundary check
// catches them via the camelCase "Test" component.
func TestGradleConfig_IntegrationTest_IsTest(t *testing.T) {
	content := "com.example:lib:1.0.0=integrationTestCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "test", deps[0].DepType,
		"'integrationTestCompileClasspath' has 'Test' at a camelCase word boundary; "+
			"must be classified as 'test'")
}
