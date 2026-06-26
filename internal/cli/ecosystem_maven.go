package cli

// ecosystem_maven.go — Lane-A lockfile-static adapter for Maven (Java/Kotlin/Scala).
//
// OSV ecosystem: "Maven" (covers all JVM languages that publish to Maven Central).
// Maximum confidence: PACKAGE_REACHABLE (OSV Maven advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate build.gradle[.kts] — Groovy/Kotlin code = arbitrary code execution.
//   - NEVER run mvn, gradle, ./mvnw, ./gradlew, or any build tool wrapper.
//   - ONLY parse the static gradle.lockfile when present.
//   - For pom.xml-only projects, return (nil, false, nil) because the full transitive
//     Maven closure requires `mvn help:effective-pom` (a tool run) which is ACE-unsafe
//     on untrusted repos. The caller marks the scan incomplete (unknown ≠ safe).
//
// Lockfile strategy:
//   - gradle.lockfile present → parse full transitive closure → complete=true.
//   - pom.xml or build.gradle only (no lockfile) → return (nil, false, nil) → incomplete.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
)

func init() {
	// Register the real Maven (JVM) Lane-A adapter.
	//
	// DetectFiles includes gradle.lockfile so that a project root containing only
	// gradle.lockfile (no build.gradle co-located) is still detected as a Java
	// project. Without it, detectEcosystems returns hasJava=false → the Lane-A
	// loop is skipped → false-clean exit 0 (advisories never queried).
	RegisterLaneAAdapter(LaneAAdapter{
		Ecosystem:     advisory.EcosystemMaven,
		Language:      "java",
		DetectFiles:   []string{"pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts"},
		ParseLockfile: parseMavenLockfile,
		// NormalizeName is nil: Maven coordinates (groupId:artifactId) are
		// case-sensitive and OSV records preserve their original casing.
		// Do NOT lowercase Maven names.
		NormalizeName: nil,
	})
}

// parseMavenLockfile is the LaneAAdapter.ParseLockfile implementation for the
// Maven (JVM) ecosystem.
//
// Resolution priority:
//  1. gradle.lockfile — if present, parse it as the full transitive dep closure.
//     Returns (deps, true, nil). This is the only path that returns complete=true.
//  2. pom.xml / build.gradle present but no gradle.lockfile — return (nil, false, nil).
//     The full Maven transitive closure requires running `mvn help:effective-pom`
//     (ACE risk on untrusted repos). Without a lockfile we cannot provide a complete
//     closure, so we degrade to incomplete (unknown ≠ safe).
//  3. Nothing present — return (nil, false, nil).
//
// NEVER return a partial closure with complete=false (LaneAAdapter contract): a
// partial dep list would produce false NOT_REACHABLE for the missing transitive
// portion, silently dropping real vulnerabilities.
func parseMavenLockfile(root string) ([]ResolvedDep, bool, error) {
	return parseGradleLockfile(root)
}

// parseGradleLockfile reads and parses a gradle.lockfile at root/gradle.lockfile.
//
// Gradle dependency locking (Gradle 4.8+) produces gradle.lockfile when a project
// enables `dependencyLocking {}`. The file contains the fully-resolved transitive
// closure of all configurations, making it a safe static lockfile for Lane-A.
//
// File format:
//
//	# comment
//	groupId:artifactId:version=config1,config2,...
//	empty=
//
// Configuration → DepType mapping:
//   - any configuration containing "test" (case-insensitive) → "test"
//   - all others (compileClasspath, runtimeClasspath, api, implementation,
//     runtimeOnly, …) → "runtime"
//
// When the same coordinate appears in both runtime and test configurations (e.g.
// "runtimeClasspath,testCompileClasspath"), "runtime" wins over "test" — consistent
// with mergeDepType semantics and the "unknown ≠ safe" invariant: we must not
// suppress a runtime advisory by accidentally tagging it as test-only.
//
// Returns:
//   - (nil, false, nil) when gradle.lockfile is absent (no error: caller decides next step).
//   - (deps, true, nil) when gradle.lockfile is present and parseable (even if empty).
//   - Malformed dep lines are skipped silently; the lockfile is still considered
//     complete if the file itself is parseable (gradle.lockfile is machine-generated).
func parseGradleLockfile(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "gradle.lockfile")
	f, err := os.Open(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent lockfile is not an error; caller can try pom.xml next.
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	var deps []ResolvedDep

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comment lines and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// "empty=" is the sentinel for "no locked deps" — valid, skip.
		if line == "empty=" {
			continue
		}

		// Format: groupId:artifactId:version=config1,config2,...
		// Split on "=" first to separate the coordinate from the configurations.
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			// Malformed line: no "=" separator; skip.
			continue
		}
		coordinate := line[:eqIdx]
		configPart := line[eqIdx+1:]

		// The coordinate must have exactly two ":" separators: group:artifact:version.
		parts := strings.SplitN(coordinate, ":", 3)
		if len(parts) != 3 {
			// Malformed coordinate (too few or too many segments); skip.
			continue
		}
		groupID := parts[0]
		artifactID := parts[1]
		version := parts[2]

		if groupID == "" || artifactID == "" || version == "" {
			// Any empty segment is invalid; skip.
			continue
		}

		// Compute DepType from the configuration list.
		// "runtime" wins over "test" (unknown ≠ safe: conservative default).
		depType := gradleConfigsToDepType(configPart)

		deps = append(deps, ResolvedDep{
			Name:    groupID + ":" + artifactID,
			Version: version,
			DepType: depType,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}

	// gradle.lockfile is present and parseable: the closure is complete (it is
	// machine-generated by Gradle's dependency locking feature and covers the
	// full transitive closure of all enabled configurations).
	return deps, true, nil
}

// gradleConfigsToDepType maps a comma-separated Gradle configuration list to a
// DepType string. "runtime" wins over "test": if any configuration is a runtime
// configuration, the dep is tagged runtime regardless of test configurations also
// being present.
//
// Conservative classification: anything not clearly "test-only" is tagged "runtime".
// This matches the "unknown ≠ safe" invariant — we must not suppress a runtime
// advisory by accidentally tagging it as test-only.
//
// Known runtime configurations: compileClasspath, runtimeClasspath, api,
// implementation, runtimeOnly, compile (legacy), runtime (legacy), provided.
// Known test configurations: testCompileClasspath, testRuntimeClasspath,
// testImplementation, testRuntimeOnly, testCompile (legacy), testRuntime (legacy).
// Integration-test configurations: integrationTestCompileClasspath,
// integrationTestRuntimeClasspath, functionalTestImplementation, etc.
//
// Classification uses isGradleTestConfig for word-boundary-aware detection:
// "test" is recognised only at a camelCase word boundary (start of name or
// after an uppercase letter), not as an arbitrary substring. This prevents
// false positives for config names like "attestationClasspath" or
// "contextClasspath" where "test" appears mid-word and is not semantically
// test-related. False negatives (unknown → runtime) are safer than false
// positives (unknown → test) per the "unknown ≠ safe" invariant.
func gradleConfigsToDepType(configPart string) string {
	if configPart == "" {
		// No configurations: unknown → runtime (conservative).
		return "runtime"
	}
	configs := strings.Split(configPart, ",")
	hasRuntime := false
	hasTestOnly := true

	for _, cfg := range configs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		if isGradleTestConfig(cfg) {
			// This configuration is test-related.
			continue
		}
		// Non-test configuration found → at least one runtime classification.
		hasRuntime = true
		hasTestOnly = false
	}

	if hasRuntime {
		return "runtime"
	}
	if hasTestOnly {
		return "test"
	}
	// All configs were empty strings (unusual); default to runtime.
	return "runtime"
}

// isGradleTestConfig reports whether cfg is a Gradle test configuration using
// word-boundary-aware matching. It recognises:
//   - Configs that start with "test" (case-insensitive): testCompileClasspath,
//     testRuntimeClasspath, testImplementation, testRuntimeOnly, etc.
//   - Configs that contain "Test" at a camelCase word start: integrationTestRuntime,
//     functionalTestCompileClasspath, smokeTestImplementation, etc.
//   - Configs that contain "TEST" (all-caps variant of the above).
//
// It does NOT match "test" as an arbitrary lowercase substring to avoid
// false positives for names like "attestationClasspath" or "contextClasspath",
// where "test" appears mid-word and is unrelated to testing.
func isGradleTestConfig(cfg string) bool {
	return strings.HasPrefix(strings.ToLower(cfg), "test") ||
		strings.Contains(cfg, "Test") ||
		strings.Contains(cfg, "TEST")
}
