package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFixtureFile creates a file at dir/name with minimal valid content.
func writeFixtureFile(t *testing.T, dir, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644))
}

// TestDetectEcosystems_GoModOnly verifies that a directory containing only
// go.mod selects the Go ecosystem exclusively.
func TestDetectEcosystems_GoModOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")

	eco := detectEcosystems(dir)
	assert.True(t, eco.hasGo, "go.mod present → Go ecosystem selected")
	assert.False(t, eco.hasJS, "no package.json → JS ecosystem not selected")
}

// TestDetectEcosystems_PackageJSONOnly verifies that a directory containing
// only package.json selects the JS ecosystem exclusively.
func TestDetectEcosystems_PackageJSONOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	assert.False(t, eco.hasGo, "no go.mod → Go ecosystem not selected")
	assert.True(t, eco.hasJS, "package.json present → JS ecosystem selected")
}

// TestDetectEcosystems_BothFiles verifies that a polyglot repo with both
// go.mod and package.json selects both ecosystems.
func TestDetectEcosystems_BothFiles(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	assert.True(t, eco.hasGo, "go.mod present → Go ecosystem selected")
	assert.True(t, eco.hasJS, "package.json present → JS ecosystem selected")
}

// TestDetectEcosystems_NeitherFile verifies that an empty directory selects
// neither ecosystem.
func TestDetectEcosystems_NeitherFile(t *testing.T) {
	dir := t.TempDir()

	eco := detectEcosystems(dir)
	assert.False(t, eco.hasGo, "no go.mod → Go ecosystem not selected")
	assert.False(t, eco.hasJS, "no package.json → JS ecosystem not selected")
}

// TestResolveLanguage_Auto_GoOnly verifies that --language auto on a Go-only
// repo resolves to the Go ecosystem.
func TestResolveLanguage_Auto_GoOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")

	eco := detectEcosystems(dir)
	hasGo, hasJS, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.True(t, hasGo)
	assert.False(t, hasJS)
}

// TestResolveLanguage_Auto_JSOnly verifies that --language auto on a JS-only
// repo resolves to the JS ecosystem.
func TestResolveLanguage_Auto_JSOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	hasGo, hasJS, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.False(t, hasGo)
	assert.True(t, hasJS)
}

// TestResolveLanguage_Auto_Both verifies that --language auto on a polyglot
// repo resolves to both ecosystems.
func TestResolveLanguage_Auto_Both(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	hasGo, hasJS, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.True(t, hasGo)
	assert.True(t, hasJS)
}

// TestResolveLanguage_GoOverride forces Go even when package.json is present.
func TestResolveLanguage_GoOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	hasGo, hasJS, err := resolveLanguage("go", eco)
	require.NoError(t, err)
	assert.True(t, hasGo)
	assert.False(t, hasJS)
}

// TestResolveLanguage_JSOverride forces JS even when go.mod is present.
func TestResolveLanguage_JSOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	hasGo, hasJS, err := resolveLanguage("js", eco)
	require.NoError(t, err)
	assert.False(t, hasGo)
	assert.True(t, hasJS)
}

// TestResolveLanguage_UnknownValue verifies that an unrecognised --language value
// returns an operational error rather than silently falling through to auto-detect.
func TestResolveLanguage_UnknownValue(t *testing.T) {
	eco := ecosystems{hasGo: true, hasJS: true}
	_, _, err := resolveLanguage("bogus", eco)
	require.Error(t, err, "--language bogus must return an error")
	assert.Contains(t, err.Error(), "bogus", "error message must name the invalid value")
	assert.Contains(t, err.Error(), "auto|go|js", "error message must list valid values")
}
