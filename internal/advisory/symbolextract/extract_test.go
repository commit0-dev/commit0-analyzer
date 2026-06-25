package symbolextract_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/internal/advisory/symbolextract"
)

// makeEchoPlugin writes a tiny shell script to tmp that always prints the
// given JSON payload and exits 0.  Returns the path to the script.
func makeEchoPlugin(t *testing.T, payload string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-plugin.sh")
	content := "#!/bin/sh\nprintf '%s' '" + payload + "'\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	return script
}

// makeExitPlugin writes a script that exits with the given code.
func makeExitPlugin(t *testing.T, code int) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "exit-plugin.sh")
	content := "#!/bin/sh\nexit " + strconv.Itoa(code) + "\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	return script
}

// makeBadOutputPlugin writes a script that prints unparseable text and exits 0.
func makeBadOutputPlugin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "bad-plugin.sh")
	content := "#!/bin/sh\nprintf 'not json'\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	return script
}

// TestExtract_ParsesSymbols verifies that a subprocess emitting a valid JSON
// symbol array is unmarshalled into []Symbol correctly.
//
// When the plugin omits the "module" field (JS/TS plugins do not set it),
// Symbol.Package must be the empty string so callers can fill it from context.
func TestExtract_ParsesSymbols(t *testing.T) {
	payload := `[{"file":"src/utils.ts","exportName":"sanitize","kind":"function"}]`
	plugin := makeEchoPlugin(t, payload)

	syms, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"--- a/src/utils.ts\n+++ b/src/utils.ts\n@@ -1,1 +1,1 @@\n-old\n+new\n",
		[]symbolextract.FileContent{{Path: "src/utils.ts", Content: "export function sanitize(s: string) { return s; }\n"}},
	)

	require.NoError(t, err)
	require.Len(t, syms, 1)
	assert.Equal(t, "sanitize", syms[0].Name)
	// No "module" field in payload → Package must be empty (JS/TS behaviour).
	assert.Equal(t, "", syms[0].Package)
}

// TestExtract_PopulatesPackageFromModule verifies that a "module" field in the
// plugin's JSON output is used to populate Symbol.Package.  This is the Python
// plugin path: the sidecar emits module-qualified names so that
// Symbol.Package carries the dotted module path (e.g.
// "celery.kombu.utils.encoding") rather than being hard-coded to "".
func TestExtract_PopulatesPackageFromModule(t *testing.T) {
	payload := `[{"file":"celery/kombu/utils/encoding.py","module":"celery.kombu.utils.encoding","exportName":"safe_decode","kind":"function"}]`
	plugin := makeEchoPlugin(t, payload)

	syms, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"--- a/celery/kombu/utils/encoding.py\n+++ b/celery/kombu/utils/encoding.py\n@@ -1,1 +1,2 @@\n def safe_decode(s):\n+    return s\n",
		[]symbolextract.FileContent{{Path: "celery/kombu/utils/encoding.py", Content: "def safe_decode(s):\n    return s\n"}},
	)

	require.NoError(t, err)
	require.Len(t, syms, 1)
	assert.Equal(t, "safe_decode", syms[0].Name)
	assert.Equal(t, "celery.kombu.utils.encoding", syms[0].Package)
}

// TestExtract_EmptyArray verifies that a subprocess emitting [] produces an
// empty slice and no error (a fetch/extract miss is "no symbols", not an error).
func TestExtract_EmptyArray(t *testing.T) {
	plugin := makeEchoPlugin(t, "[]")

	syms, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"",
		nil,
	)

	require.NoError(t, err)
	assert.Empty(t, syms)
}

// TestExtract_NonZeroExit verifies that a subprocess that exits non-zero
// returns an error so the caller can degrade gracefully.
func TestExtract_NonZeroExit(t *testing.T) {
	plugin := makeExitPlugin(t, 1)

	_, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"",
		nil,
	)

	assert.Error(t, err)
}

// TestExtract_UnparsableOutput verifies that a subprocess that emits
// non-JSON text (but exits 0) returns an error.
func TestExtract_UnparsableOutput(t *testing.T) {
	plugin := makeBadOutputPlugin(t)

	_, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"",
		nil,
	)

	assert.Error(t, err)
}

// TestExtract_MultipleSymbols verifies that multiple symbols from the
// subprocess are all mapped correctly.
func TestExtract_MultipleSymbols(t *testing.T) {
	payload := `[{"file":"a.ts","exportName":"foo","kind":"function"},{"file":"a.ts","exportName":"Bar","kind":"class"}]`
	plugin := makeEchoPlugin(t, payload)

	syms, err := symbolextract.Extract(
		context.Background(),
		plugin,
		"diff content",
		[]symbolextract.FileContent{{Path: "a.ts", Content: "export function foo(){}\nexport class Bar{}\n"}},
	)

	require.NoError(t, err)
	require.Len(t, syms, 2)
	names := []string{syms[0].Name, syms[1].Name}
	assert.Contains(t, names, "foo")
	assert.Contains(t, names, "Bar")
}
