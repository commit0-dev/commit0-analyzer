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
