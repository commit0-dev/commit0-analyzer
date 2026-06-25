// Package symbolextract invokes the js-reachability plugin's --extract-symbols
// subcommand to identify which exported JS/TS symbols were touched by a
// security-fix patch.
//
// The plugin binary reads a JSON request from stdin and writes a JSON array of
// symbol objects to stdout.  This package handles subprocess lifecycle, JSON
// marshalling, and maps the plugin output to the advisory.Symbol type.
//
// A subprocess that exits non-zero or emits unparseable output returns an
// error; the caller decides how to degrade (e.g. fall back to package-level
// confidence).  An empty array from the plugin ("no symbols found") is not an
// error — it returns an empty slice and nil.
package symbolextract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/ducthinh993/anst-analyzer/internal/advisory"
)

// FileContent carries the post-fix content of a single source file.
type FileContent struct {
	// Path must be the repo-relative form produced by the plugin's
	// parseUnifiedDiff (e.g. "src/utils.ts", not "a/src/utils.ts" or an
	// absolute path).  It must match the path as it appears in the diff
	// exactly.  A mismatch causes the file to be silently dropped on the
	// plugin side with a diagnostic on the plugin's stderr — no symbols are
	// extracted for it and no error is returned by Extract.
	Path    string
	Content string
}

// pluginRequest is the JSON shape written to the plugin's stdin.
type pluginRequest struct {
	Patch string              `json:"patch"`
	Files []pluginFileContent `json:"files"`
}

type pluginFileContent struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// pluginSymbol is one element of the JSON array the plugin writes to stdout.
type pluginSymbol struct {
	File       string `json:"file"`
	ExportName string `json:"exportName"`
	Kind       string `json:"kind"`
}

// Extract spawns pluginBin with --extract-symbols, sends the patch and file
// contents to its stdin, and returns the symbols the plugin identifies.
//
// pluginBin must be the path to the compiled js-reachability binary (or any
// executable that honours the same stdin/stdout protocol).
//
// Path contract: each FileContent.Path must be the repo-relative path that
// appears in the diff after the plugin strips the git "a/"/"b/" prefix (e.g.
// "src/utils.ts").  Callers fetching file content from the fix commit must use
// the same path form.  A mismatch causes the plugin to drop the file and emit
// a diagnostic on its stderr; Extract still returns the symbols it could
// extract and does not treat a miss as an error.
//
// Returns an empty slice and nil error when the plugin emits [].
// Returns an error when the subprocess exits non-zero or stdout is not valid JSON.
func Extract(ctx context.Context, pluginBin, patch string, files []FileContent) ([]advisory.Symbol, error) {
	// Build the request payload.
	pfiles := make([]pluginFileContent, 0, len(files))
	for _, f := range files {
		pfiles = append(pfiles, pluginFileContent(f))
	}
	req := pluginRequest{Patch: patch, Files: pfiles}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("symbolextract: marshal request: %w", err)
	}

	// Spawn the plugin.
	cmd := exec.CommandContext(ctx, pluginBin, "--extract-symbols") //nolint:gosec
	cmd.Stdin = bytes.NewReader(reqJSON)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("symbolextract: plugin exited with error: %w", err)
	}

	// Unmarshal the symbol array.
	var raw []pluginSymbol
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("symbolextract: parse plugin output: %w", err)
	}

	if len(raw) == 0 {
		return nil, nil
	}

	syms := make([]advisory.Symbol, 0, len(raw))
	for _, s := range raw {
		syms = append(syms, advisory.Symbol{
			// Package is not known at this layer (JS has no import-path concept
			// equivalent to Go); leave it empty so callers can fill it from context.
			Package: "",
			Name:    s.ExportName,
		})
	}
	return syms, nil
}
