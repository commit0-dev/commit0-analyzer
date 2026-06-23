/**
 * Parse a unified diff (git format) and return the list of source files it
 * touches, along with the new-side line numbers that were added or modified.
 *
 * Only JS/TS source files are returned (.js .cjs .mjs .jsx .ts .cts .mts .tsx).
 * Deleted files (/dev/null new path) and pure binary diffs are skipped.
 * The function never throws — malformed input yields an empty array.
 */

import path from "node:path";
import type { ChangedFile } from "./types.js";

// ── constants ─────────────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  ".js", ".cjs", ".mjs", ".jsx",
  ".ts", ".cts", ".mts", ".tsx",
]);

// Match the +++ line for the new file path.
// git diff uses +++ b/<path> ; plain diff uses +++ <path>
const NEW_FILE_RE = /^\+\+\+\s+(.+?)(?:\s+\d{4}-\d{2}-\d{2}.*)?$/;

// Match a hunk header: @@ -a,b +c,d @@ ...
const HUNK_HEADER_RE = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/;

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Strip the leading a/ or b/ git prefix from a diff path, if present.
 * Leaves other paths (e.g. /dev/null, bare paths) unchanged.
 */
function stripGitPrefix(p: string): string {
  if (p.startsWith("a/") || p.startsWith("b/")) {
    return p.slice(2);
  }
  return p;
}

/** Return true when the file extension is a JS/TS source file we care about. */
function isSourceFile(filePath: string): boolean {
  return SOURCE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

// ── main parser ───────────────────────────────────────────────────────────────

/**
 * Parse a unified diff string and return one ChangedFile per modified source
 * file.  The changedLines array contains 1-based new-side line numbers for
 * every line that was added (prefix "+") in the patch.
 *
 * Context lines (" " prefix) and removed lines ("-" prefix) are not included
 * in changedLines because they do not represent code in the post-patch file
 * that was introduced by the fix.
 */
export function parseUnifiedDiff(patch: string): ChangedFile[] {
  if (!patch || typeof patch !== "string") return [];

  const results: ChangedFile[] = [];
  const lines = patch.split("\n");

  let currentPath: string | null = null;
  let changedLines: number[] = [];
  let newLineCounter = 0; // tracks current new-side line position inside a hunk
  let inHunk = false; // true once we have seen the first @@ for the current file

  function flush(): void {
    if (currentPath !== null && changedLines.length > 0) {
      results.push({ path: currentPath, newContent: "", changedLines });
    }
    currentPath = null;
    changedLines = [];
    newLineCounter = 0;
    inHunk = false;
  }

  for (const line of lines) {
    // ── old file header (--- line) ────────────────────────────────────────
    // A "--- " line signals the start of a new file header pair and resets
    // the in-hunk state so the following "+++ " is correctly parsed as a header.
    if (line.startsWith("--- ")) {
      inHunk = false;
      // Do not flush here; the flush happens on the matching "+++ " line.
      continue;
    }

    // ── new file header ───────────────────────────────────────────────────
    // Only treat "+++ " as a file header when we are NOT inside a hunk body.
    // An added source line whose content begins with "++ " produces a diff
    // line starting with "+++ " but must stay in the hunk, not restart parsing.
    if (line.startsWith("+++ ") && !inHunk) {
      // Flush previous file
      flush();

      const m = NEW_FILE_RE.exec(line);
      if (!m) continue;

      const rawPath = m[1].trim();

      // Deleted file: new path is /dev/null → skip
      if (rawPath === "/dev/null") {
        currentPath = null;
        continue;
      }

      const stripped = stripGitPrefix(rawPath);

      if (!isSourceFile(stripped)) {
        currentPath = null;
        continue;
      }

      currentPath = stripped;
      changedLines = [];
      newLineCounter = 0;
      continue;
    }

    // Ignore lines when we're not tracking a source file
    if (currentPath === null) continue;

    // ── hunk header ───────────────────────────────────────────────────────
    if (line.startsWith("@@")) {
      const m = HUNK_HEADER_RE.exec(line);
      if (!m) continue;
      // newStart is 1-based; set the counter to one before so the first body
      // line increments it to newStart.
      newLineCounter = parseInt(m[1], 10) - 1;
      inHunk = true;
      continue;
    }

    // ── hunk body ─────────────────────────────────────────────────────────
    if (line.startsWith("+")) {
      // Added line: advance counter and record it
      newLineCounter++;
      changedLines.push(newLineCounter);
    } else if (line.startsWith("-")) {
      // Removed line: no new-side line number, counter does not advance
    } else if (line.startsWith(" ")) {
      // Context line: exists on the new side, advance counter
      newLineCounter++;
    }
    // Lines that don't match any prefix (e.g. "Binary files ...") are ignored
  }

  // Flush the last file
  flush();

  return results;
}
