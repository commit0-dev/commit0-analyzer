/**
 * Shared parse guard thresholds used by both the call-graph builder and the
 * isolated parser worker.
 *
 * Feeding multi-megabyte bundles or minified files to the native oxc parser
 * can crash the process via OS memory pressure (uncatchable signal kill). Two
 * signals reliably identify these files before parsing:
 *   - total size: a 300KB+ JS/TS file is generated/vendored, not hand-authored
 *   - longest line: minified blobs pack code into hundreds-of-KB lines
 *
 * Both builder and worker must apply the same thresholds so the worker never
 * forwards a known-dangerous file to oxc.
 */

/** Files larger than this byte count are skipped without parsing. */
export const MAX_PARSE_BYTES = 300_000;

/** Files with any single line longer than this byte count are skipped. */
export const MAX_LINE_BYTES = 50_000;

/** True when any single line of s exceeds maxLen bytes (no array allocation). */
export function hasLineLongerThan(s: string, maxLen: number): boolean {
  let last = -1;
  let idx: number;
  while ((idx = s.indexOf("\n", last + 1)) !== -1) {
    if (idx - last - 1 > maxLen) return true;
    last = idx;
  }
  return s.length - last - 1 > maxLen;
}
