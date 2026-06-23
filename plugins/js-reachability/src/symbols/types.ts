/**
 * Types for the vulnerable-symbol extractor.
 *
 * ChangedFile is the input shape produced by parseUnifiedDiff; it carries the
 * post-patch file content plus the new-side line numbers touched by the diff.
 *
 * VulnerableSymbol is the output shape consumed by downstream reachability
 * phases (e.g. P5 symbol-reachability checking).
 */

/** A source file touched by a security-fix patch. */
export interface ChangedFile {
  /** Relative path of the file (a/b/ git prefixes already stripped). */
  path: string;
  /** Full text of the file as it appears after the patch. */
  newContent: string;
  /**
   * 1-based line numbers on the new side of the diff that were added or
   * modified by the patch.  Context-only lines are NOT included.
   */
  changedLines: number[];
}

/** An exported symbol whose implementation was touched by a security fix. */
export interface VulnerableSymbol {
  /** Relative file path matching ChangedFile.path. */
  file: string;
  /**
   * Exported name as it appears in the public API:
   *   - top-level export:  "functionName" | "ClassName" | "varName"
   *   - default export:    "default"
   *   - class method:      "ClassName.methodName"
   *   - CJS named export:  "exportedName"
   *   - no enclosing export found: "module-level"
   */
  exportName: string;
  kind: "function" | "class" | "method" | "variable";
}
