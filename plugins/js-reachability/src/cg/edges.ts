/**
 * Edge types for the call graph.
 *
 * The call graph is flow-insensitive and conservative. Every edge records
 * the source file, the call site location, and the target — either a
 * first-party file or a third-party package import boundary.
 *
 * Import-boundary model: third-party dependencies are opaque. The call
 * graph's job is the first-party connection from an entrypoint to the
 * import site of a third-party package. We do not trace into dep internals.
 */

// ── Edge types ────────────────────────────────────────────────────────────────

/** A call edge within first-party code: file → file. */
export interface FirstPartyEdge {
  kind: "first-party";
  /** Absolute path of the calling file. */
  fromFile: string;
  /** Absolute path of the callee file. */
  toFile: string;
  /** 1-based line in the calling file where the import/call appears. */
  line: number;
  /** 1-based column. */
  column: number;
}

/**
 * An import site edge: first-party file → third-party package.
 * This is the boundary the reachability query checks.
 */
export interface ImportSiteEdge {
  kind: "import-site";
  /** Absolute path of the first-party file that imports the package. */
  fromFile: string;
  /** npm package name (e.g. "serialize-javascript"). */
  packageName: string;
  /** 1-based line number of the import/require statement. */
  line: number;
  /** 1-based column. */
  column: number;
}

export type CgEdge = FirstPartyEdge | ImportSiteEdge;

// ── Stable sort key ───────────────────────────────────────────────────────────

/**
 * Stable sort key for a call-graph edge: module-path + line + col.
 * Used to ensure deterministic BFS traversal order.
 */
export function edgeSortKey(e: CgEdge): string {
  const to = e.kind === "first-party" ? e.toFile : e.packageName;
  return `${e.fromFile}\x00${to}\x00${e.line}\x00${e.column}`;
}
