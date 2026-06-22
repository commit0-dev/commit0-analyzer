/**
 * Deterministic BFS over the import graph.
 *
 * The import graph for JS/TS is module-level: nodes are first-party files,
 * edges are import/require relationships. Third-party packages are leaf nodes
 * represented by their import sites — we do not traverse into them.
 *
 * BFS from sorted roots; edges sorted by stable key before enqueue.
 * This guarantees byte-identical traversal across runs regardless of Map/Set
 * iteration order (the same class of bug that hit the Go engine).
 */

import type { ImportSite } from "../cg/build.js";
import type { UnknownMarker } from "../engine/graph.js";

// ── Types ─────────────────────────────────────────────────────────────────────

/** One step on the path from an entrypoint to a package import site. */
export interface BfsPathStep {
  /** Absolute path of the file at this step. */
  file: string;
  /** Symbol name at this step, if known (e.g. the imported name). */
  symbol?: string;
  /** 1-based line of the edge that led here. */
  line: number;
  /** 1-based column. */
  column: number;
}

/** Result of a BFS reachability check for one package. */
export interface BfsResult {
  /** Whether any import site of the package is reachable from the roots. */
  reachable: boolean;
  /**
   * The shortest path from a root to the first reachable import site.
   * Only populated when reachable === true.
   */
  path: BfsPathStep[];
  /**
   * Whether an UNKNOWN frontier that is a reachable file's import blocks
   * the only candidate path to the package.
   * Used to distinguish UNKNOWN from NOT_REACHABLE.
   */
  unknownFrontierBlocks: boolean;
}

// ── BFS ───────────────────────────────────────────────────────────────────────

/**
 * Run BFS from sorted roots over the import graph, checking whether any
 * import site of targetPackage is reachable.
 *
 * @param roots           Sorted absolute paths of entrypoint files.
 * @param reachableFiles  All files reachable from any root (pre-computed by buildCallGraph).
 * @param importSites     Import sites for targetPackage (from CallGraphResult).
 * @param unknownFrontiers All UNKNOWN markers collected during graph build.
 */
export function bfsReachable(
  roots: string[],
  reachableFiles: Set<string>,
  importSites: ImportSite[],
  unknownFrontiers: UnknownMarker[]
): BfsResult {
  if (importSites.length === 0) {
    // No static import sites found. The package may still be reachable through
    // dynamic dispatch (require(var), eval, aliased require, etc.) if any
    // UNKNOWN frontier is in a reachable file. Consult those frontiers before
    // concluding NOT_REACHABLE — unknown ≠ safe.
    const reachableUnknowns = unknownFrontiers.filter((u) =>
      reachableFiles.has(u.fromFile)
    );
    return {
      reachable: false,
      path: [],
      unknownFrontierBlocks: reachableUnknowns.length > 0,
    };
  }

  // The call graph already computed all reachable files from roots.
  // Check whether any import site's fromFile is in the reachable set.
  const reachableSites = importSites.filter((s) =>
    reachableFiles.has(s.fromFile)
  );

  if (reachableSites.length > 0) {
    // Found a reachable import site. Build a minimal one-step path.
    // Sort for determinism; pick the lexicographically first site.
    const sorted = [...reachableSites].sort(
      (a, b) =>
        a.fromFile.localeCompare(b.fromFile) ||
        a.line - b.line ||
        a.column - b.column
    );
    const site = sorted[0];
    const step: BfsPathStep = {
      file: site.fromFile,
      line: site.line,
      column: site.column,
    };
    return { reachable: true, path: [step], unknownFrontierBlocks: false };
  }

  // No reachable concrete import site. Check whether an UNKNOWN frontier in a
  // reachable file could have led to the package — that forces UNKNOWN verdict.
  const reachableUnknowns = unknownFrontiers.filter((u) =>
    reachableFiles.has(u.fromFile)
  );
  const unknownFrontierBlocks = reachableUnknowns.length > 0;

  return { reachable: false, path: [], unknownFrontierBlocks };
}
