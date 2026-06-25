/**
 * Deterministic BFS over the import graph.
 *
 * The import graph for JS/TS is module-level: nodes are first-party and
 * traversable dep source files, edges are import/require relationships.
 * Third-party packages with reduced/none fidelity are UNKNOWN frontier leaves.
 *
 * BFS from sorted roots; edges sorted by stable key before enqueue.
 * This guarantees byte-identical traversal across runs regardless of Map/Set
 * iteration order (the same class of bug that hit the Go engine).
 *
 * UNKNOWN frontier scoping:
 *   - UNKNOWN frontiers WITHOUT couldReach (from ANY reachable file, first-party
 *     OR dep source) block NOT_REACHABLE for ALL installed packages (global scope).
 *     Node's hoisting means dynamic specifiers can resolve to any package, so
 *     scoping to a dep's declared set is unsound (C1/C2 false NOT_REACHABLE).
 *   - UNKNOWN frontiers WITH couldReach (always scoped) block NOT_REACHABLE only
 *     for packages in the couldReach set. Used for reduced/none fidelity deps:
 *     the TRANSITIVE closure of declared deps is the sound bound for what a
 *     bundled/minified dep could load at runtime (C3: deep deps in the closure
 *     must be UNKNOWN, not just the one-level declared set).
 */

import path from "node:path";
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
  unknownFrontiers: UnknownMarker[],
  targetPackage?: string
): BfsResult {
  if (importSites.length === 0) {
    // No static import sites found. Check unknown frontiers:
    // 1. First-party reachable files with any frontier → globally UNKNOWN.
    // 2. Dep-internal frontiers with couldReach listing the target → UNKNOWN.
    const unknownFrontierBlocks = checkUnknownFrontierBlocks(
      unknownFrontiers,
      reachableFiles,
      targetPackage
    );
    return {
      reachable: false,
      path: [],
      unknownFrontierBlocks,
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

  // No reachable concrete import site. Check whether an UNKNOWN frontier
  // in a reachable file could have led to the package.
  const unknownFrontierBlocks = checkUnknownFrontierBlocks(
    unknownFrontiers,
    reachableFiles,
    targetPackage
  );

  return { reachable: false, path: [], unknownFrontierBlocks };
}

/**
 * Determine whether any reachable UNKNOWN frontier blocks a NOT_REACHABLE
 * verdict for the target package.
 *
 * Priority rules:
 *   1. A frontier WITH a couldReach set (scoped, regardless of fromFile)
 *      — blocks NOT_REACHABLE only when targetPackage is in couldReach.
 *      Used for: reduced/none fidelity deps whose transitive declared-dep
 *      closure cannot be proven unreachable.
 *   2. A frontier WITHOUT couldReach (from ANY reachable file, first-party OR dep)
 *      — global: blocks NOT_REACHABLE for all packages.
 *      Used for: dynamic dispatch (require(var)/import(expr)/eval/Function) in
 *      any reachable file. Node's hoisting means a dynamic specifier can resolve
 *      to ANY installed package, so the frontier cannot be safely scoped.
 *
 * Soundness invariant (C1/C2):
 *   Dynamic specifiers in reachable dep files are now emitted WITHOUT couldReach
 *   (global). The previous scoped model (couldReach = dep's declared deps) caused
 *   false NOT_REACHABLE when:
 *     C1: dep declares nothing → couldReach was empty → frontier dropped by
 *         makeUnknownMarker → checkUnknownFrontierBlocks never saw it
 *     C2: dep declares some pkgs → hoisted pkgs outside the list were missed
 *
 * When targetPackage is undefined (legacy call without package context), both
 * rules still apply correctly: scoped frontiers are skipped (no targetPackage
 * to check), unscoped frontiers remain globally blocking.
 */
function checkUnknownFrontierBlocks(
  unknownFrontiers: UnknownMarker[],
  reachableFiles: Set<string>,
  targetPackage?: string
): boolean {
  for (const u of unknownFrontiers) {
    if (!reachableFiles.has(u.fromFile)) continue;

    if (u.couldReach !== undefined) {
      // Scoped frontier: only blocks NOT_REACHABLE when targetPackage is listed.
      if (targetPackage !== undefined && u.couldReach.includes(targetPackage)) {
        return true;
      }
      // Does not fall through to the global check — couldReach means scoped.
      continue;
    }

    // Unscoped frontier (no couldReach): GLOBAL — blocks NOT_REACHABLE for all
    // packages regardless of whether fromFile is first-party or inside node_modules.
    // Dynamic specifiers in reachable dep files are now emitted without couldReach
    // because Node's hoisting means they can resolve to any installed package.
    return true;
  }
  return false;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns true when an absolute file path is inside a node_modules directory. */
function isInsideNodeModules(file: string): boolean {
  return file.includes(`${path.sep}node_modules${path.sep}`);
}
