/**
 * Confidence tier assignment — mirrors Go AssignConfidence exactly.
 *
 * Decision tree (in priority order):
 *   parse/type/resolve error in scope        → UNKNOWN
 *   package not imported anywhere            → NOT_REACHABLE
 *   symbol_level && symbol resolved && path  → SYMBOL_REACHABLE (+path)
 *   reachable (package node)                 → PACKAGE_REACHABLE
 *   UNKNOWN frontier on only candidate path  → UNKNOWN
 *   else                                     → NOT_REACHABLE
 *
 * Invariants:
 *   - unknown ≠ safe: any ambiguity → CONFIDENCE_UNKNOWN, never NOT_REACHABLE.
 *   - ReachabilityPath is nil for everything except SYMBOL_REACHABLE.
 *   - PACKAGE_REACHABLE requires symbolLevel==false and packageImported==true.
 */

import { Confidence } from "./gen/anst/v1/plugin.js";
import type { CallStep, ReachabilityPath } from "./gen/anst/v1/plugin.js";

// ── Input ─────────────────────────────────────────────────────────────────────

export interface ConfidenceInput {
  /** Whether a parse/type/resolve error was encountered in the analysis scope. */
  parseError: boolean;
  /** Whether the package is imported at least once in first-party code. */
  packageImported: boolean;
  /** Whether the advisory has symbol-level data (advisory.symbolLevel). */
  symbolLevel: boolean;
  /** Whether the specific vulnerable symbol could be resolved in the import graph. */
  symbolResolved: boolean;
  /** Whether BFS found a path from an entrypoint to an import site of the package. */
  bfsReachable: boolean;
  /**
   * Whether the only candidate path to the package is blocked by an UNKNOWN
   * frontier (dynamic specifier, parse error at a key node, etc.).
   * When true and bfsReachable is false → UNKNOWN, never NOT_REACHABLE.
   */
  unknownFrontierOnOnlyPath: boolean;
  /**
   * BFS path steps for SYMBOL_REACHABLE. Only consulted when symbolResolved
   * and bfsReachable are both true.
   */
  bfsPath?: CallStep[];
}

// ── Output ────────────────────────────────────────────────────────────────────

export interface ConfidenceResult {
  confidence: Confidence;
  /** Populated only when confidence === CONFIDENCE_SYMBOL_REACHABLE. */
  path?: ReachabilityPath;
}

// ── Decision tree ─────────────────────────────────────────────────────────────

/**
 * Assign a confidence tier given the analysis inputs.
 * Pure function — no I/O, no side effects.
 */
export function assignConfidence(inp: ConfidenceInput): ConfidenceResult {
  // 1. Parse/type/resolve error in scope → UNKNOWN (conservative)
  if (inp.parseError) {
    return { confidence: Confidence.CONFIDENCE_UNKNOWN };
  }

  // 2. Package not imported anywhere via static edges.
  // But if an UNKNOWN frontier in a reachable file is the only candidate path,
  // the dynamic call could be loading this package → UNKNOWN, not NOT_REACHABLE.
  if (!inp.packageImported) {
    if (inp.unknownFrontierOnOnlyPath) {
      return { confidence: Confidence.CONFIDENCE_UNKNOWN };
    }
    return { confidence: Confidence.CONFIDENCE_NOT_REACHABLE };
  }

  // 3. Symbol resolved and BFS found a path → SYMBOL_REACHABLE with path.
  // Checked before the general reachable check so the higher-confidence tier wins.
  if (inp.symbolLevel && inp.symbolResolved && inp.bfsReachable && inp.bfsPath) {
    return {
      confidence: Confidence.CONFIDENCE_SYMBOL_REACHABLE,
      path: { steps: inp.bfsPath },
    };
  }

  // 4. Package reachable (BFS confirmed).
  // Covers both non-symbol advisories and symbol-level advisories where the
  // symbol could not be verified at the import site: knowing the package is
  // reachable is more informative than UNKNOWN, so we report PACKAGE_REACHABLE
  // rather than fabricating uncertainty about whether the package is reached.
  if (inp.bfsReachable) {
    return { confidence: Confidence.CONFIDENCE_PACKAGE_REACHABLE };
  }

  // 6. UNKNOWN frontier blocks the only candidate path → UNKNOWN (not NOT_REACHABLE)
  if (inp.unknownFrontierOnOnlyPath) {
    return { confidence: Confidence.CONFIDENCE_UNKNOWN };
  }

  // 7. Clean graph, no path found → NOT_REACHABLE
  return { confidence: Confidence.CONFIDENCE_NOT_REACHABLE };
}
