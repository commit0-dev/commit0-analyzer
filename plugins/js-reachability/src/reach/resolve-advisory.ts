/**
 * Per-advisory confidence resolver — the single source of truth for
 * BFS + symbol + parse-error + confidence wiring.
 *
 * Both analyze() and queryReachability() delegate to this function so that
 * the shipped path and the query path are always identical. Previously the
 * two callers re-implemented the logic independently and had diverged:
 *   - The empty-importSites branch only existed in query.ts (root cause of
 *     the false NOT_REACHABLE on the SHIPPED path, C1).
 *   - Parse-error scoping (reachable-filtered) only existed in analyze.ts.
 *   - Symbol resolution set symbolResolved=true without verifying the symbol
 *     was actually referenced at the import site (H1).
 *
 * Invariants:
 *   - unknown ≠ safe: UNKNOWN frontiers in reachable files are always
 *     consulted, even when importSites.length === 0.
 *   - Parse-error filtering is reachable-file-scoped (same as analyze.ts).
 *   - Symbol is only "resolved" when the named binding appears at a reachable
 *     import site — i.e. the import destructures or aliases that symbol name.
 *     If the symbol cannot be verified, we stay at PACKAGE_REACHABLE.
 *   - Pure function: no I/O, no side effects.
 */

import { bfsReachable } from "./bfs.js";
import { assignConfidence } from "../confidence.js";
import type { ImportSite, CallGraphResult } from "../cg/build.js";
import type { CallStep, ReachabilityPath } from "../gen/anst/v1/plugin.js";
import { Confidence } from "../gen/anst/v1/plugin.js";

// ── Input / output types ──────────────────────────────────────────────────────

export interface AdvisoryInput {
  module: string;
  symbolLevel: boolean;
  symbols: Array<{ package: string; name: string }>;
}

export interface AdvisoryConfidenceResult {
  confidence: Confidence;
  /** Populated only when confidence === CONFIDENCE_SYMBOL_REACHABLE. */
  path?: ReachabilityPath;
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/**
 * Resolve the confidence tier for one advisory against a pre-built call graph.
 *
 * @param advisory   The advisory to evaluate.
 * @param cgResult   The call graph built from the project's entrypoints.
 * @param entrypoints Sorted absolute paths of entrypoint files (for BFS).
 */
export function resolveAdvisoryConfidence(
  advisory: AdvisoryInput,
  cgResult: CallGraphResult,
  entrypoints: string[]
): AdvisoryConfidenceResult {
  const sites: ImportSite[] = cgResult.importSites.get(advisory.module) ?? [];

  // Parse errors scoped to reachable files only (conservative: a parse error
  // in a non-reachable file should not inflate the confidence of every advisory).
  const hasParseError = cgResult.unknownFrontiers.some(
    (u) => u.reason === "parse-error" && cgResult.reachableFiles.has(u.fromFile)
  );

  // BFS reachability — when there are no static import sites, bfsReachable
  // still consults reachable UNKNOWN frontiers so the caller receives a
  // correct unknownFrontierBlocks signal (a package reached only via a dynamic
  // require must surface as UNKNOWN, never a false not-reachable).
  const bfs = bfsReachable(
    [...entrypoints].sort(),
    cgResult.reachableFiles,
    sites,
    cgResult.unknownFrontiers
  );

  // Symbol resolution for symbol-level advisories (H1 fix: verify the named
  // symbol is actually referenced at a reachable import site before claiming
  // SYMBOL_REACHABLE — do not fabricate a path for an unverifiable symbol).
  let symbolResolved = false;
  let bfsPath: CallStep[] | undefined;

  if (advisory.symbolLevel && advisory.symbols.length > 0 && bfs.reachable) {
    const targetSymbol = advisory.symbols[0];
    const resolved = resolveSymbolAtSites(
      sites,
      cgResult.reachableFiles,
      targetSymbol.name
    );
    if (resolved !== null) {
      symbolResolved = true;
      bfsPath = resolved;
    }
  }

  const { confidence, path } = assignConfidence({
    parseError: hasParseError,
    packageImported: sites.length > 0,
    symbolLevel: advisory.symbolLevel,
    symbolResolved,
    bfsReachable: bfs.reachable,
    unknownFrontierOnOnlyPath: bfs.unknownFrontierBlocks,
    bfsPath,
  });

  return { confidence, path };
}

// ── Symbol resolution helper ──────────────────────────────────────────────────

/**
 * Attempt to verify that the named symbol is actually referenced at a
 * reachable import site (via destructuring or named binding).
 *
 * We inspect the binding style recorded by the parser:
 *   - `const { serialize } = require("serialize-javascript")` → binding "serialize"
 *   - `import { serialize } from "serialize-javascript"` → binding "serialize"
 *   - `const s = require("serialize-javascript")` → namespace import; symbol
 *     is not directly verifiable from the import site alone → return null.
 *
 * When the import site carries a matching named binding the symbol is
 * considered resolved. When no binding information is available (e.g. a
 * plain namespace import `const pkg = require(...)`) we return null to avoid
 * fabricating a SYMBOL_REACHABLE verdict.
 *
 * Returns a single-step CallStep[] for the path, or null if unresolvable.
 */
function resolveSymbolAtSites(
  sites: Array<ImportSite & { bindings?: string[] }>,
  reachableFiles: Set<string>,
  symbolName: string
): CallStep[] | null {
  // Filter to reachable sites, sorted for determinism.
  const reachableSites = sites
    .filter((s) => reachableFiles.has(s.fromFile))
    .sort(
      (a, b) =>
        a.fromFile.localeCompare(b.fromFile) ||
        a.line - b.line ||
        a.column - b.column
    );

  if (reachableSites.length === 0) return null;

  // Look for a site that explicitly names the symbol in its bindings.
  // Sites that record bindings (destructured imports) allow us to confirm
  // the symbol is used. Sites without binding info (namespace imports) do not.
  for (const site of reachableSites) {
    if (site.bindings && site.bindings.includes(symbolName)) {
      return [
        {
          symbol: symbolName,
          location: { file: site.fromFile, line: site.line, column: site.column },
        },
      ];
    }
  }

  // No site records a binding for this symbol — cannot confirm it is used.
  // Returning null keeps confidence at PACKAGE_REACHABLE rather than
  // fabricating a SYMBOL_REACHABLE verdict.
  return null;
}
