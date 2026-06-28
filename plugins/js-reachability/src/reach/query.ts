/**
 * Per-advisory reachability query — thin wrapper over resolveAdvisoryConfidence.
 *
 * Builds the call graph on each call and delegates confidence resolution to
 * the shared resolveAdvisoryConfidence function so this path and analyze()
 * are always identical.
 *
 * Callers that check multiple advisories against the same project should use
 * the batch analyze() function in engine/analyze.ts instead (one graph build
 * for all advisories).
 */

import { buildCallGraph } from "../cg/build.js";
import { resolveAdvisoryConfidence } from "./resolve-advisory.js";
import type { ReachabilityPath } from "../gen/commit0/v1/plugin.js";
import { Confidence } from "../gen/commit0/v1/plugin.js";

// ── Public types ──────────────────────────────────────────────────────────────

/** Subset of Advisory used by the query (avoids importing the full proto). */
export interface QueryAdvisory {
  id: string;
  module: string;
  versionRange: string;
  symbols: Array<{ package: string; name: string }>;
  symbolLevel: boolean;
  sources: string[];
}

export interface QueryOptions {
  projectRoot: string;
  entrypoints: string[];
  advisory: QueryAdvisory;
}

export interface QueryResult {
  confidence: Confidence;
  /** Populated only for SYMBOL_REACHABLE. */
  path?: ReachabilityPath;
}

// ── Query ─────────────────────────────────────────────────────────────────────

/**
 * Run a full reachability query for one advisory against a project root.
 * Builds the call graph on each call — callers that check multiple advisories
 * should use the batch analyze() function in engine/analyze.ts instead.
 */
export async function queryReachability(
  opts: QueryOptions
): Promise<QueryResult> {
  const { projectRoot, entrypoints, advisory } = opts;

  const cgResult = await buildCallGraph({ projectRoot, entrypoints });

  const { confidence, path } = resolveAdvisoryConfidence(
    advisory,
    cgResult,
    entrypoints
  );

  return { confidence, path };
}
