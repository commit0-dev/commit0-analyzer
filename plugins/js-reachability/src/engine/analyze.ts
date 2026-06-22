/**
 * Core reachability engine — shared by the standalone shim and the gRPC handler.
 *
 * Accepts an AnalyzeRequest (same shape as the gRPC proto) and returns a
 * sorted, deterministic Finding[] array.  The shim writes this to stdout as
 * JSON; the gRPC handler streams them one by one.
 *
 * Algorithm:
 *   1. Build the call graph once for the project (demand-driven from entrypoints).
 *   2. For each advisory, run BFS + confidence assignment via resolveAdvisoryConfidence.
 *   3. Build a Finding proto from the result.
 *   4. Sort findings by stable key and return.
 *
 * Determinism invariants:
 *   - Advisories processed in input order (caller must sort if needed).
 *   - Import sites and BFS are deterministic (sorted internally).
 *   - Output sorted by stable key before return.
 *   - unknown ≠ safe: UNKNOWN frontiers never coerced to NOT_REACHABLE.
 */

import { buildCallGraph } from "../cg/build.js";
import { resolveAdvisoryConfidence } from "../reach/resolve-advisory.js";
import { buildFinding, sortFindings } from "../finding.js";
import { detectEntrypoints } from "../entry/detect-entrypoints.js";
import { buildProjectModel } from "../project/build-project-model.js";
import { Confidence } from "../gen/anst/v1/plugin.js";
import type { Finding } from "../gen/anst/v1/plugin.js";

// ── Public types ──────────────────────────────────────────────────────────────

/** Subset of AnalyzeRequest sufficient for the engine. */
export interface EngineRequest {
  moduleRoot: string;
  entrypoints: string[];
  advisories: Array<{
    id: string;
    module: string;
    versionRange: string;
    symbols: Array<{ package: string; name: string }>;
    symbolLevel: boolean;
    sources: string[];
  }>;
}

// ── Engine ────────────────────────────────────────────────────────────────────

/**
 * Run the full reachability engine for a request.
 * Returns findings sorted by stable key (advisory.id + module + workspace).
 */
export async function analyze(req: EngineRequest): Promise<Finding[]> {
  const { moduleRoot, advisories } = req;

  // Resolve entrypoints: explicit override or auto-detect from project model
  const model = await buildProjectModel(moduleRoot);

  let entrypoints: string[];
  if (req.entrypoints && req.entrypoints.length > 0) {
    entrypoints = [...req.entrypoints].sort();
  } else {
    const epMap = detectEntrypoints(model);
    // Collect all entrypoints across all workspaces, sorted for determinism
    entrypoints = [];
    for (const [, eps] of [...epMap.entries()].sort((a, b) =>
      a[0].localeCompare(b[0])
    )) {
      for (const ep of eps) {
        entrypoints.push(ep.file);
      }
    }
    entrypoints.sort();
  }

  // Build the call graph once for all advisories
  const cgResult = await buildCallGraph({ projectRoot: moduleRoot, entrypoints });

  // Determine the workspace name for each finding
  const workspaceName = model.workspaces[0]?.name ?? "default";

  const findings: Finding[] = [];

  for (const advisory of advisories) {
    const sites = cgResult.importSites.get(advisory.module) ?? [];

    // Import-graph-only verdict (Metric V1-JS): does the import graph alone
    // (ignoring call edges) show the package is reachable?
    // Exposed as a property on the Finding for comparison reporting.
    const igReachable = sites.some((s) => cgResult.reachableFiles.has(s.fromFile));
    const igVerdict = igReachable
      ? Confidence.CONFIDENCE_PACKAGE_REACHABLE
      : Confidence.CONFIDENCE_NOT_REACHABLE;

    // Delegate confidence resolution to the shared function so the shipped
    // path and the query path are always identical.
    const { confidence, path } = resolveAdvisoryConfidence(
      advisory,
      cgResult,
      entrypoints
    );

    // Determine the language from the first reachable import site
    const importingFile = sites.find((s) => cgResult.reachableFiles.has(s.fromFile))
      ?.fromFile;

    // Check if the dep is phantom
    const phantom = cgResult.unknownFrontiers.some(
      (u) =>
        u.reason === "phantom-dep" &&
        sites.some((s) => s.fromFile === u.fromFile)
    );

    const finding = buildFinding({
      advisory,
      confidence,
      workspace: workspaceName,
      importingFile,
      path,
      phantom,
      importGraphVerdict: igVerdict,
    });

    findings.push(finding);
  }

  return sortFindings(findings);
}
