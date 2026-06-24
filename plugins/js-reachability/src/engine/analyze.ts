/**
 * Core reachability engine — shared by the standalone shim and the gRPC handler.
 *
 * Accepts an AnalyzeRequest (same shape as the gRPC proto) and returns a
 * sorted, deterministic Finding[] array.  The shim writes this to stdout as
 * JSON; the gRPC handler streams them one by one.
 *
 * Algorithm (per-workspace):
 *   1. Build the project model and discover workspaces.
 *   2. Deduplicate advisories by id+module (the Go host queries per workspace dep
 *      and may send the same advisory once per workspace).
 *   3. For each workspace:
 *      a. Detect that workspace's entrypoints.
 *      b. Build a call graph scoped to those entrypoints.
 *      c. For each advisory whose package is declared in this workspace's deps,
 *         resolve reachability against the per-workspace call graph.
 *      d. Emit one Finding per (advisory, workspace).
 *   4. Sort all findings by stable key and return.
 *
 * When explicit entrypoints are provided (override from the caller), the engine
 * falls back to single-pass mode using the first workspace name, preserving the
 * pre-workspace behaviour for callers that supply their own entrypoint list.
 *
 * Determinism invariants:
 *   - Workspaces processed in sorted-name order.
 *   - Advisories deduplicated, then processed in original order within each workspace.
 *   - Import sites and BFS are deterministic (sorted internally).
 *   - Output sorted by stable key before return.
 *   - unknown ≠ safe: UNKNOWN frontiers never coerced to NOT_REACHABLE.
 */

import { buildCallGraph } from "../cg/build.js";
import { resolveAdvisoryConfidence } from "../reach/resolve-advisory.js";
import { buildFinding, sortFindings } from "../finding.js";
import { detectEntrypoints } from "../entry/detect-entrypoints.js";
import { buildProjectModel } from "../project/build-project-model.js";
import { computeWorkspaceClosure } from "../project/dep-closure.js";
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

  // Resolve project model to discover workspaces and their declared deps.
  const model = await buildProjectModel(moduleRoot);

  // Deduplicate advisories by id+module. The Go host queries advisories
  // per-dep across workspaces and may send the same advisory once per
  // workspace that declares the dep. Per-workspace attribution is handled
  // below by checking each workspace's deps map — duplicates in the input
  // would otherwise produce duplicate findings for the same workspace.
  const seenAdvisory = new Set<string>();
  const uniqueAdvisories = advisories.filter((a) => {
    const key = `${a.id}\x00${a.module}`;
    if (seenAdvisory.has(key)) return false;
    seenAdvisory.add(key);
    return true;
  });

  // ── Explicit-entrypoints path (single-pass, caller-scoped) ────────────────
  // When the caller provides explicit entrypoints we cannot infer per-workspace
  // scope, so we fall back to the original single-pass behaviour and assign all
  // findings to the first workspace name.
  if (req.entrypoints && req.entrypoints.length > 0) {
    const entrypoints = [...req.entrypoints].sort();
    const cgResult = await buildCallGraph({ projectRoot: moduleRoot, entrypoints });
    const workspaceName = model.workspaces[0]?.name ?? "default";
    const findings: Finding[] = [];

    // Compute devOnly against the UNION of all workspace closures so a package
    // that is runtime in ANY workspace is not mistagged dev_only (H2 fix).
    const allRuntimeNames = new Set<string>();
    const allDevNames = new Set<string>();
    for (const ws of model.workspaces) {
      const c = computeWorkspaceClosure(ws);
      for (const name of c.runtime.keys()) allRuntimeNames.add(name);
      for (const name of c.dev.keys()) allDevNames.add(name);
    }

    for (const advisory of uniqueAdvisories) {
      const sites = cgResult.importSites.get(advisory.module) ?? [];
      const igReachable = sites.some((s) => cgResult.reachableFiles.has(s.fromFile));
      const igVerdict = igReachable
        ? Confidence.CONFIDENCE_PACKAGE_REACHABLE
        : Confidence.CONFIDENCE_NOT_REACHABLE;
      const { confidence, path } = resolveAdvisoryConfidence(advisory, cgResult, entrypoints);
      const importingFile = sites.find((s) => cgResult.reachableFiles.has(s.fromFile))?.fromFile;
      const phantom = cgResult.unknownFrontiers.some(
        (u) => u.reason === "phantom-dep" && sites.some((s) => s.fromFile === u.fromFile)
      );
      // dev_only: in dev in at least one workspace, AND runtime in NO workspace.
      const devOnly = allDevNames.has(advisory.module) && !allRuntimeNames.has(advisory.module);
      findings.push(buildFinding({ advisory, confidence, workspace: workspaceName, importingFile, path, phantom, importGraphVerdict: igVerdict, devOnly }));
    }

    return sortFindings(findings);
  }

  // ── Per-workspace path (auto-detected entrypoints) ────────────────────────
  // Process each workspace independently: detect its entrypoints, build a
  // call graph scoped only to those entrypoints, and resolve advisories for
  // packages declared in that workspace's deps.
  //
  // A package that is declared in a workspace's deps but never imported from
  // that workspace's entrypoints will receive NOT_REACHABLE for that workspace.
  // A package that is declared AND imported (reachable) receives PACKAGE_REACHABLE.

  const epMap = detectEntrypoints(model);
  const findings: Finding[] = [];

  // Sort workspaces by name for deterministic output order.
  const sortedWorkspaces = [...model.workspaces].sort((a, b) =>
    a.name.localeCompare(b.name)
  );

  for (const ws of sortedWorkspaces) {
    const wsEps = (epMap.get(ws.name) ?? []).map((e) => e.file).sort();

    // A workspace with no resolvable entrypoint (no bin, main, or exports — e.g.
    // a private example or fixture package whose dependencies are exercised only
    // through test files or source types we do not parse such as .vue/.svelte)
    // cannot be analyzed for reachability. There are no roots to traverse from,
    // so concluding NOT_REACHABLE would be a false negative ("checked from no
    // starting point, found nothing"). Per unknown != safe, such a workspace's
    // declared-dependency advisories are UNKNOWN.
    const noEntrypoint = wsEps.length === 0;

    // Build a call graph scoped to this workspace's entrypoints.
    const cgResult = await buildCallGraph({
      projectRoot: moduleRoot,
      entrypoints: wsEps,
    });

    // Compute the full transitive dep closure for this workspace once.
    // runtime = full closure reachable from runtime direct deps (transitive).
    // dev     = closure from dev direct deps MINUS runtime (dev-only packages).
    const closure = computeWorkspaceClosure(ws);

    // Emit a finding for each advisory whose package appears anywhere in this
    // workspace's dep closure (runtime or dev-only). Packages absent from the
    // closure are not installed in this workspace — skip them here; another
    // workspace may own the finding.
    for (const advisory of uniqueAdvisories) {
      const inRuntime = closure.runtime.has(advisory.module);
      const inDev = closure.dev.has(advisory.module);

      if (!inRuntime && !inDev) {
        // Not in this workspace's installed dep tree at all.
        continue;
      }

      // True when the package is reachable only via devDependencies. The Go gate
      // uses this property to mark the finding as non-gating.
      const devOnly = inDev && !inRuntime;

      const sites = cgResult.importSites.get(advisory.module) ?? [];
      const igReachable = sites.some((s) => cgResult.reachableFiles.has(s.fromFile));
      const igVerdict = igReachable
        ? Confidence.CONFIDENCE_PACKAGE_REACHABLE
        : Confidence.CONFIDENCE_NOT_REACHABLE;

      const { confidence, path } = noEntrypoint
        ? { confidence: Confidence.CONFIDENCE_UNKNOWN, path: undefined }
        : resolveAdvisoryConfidence(advisory, cgResult, wsEps);

      const importingFile = sites.find((s) => cgResult.reachableFiles.has(s.fromFile))
        ?.fromFile;

      const phantom = cgResult.unknownFrontiers.some(
        (u) =>
          u.reason === "phantom-dep" &&
          sites.some((s) => s.fromFile === u.fromFile)
      );

      findings.push(
        buildFinding({
          advisory,
          confidence,
          workspace: ws.name,
          importingFile,
          path,
          phantom,
          importGraphVerdict: igVerdict,
          devOnly,
        })
      );
    }
  }

  return sortFindings(findings);
}
