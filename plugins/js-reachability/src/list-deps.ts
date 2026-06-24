/**
 * --list-deps <root>: enumerate npm dependencies from the project model.
 *
 * Emits a deterministic JSON object to stdout:
 *   {
 *     "deps": [
 *       {
 *         "ecosystem": "npm",
 *         "name": "<pkg>",
 *         "version": "<resolved>",
 *         "workspace": "<ws-name>",
 *         "direct": true|false,
 *         "dev": true|false
 *       },
 *       ...
 *     ],
 *     "incomplete": [
 *       { "scope": "<scope>", "reason": "<reason>" },
 *       ...
 *     ]
 *   }
 *
 * Fields:
 *   direct  — true when the package is declared in the workspace's
 *             dependencies or optionalDependencies (not just transitive).
 *   dev     — true when the package appears only in devDependencies and NOT
 *             in runtime dependencies or optionalDependencies. Runtime deps
 *             that also appear in devDependencies are NOT marked dev.
 *
 * Determinism guarantees:
 *   - Entries are sorted by workspace name, then package name, then version.
 *   - Duplicate (workspace, name, version) triples are deduplicated.
 *   - No wall-clock timestamps or non-deterministic fields are included.
 *
 * The CLI consumes this output to query advisories for each dep per workspace.
 * The incomplete[] array signals that the project model is partial (e.g. a
 * lockfile could not be parsed); the CLI marks the scan incomplete when non-empty.
 */

import path from "node:path";
import { buildProjectModel } from "./project/build-project-model.js";
import type { IncompleteKind } from "./project/model.js";

/** A single resolved npm dependency entry as emitted to stdout. */
export interface DepEntry {
  ecosystem: "npm";
  name: string;
  version: string;
  workspace: string;
  /**
   * true when the package is directly declared in the workspace's
   * dependencies or optionalDependencies (not transitive-only).
   */
  direct: boolean;
  /**
   * true when the package appears in devDependencies but NOT in
   * dependencies or optionalDependencies of this workspace.
   * Best-effort: if the lockfile doesn't resolve the devDep it is omitted.
   */
  dev: boolean;
}

/** The shape of the JSON object written to stdout by --list-deps. */
export interface ListDepsOutput {
  deps: DepEntry[];
  incomplete: Array<{ scope: string; reason: string; kind: IncompleteKind }>;
  /**
   * Total number of declared runtime deps across all workspaces (before
   * resolution). The CLI uses this together with incomplete[].kind to decide
   * whether to mark the scan incomplete:
   *   - lockfile-corrupt → always incomplete (corrupt lockfile is an error
   *     regardless of whether any deps are declared).
   *   - all other kinds → only incomplete when declaredDepCount > 0 (a missing
   *     lockfile on a project with no declared deps is not a concern).
   */
  declaredDepCount: number;
}

/**
 * Collect all resolved deps across all workspaces of the project at root.
 * Returns a deterministic ListDepsOutput (sorted, deduplicated).
 *
 * Emits both runtime deps (ws.deps) and devDependencies (ws.devDeps).
 * Runtime deps are tagged direct:true; devDeps-only packages are tagged dev:true.
 */
export async function listDeps(root: string): Promise<ListDepsOutput> {
  const model = await buildProjectModel(root);

  // Count total declared runtime deps across all workspaces (before resolution).
  // This tells the CLI whether any declared deps could not be resolved.
  let declaredDepCount = 0;
  for (const ws of model.workspaces) {
    const manifest = ws.manifest;
    declaredDepCount +=
      Object.keys(manifest.dependencies ?? {}).length +
      Object.keys(manifest.optionalDependencies ?? {}).length;
  }

  const seen = new Set<string>();
  const deps: DepEntry[] = [];

  // Workspaces are already sorted by discoverWorkspaces; iterate in order.
  for (const ws of model.workspaces) {
    // Build the set of direct runtime dep names for this workspace.
    const directRuntimeNames = new Set([
      ...Object.keys(ws.manifest.dependencies ?? {}),
      ...Object.keys(ws.manifest.optionalDependencies ?? {}),
    ]);

    // Emit runtime deps (direct:true, dev:false)
    const sortedDepNames = [...ws.deps.keys()].sort();
    for (const name of sortedDepNames) {
      const pkg = ws.deps.get(name)!;
      const key = `${ws.name}\0${name}\0${pkg.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deps.push({
        ecosystem: "npm",
        name,
        version: pkg.version,
        workspace: ws.name,
        direct: directRuntimeNames.has(name),
        dev: false,
      });
    }

    // Emit devDeps that are NOT already in runtime deps (dev:true, direct:false)
    const sortedDevDepNames = [...ws.devDeps.keys()].sort();
    for (const name of sortedDevDepNames) {
      if (ws.deps.has(name)) continue; // already emitted as runtime dep above
      const pkg = ws.devDeps.get(name)!;
      const key = `${ws.name}\0${name}\0${pkg.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deps.push({
        ecosystem: "npm",
        name,
        version: pkg.version,
        workspace: ws.name,
        direct: false,
        dev: true,
      });
    }
  }

  // Sort the final list: workspace → name → version (all ascending).
  deps.sort((a, b) => {
    const ws = a.workspace.localeCompare(b.workspace);
    if (ws !== 0) return ws;
    const nm = a.name.localeCompare(b.name);
    if (nm !== 0) return nm;
    return a.version.localeCompare(b.version);
  });

  const incomplete = model.incomplete.map((e) => ({
    scope: e.scope,
    reason: e.reason,
    kind: e.kind,
  }));

  return { deps, incomplete, declaredDepCount };
}

/** Entry point dispatched from main.ts when --list-deps is the first arg. */
export async function run(): Promise<void> {
  const rootArg = process.argv[3];
  if (!rootArg) {
    process.stderr.write("Usage: --list-deps <directory>\n");
    process.exit(1);
  }

  const root = path.resolve(rootArg);
  const output = await listDeps(root);
  process.stdout.write(JSON.stringify(output) + "\n");
}
