/**
 * Demand-driven, flow-insensitive call-graph builder.
 *
 * Starts from explicit entrypoints and follows import/require edges through
 * first-party code only. Third-party packages are treated as opaque import
 * boundaries: we record the import site but do not traverse into dep internals.
 *
 * UNKNOWN frontier markers are emitted for:
 *   - dynamic specifiers: require(variable) / import(expr)
 *   - specifiers that cannot be resolved
 *   - parse errors on reachable files
 *
 * Invariants:
 *   - unknown ≠ safe: every unresolvable edge emits an UnknownMarker.
 *   - Determinism: files are visited in sorted order; edges are sorted before
 *     being added to the queue.
 *   - Never throws.
 */

import path from "node:path";
import fs from "node:fs";
import { parseModule } from "../parse/index.js";
import { resolveSpecifier } from "../resolve/index.js";
import { buildProjectModel } from "../project/build-project-model.js";
import type { ResolveContext } from "../resolve/index.js";
import type { UnknownMarker } from "../engine/graph.js";
import { makeUnknownMarker } from "./unknown-frontier.js";

// ── Public types ──────────────────────────────────────────────────────────────

export interface BuildCallGraphOptions {
  /** Absolute path to the project root (where package.json lives). */
  projectRoot: string;
  /** Absolute paths to entrypoint files. When empty, auto-detection is used. */
  entrypoints: string[];
}

/** An import site: one first-party file importing one third-party package. */
export interface ImportSite {
  /** The first-party file that contains the import/require. */
  fromFile: string;
  /** 1-based line of the import statement. */
  line: number;
  /** 1-based column of the import statement. */
  column: number;
  /**
   * Named bindings destructured from this import, when statically known.
   * Mirrors ImportRecord.bindings. Used by symbol resolution to verify
   * a named export is actually referenced at this site.
   */
  bindings?: string[];
}

export interface CallGraphResult {
  /**
   * All first-party files reachable from the entrypoints (including the
   * entrypoints themselves). Sorted for determinism.
   */
  reachableFiles: Set<string>;

  /**
   * Import sites grouped by package name.
   * Key = npm package name (e.g. "serialize-javascript").
   * Value = list of first-party import sites (sorted by fromFile→line→col).
   */
  importSites: Map<string, ImportSite[]>;

  /**
   * UNKNOWN frontier markers collected during traversal.
   * Each represents a place where static analysis could not determine the
   * import target. Consulted by the reachability query.
   */
  unknownFrontiers: UnknownMarker[];
}

// ── Main builder ──────────────────────────────────────────────────────────────

/**
 * Build a demand-driven call graph starting from the given entrypoints.
 *
 * The graph is flow-insensitive: we follow import/require declarations, not
 * actual runtime call sites. Module-level reachability is what the engine
 * asserts; intra-function call edges are out of scope for this builder.
 */
export async function buildCallGraph(
  opts: BuildCallGraphOptions
): Promise<CallGraphResult> {
  const { projectRoot, entrypoints } = opts;

  // Build project model to get declared deps and lockfile-resolved packages
  const model = await buildProjectModel(projectRoot);

  // Build declared-deps set (union of all dependency fields across workspaces)
  // so phantom detection (undeclared imports) works correctly.
  const declaredDeps = new Set<string>();
  for (const ws of model.workspaces) {
    const m = ws.manifest;
    for (const key of [
      ...Object.keys(m.dependencies ?? {}),
      ...Object.keys(m.devDependencies ?? {}),
      ...Object.keys(m.optionalDependencies ?? {}),
      ...Object.keys(m.peerDependencies ?? {}),
    ]) {
      declaredDeps.add(key);
    }
  }

  // Map workspace name → source dir for sibling resolution
  const workspaceDirs = new Map<string, string>();
  for (const ws of model.workspaces) {
    workspaceDirs.set(ws.name, ws.dir);
  }

  // Determine deps map: use the root workspace's deps (or first workspace).
  // For single-package projects this is the only workspace.
  const rootWs = model.workspaces[0];
  const deps = rootWs ? rootWs.deps : new Map();

  const reachableFiles = new Set<string>();
  const importSites = new Map<string, ImportSite[]>();
  const unknownFrontiers: UnknownMarker[] = [];

  // BFS queue: sorted list of absolute file paths to visit.
  // Sorting before enqueue ensures deterministic visitation order.
  const queue: string[] = [];
  const enqueued = new Set<string>();

  function enqueue(file: string): void {
    if (!enqueued.has(file)) {
      enqueued.add(file);
      queue.push(file);
    }
  }

  // Seed queue from entrypoints (sorted for determinism)
  const sortedEntrypoints = [...entrypoints].sort();
  for (const ep of sortedEntrypoints) {
    enqueue(ep);
  }

  // If no explicit entrypoints provided, detect from project model
  if (sortedEntrypoints.length === 0 && rootWs) {
    const autoEps = detectAutoEntrypoints(rootWs.dir, rootWs.manifest);
    for (const ep of autoEps.sort()) {
      enqueue(ep);
    }
  }

  while (queue.length > 0) {
    // Sort the front of the queue for deterministic BFS order
    // (small cost; queue stays short in practice for typical projects)
    queue.sort();
    const file = queue.shift()!;

    if (reachableFiles.has(file)) continue;
    reachableFiles.add(file);

    // Find the workspace this file belongs to (closest ancestor workspace dir)
    const ws = findWorkspaceForFile(file, model.workspaces) ?? rootWs;
    const workspaceDir = ws ? ws.dir : projectRoot;
    const wsDeps = ws ? ws.deps : deps;

    const ctx: ResolveContext = {
      fromFile: file,
      workspaceDir,
      deps: wsDeps,
      conditions: ["require", "import", "default"],
      workspaceDirs,
      declaredDeps,
    };

    const parsed = await parseModule(file);

    if (parsed.kind === "unknown") {
      // Parse error: emit UNKNOWN marker, do not traverse further from this file
      unknownFrontiers.push(
        makeUnknownMarker("parse-error", parsed.reason, file, 0, 0)
      );
      continue;
    }

    // Process all import/require records in sorted order (by line, then col)
    const sortedImports = [...parsed.imports].sort(
      (a, b) => a.line - b.line || a.column - b.column
    );

    for (const imp of sortedImports) {
      if (imp.specifier === null) {
        // Dynamic specifier (require(variable) / import(expr)) → UNKNOWN frontier
        unknownFrontiers.push(
          makeUnknownMarker(
            "dynamic-specifier",
            `Dynamic specifier at ${file}:${imp.line}:${imp.column}`,
            file,
            imp.line,
            imp.column
          )
        );
        continue;
      }

      const resolved = resolveSpecifier(imp.specifier, ctx);

      if (resolved.kind === "unknown") {
        unknownFrontiers.push(
          makeUnknownMarker(
            "unresolved-specifier",
            resolved.reason,
            file,
            imp.line,
            imp.column
          )
        );
        continue;
      }

      if (resolved.kind === "first-party") {
        // Traverse into first-party files
        enqueue(resolved.resolvedPath);
        continue;
      }

      // Third-party import boundary: record import site
      if (resolved.kind === "third-party") {
        const pkgName = resolved.packageName;
        if (!importSites.has(pkgName)) {
          importSites.set(pkgName, []);
        }
        importSites.get(pkgName)!.push({
          fromFile: file,
          line: imp.line,
          column: imp.column,
          bindings: imp.bindings,
        });

        // Mark phantom imports
        if (resolved.phantom) {
          unknownFrontiers.push(
            makeUnknownMarker(
              "phantom-dep",
              `Phantom (undeclared) dep "${pkgName}" imported at ${file}:${imp.line}`,
              file,
              imp.line,
              imp.column
            )
          );
        }
      }
    }

    // Emit UNKNOWN frontiers for non-import dynamic dispatch constructs
    // (eval, Function constructor, computed member calls, aliased require).
    // These constructs can load any package at runtime and must prevent a
    // NOT_REACHABLE verdict when they sit on the only candidate path.
    for (const site of parsed.dynamicDispatchSites) {
      unknownFrontiers.push(
        makeUnknownMarker(
          "dynamic-dispatch",
          site.detail,
          file,
          site.line,
          site.column
        )
      );
    }
  }

  // Sort import sites within each package for determinism
  for (const [, sites] of importSites) {
    sites.sort(
      (a, b) =>
        a.fromFile.localeCompare(b.fromFile) ||
        a.line - b.line ||
        a.column - b.column
    );
  }

  return { reachableFiles, importSites, unknownFrontiers };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

import type { Workspace } from "../project/model.js";

function findWorkspaceForFile(
  file: string,
  workspaces: Workspace[]
): Workspace | null {
  let best: Workspace | null = null;
  let bestLen = -1;
  for (const ws of workspaces) {
    if (
      (file.startsWith(ws.dir + path.sep) || file === ws.dir) &&
      ws.dir.length > bestLen
    ) {
      bestLen = ws.dir.length;
      best = ws;
    }
  }
  return best;
}

/** Simple auto-detection: look for main/index files in the project root. */
function detectAutoEntrypoints(
  dir: string,
  manifest: Record<string, unknown>
): string[] {
  const candidates: string[] = [];

  // main field
  if (typeof manifest.main === "string") {
    const abs = path.resolve(dir, manifest.main);
    if (fs.existsSync(abs)) candidates.push(abs);
  }

  // Common conventions
  for (const name of ["index.js", "index.ts", "src/index.js", "src/index.ts"]) {
    const abs = path.join(dir, name);
    if (fs.existsSync(abs) && !candidates.includes(abs)) {
      candidates.push(abs);
    }
  }

  return candidates;
}
