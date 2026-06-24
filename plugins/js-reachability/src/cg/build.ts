/**
 * Demand-driven, flow-insensitive call-graph builder.
 *
 * Starts from explicit entrypoints and follows import/require edges through
 * first-party code AND into third-party dependency source files when the
 * dependency has source fidelity. Third-party packages with reduced or no
 * fidelity (minified bundles, types-only) are treated as UNKNOWN frontiers.
 *
 * UNKNOWN frontier markers are emitted for:
 *   - dynamic specifiers: require(variable) / import(expr)
 *   - specifiers that cannot be resolved
 *   - parse errors on reachable files
 *   - third-party packages whose entry is reduced/none fidelity
 *
 * Invariants:
 *   - unknown ≠ safe: every unresolvable edge emits an UnknownMarker.
 *   - Determinism: files are visited in sorted order; edges are sorted before
 *     being added to the queue.
 *   - Bounded: each file is visited at most once; dep source resolutions are
 *     cached by package dir to avoid redundant I/O and guard against cycles.
 *   - Never throws.
 */

import path from "node:path";
import fs from "node:fs";
import { parseModule } from "../parse/index.js";
import { resolveSpecifier } from "../resolve/index.js";
import { buildProjectModel } from "../project/build-project-model.js";
import { resolveDepSource } from "../depsource/resolve-dep-source.js";
import type { ResolveContext } from "../resolve/index.js";
import type { UnknownMarker } from "../engine/graph.js";
import { makeUnknownMarker } from "./unknown-frontier.js";
import type { ResolvedPackage } from "../project/model.js";

// ── Public types ──────────────────────────────────────────────────────────────

export interface BuildCallGraphOptions {
  /** Absolute path to the project root (where package.json lives). */
  projectRoot: string;
  /** Absolute paths to entrypoint files. When empty, auto-detection is used. */
  entrypoints: string[];
}

/** An import site: one reachable file importing one third-party package. */
export interface ImportSite {
  /**
   * The file (first-party OR dep source file) that contains the import/require.
   * This file is in the reachable set when the advisory's package is PACKAGE_REACHABLE.
   */
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
   * All files reachable from the entrypoints (first-party AND dep source files
   * that were traversed). Sorted for determinism.
   */
  reachableFiles: Set<string>;

  /**
   * Import sites grouped by package name.
   * Key = npm package name (e.g. "serialize-javascript").
   * Value = list of import sites (sorted by fromFile→line→col).
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
 *
 * When a reachable file imports a third-party package, resolveDepSource
 * classifies its entry fidelity:
 *   source  → traverse into the dep file and follow its imports recursively
 *   reduced → emit UNKNOWN frontier (minified; cannot trace reliably)
 *   none    → emit UNKNOWN frontier (no runtime entry resolved)
 *
 * This gives transitive reachability: if first-party → dep-a (source) →
 * dep-b, then dep-b is PACKAGE_REACHABLE. If dep-a → dep-b via dynamic
 * require(var), dep-b stays UNKNOWN (never NOT_REACHABLE).
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
  const rootDeps = rootWs ? rootWs.deps : new Map<string, ResolvedPackage>();

  const reachableFiles = new Set<string>();
  const importSites = new Map<string, ImportSite[]>();
  const unknownFrontiers: UnknownMarker[] = [];

  // Cache for resolveDepSource results keyed by package directory absolute path.
  // Avoids re-reading and re-classifying the same dep dir multiple times.
  const depSourceCache = new Map<string, ReturnType<typeof resolveDepSource>>();

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
    // Sort the queue for deterministic BFS order
    queue.sort();
    const file = queue.shift()!;

    if (reachableFiles.has(file)) continue;
    reachableFiles.add(file);

    // Determine resolution context for this file.
    // For first-party files: use workspace-aware context.
    // For dep files (inside node_modules): use the dep's dir as workspaceDir
    // and an empty deps map so the flat node_modules walk handles bare specifiers.
    const inNodeModules = isInsideNodeModules(file);

    let ctx: ResolveContext;
    if (!inNodeModules) {
      // First-party file: workspace-aware resolution
      const ws = findWorkspaceForFile(file, model.workspaces) ?? rootWs;
      const workspaceDir = ws ? ws.dir : projectRoot;
      const wsDeps = ws ? ws.deps : rootDeps;
      ctx = {
        fromFile: file,
        workspaceDir,
        deps: wsDeps,
        conditions: ["require", "import", "default"],
        workspaceDirs,
        declaredDeps,
      };
    } else {
      // Dep source file: resolve from the file's own directory upward.
      // Use empty deps map — the flat node_modules walk in resolveSpecifier
      // will find peer deps via the filesystem hierarchy.
      const fileDir = path.dirname(file);
      ctx = {
        fromFile: file,
        workspaceDir: fileDir,
        deps: new Map<string, ResolvedPackage>(),
        conditions: ["require", "import", "default"],
        workspaceDirs,
        declaredDeps: new Set(), // dep code not checked for phantom status
      };
    }

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
        // Dynamic specifier (require(variable) / import(expr)) → UNKNOWN frontier.
        //
        // Node.js runtime resolution walks UP the node_modules hierarchy (hoisting),
        // so a dynamic specifier in any reachable file — first-party OR a traversable
        // dependency — can resolve to ANY installed package reachable via the lookup
        // chain. There is no safe way to scope this to the dep's own declared set:
        //   - Hoisted packages that the dep never declared are still resolvable.
        //   - A dep that declares NOTHING can still resolve hoisted packages.
        //
        // Invariant: unknown ≠ safe. Emit a GLOBAL frontier (no couldReach scope).
        // This is the same treatment first-party dynamic dispatch already receives.
        // The previous scoped model (couldReach = dep's declared deps) caused:
        //   C1: deps declaring nothing → empty couldReach → frontier dropped → false NOT_REACHABLE
        //   C2: deps declaring partial set → hoisted pkgs outside the set → false NOT_REACHABLE
        unknownFrontiers.push(
          makeUnknownMarker(
            "dynamic-specifier",
            `Dynamic specifier at ${file}:${imp.line}:${imp.column}`,
            file,
            imp.line,
            imp.column
            // No couldReach: global frontier — blocks NOT_REACHABLE for all installed pkgs
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
        // Traverse into first-party files (or dep-internal relative imports)
        enqueue(resolved.resolvedPath);
        continue;
      }

      // Third-party import boundary: record import site and check fidelity
      if (resolved.kind === "third-party") {
        const pkgName = resolved.packageName;

        // Record the import site (from whatever file we are currently in)
        if (!importSites.has(pkgName)) {
          importSites.set(pkgName, []);
        }
        importSites.get(pkgName)!.push({
          fromFile: file,
          line: imp.line,
          column: imp.column,
          bindings: imp.bindings,
        });

        // Mark phantom imports (only meaningful for first-party files)
        if (resolved.phantom && !inNodeModules) {
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

        // Check fidelity to decide whether to traverse into the dep
        const depSource = getDepSource(pkgName, resolved.version, resolved.packageDir, depSourceCache);

        if (depSource.fidelity === "source" && depSource.entryFile !== null) {
          // Source fidelity: traverse into this dep's entry file
          enqueue(depSource.entryFile);
        } else if (depSource.fidelity === "reduced" || depSource.fidelity === "none") {
          // Reduced or none fidelity: we cannot analyze this dep's code. We know
          // it is imported (dep-e IS PACKAGE_REACHABLE from the import site above),
          // but we cannot prove its dependencies are unreachable.
          //
          // Sound bound: a bundled/minified dep can only statically import packages
          // in its FULL TRANSITIVE declared dependency closure. Any package in that
          // closure without a proven static reachable path must be UNKNOWN.
          //
          // The previous one-level scope (readDepDeclaredPackages) caused C3:
          //   dep-e (reduced) → dep-f (one level) → deep-vuln (two levels)
          //   deep-vuln was NOT in dep-e's one-level declared set → false NOT_REACHABLE.
          //
          // Fix: compute the transitive closure over the installed node_modules layout
          // (filesystem walk, respects the actual hoisted/nested install tree).
          const transitiveClosure = computeTransitiveDepClosure(resolved.packageDir);
          if (transitiveClosure.length > 0) {
            unknownFrontiers.push(
              makeUnknownMarker(
                "dynamic-specifier",
                `Reduced-fidelity dep "${pkgName}" is reachable but unanalyzable; its transitive deps may be loaded`,
                file,
                imp.line,
                imp.column,
                transitiveClosure
              )
            );
          }
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

/**
 * Compute the FULL TRANSITIVE closure of declared dependency names reachable
 * from a package directory.
 *
 * Starting from pkgDir's declared deps (dependencies, peerDependencies,
 * optionalDependencies), follows each dep's own package.json declarations
 * recursively until the fixpoint is reached. Handles cycles by tracking
 * which packages have already been expanded.
 *
 * Resolution: for each declared dep name, walks up the node_modules hierarchy
 * from pkgDir to find the installed package directory (mirrors Node's lookup).
 *
 * Returns a sorted list of all transitively declared package names (not paths).
 * Returns an empty array if the package.json cannot be read or parsed.
 */
function computeTransitiveDepClosure(pkgDir: string): string[] {
  const visited = new Set<string>(); // package dirs we have already expanded
  const closure = new Set<string>(); // accumulated package names

  function expand(dir: string): void {
    if (visited.has(dir)) return;
    visited.add(dir);

    const names = readDepDeclaredPackages(dir);
    for (const name of names) {
      closure.add(name);
      // Resolve the installed location by walking up from dir
      const installedDir = findInstalledPackageDir(name, dir);
      if (installedDir !== null) {
        expand(installedDir);
      }
    }
  }

  expand(pkgDir);
  return [...closure].sort();
}

/**
 * Find the installed directory for a package name by walking up the
 * node_modules lookup chain from a starting directory.
 *
 * Mirrors Node.js module resolution: check <startDir>/node_modules/<name>,
 * then <parent>/node_modules/<name>, until the filesystem root.
 *
 * Returns the absolute path to the package directory or null if not found.
 */
function findInstalledPackageDir(name: string, startDir: string): string | null {
  let current = startDir;
  while (true) {
    const candidate = path.join(current, "node_modules", name);
    try {
      if (fs.statSync(candidate).isDirectory()) return candidate;
    } catch {
      // not found at this level
    }
    const parent = path.dirname(current);
    if (parent === current) break; // filesystem root
    current = parent;
  }
  return null;
}

/**
 * Read the declared dependency names from a package's package.json.
 *
 * Returns the union of dependencies, peerDependencies, and optionalDependencies
 * (all fields that could be loaded at runtime via require/import).
 * Returns an empty array if the package.json cannot be read or parsed.
 */
function readDepDeclaredPackages(pkgDir: string): string[] {
  try {
    const manifestPath = path.join(pkgDir, "package.json");
    const raw = fs.readFileSync(manifestPath, "utf8");
    const manifest = JSON.parse(raw) as Record<string, unknown>;
    const names = new Set<string>();
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
      const deps = manifest[field];
      if (deps && typeof deps === "object" && !Array.isArray(deps)) {
        for (const name of Object.keys(deps as Record<string, unknown>)) {
          names.add(name);
        }
      }
    }
    return [...names].sort();
  } catch {
    return [];
  }
}

/**
 * Given an absolute path to a file inside node_modules, return the absolute
 * path to the package directory that owns the file.
 *
 * Walks up from the file's directory until it finds the package root:
 * a directory directly under node_modules (or under node_modules/@scope).
 * Returns null if the file is not inside node_modules.
 *
 * Examples:
 *   .../node_modules/dep-a/src/index.js → .../node_modules/dep-a
 *   .../node_modules/@scope/pkg/index.js → .../node_modules/@scope/pkg
 */
function packageDirForDepFile(file: string): string | null {
  const nmSep = `${path.sep}node_modules${path.sep}`;
  const nmIdx = file.lastIndexOf(nmSep);
  if (nmIdx === -1) return null;

  const afterNm = file.slice(nmIdx + nmSep.length);
  const parts = afterNm.split(path.sep);

  // Scoped packages: @scope/name
  if (parts[0].startsWith("@") && parts.length >= 2) {
    return file.slice(0, nmIdx + nmSep.length) + parts[0] + path.sep + parts[1];
  }
  // Unscoped packages: name
  return file.slice(0, nmIdx + nmSep.length) + parts[0];
}

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

/** Returns true when an absolute file path is inside a node_modules directory. */
function isInsideNodeModules(file: string): boolean {
  return file.includes(`${path.sep}node_modules${path.sep}`);
}

/**
 * Resolve and cache the DepSource for a package directory.
 * The cache key is the absolute package directory path.
 */
function getDepSource(
  pkgName: string,
  version: string,
  pkgDir: string,
  cache: Map<string, ReturnType<typeof resolveDepSource>>
): ReturnType<typeof resolveDepSource> {
  if (cache.has(pkgDir)) {
    return cache.get(pkgDir)!;
  }
  const source = resolveDepSource({ name: pkgName, version, dir: pkgDir });
  cache.set(pkgDir, source);
  return source;
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
