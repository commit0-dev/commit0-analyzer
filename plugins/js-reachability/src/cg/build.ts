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
import { resolveSpecifier } from "../resolve/index.js";
import { buildProjectModel } from "../project/build-project-model.js";
import { resolveDepSource } from "../depsource/resolve-dep-source.js";
import type { ResolveContext } from "../resolve/index.js";
import type { UnknownMarker } from "../engine/graph.js";
import { makeUnknownMarker } from "./unknown-frontier.js";
import type { ResolvedPackage } from "../project/model.js";
import * as telemetry from "../telemetry.js";

// Files matching either guard are skipped before the isolated parser sees them.
// A generated bundle or a minified vendor blob is not analyzable hand-written
// source; feeding one to the native oxc parser can crash the worker process via
// OS memory pressure (uncatchable signal kill). Two signals catch the offenders:
//   - total size (multi-megabyte files: e.g. a vendored compiler);
//   - longest single line (minified bundles pack code into ~hundreds-of-KB
//     lines; real source stays well under this).
// The worker applies the same thresholds before calling oxc so that even if a
// request slips through (e.g. a file that grows between stat and parse), the
// worker is the last line of defense. Both checks share the constants below
// (imported from parse-limits.ts, DRY).
//
// Soundness is preserved: an unparsed reachable file is an unanalyzable
// boundary (its imports become UNKNOWN, never NOT_REACHABLE).
import {
  MAX_PARSE_BYTES,
  MAX_LINE_BYTES,
  hasLineLongerThan,
} from "../parse/parse-limits.js";
import { ParserPool, DEFAULT_POOL_CONCURRENCY } from "../parse/parser-pool.js";
import type { ParsedModule } from "../parse/types.js";
import {
  findInstalledPackageDir,
  readDepDeclaredPackages,
  clearDepClosureCaches,
} from "../project/dep-closure.js";

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
  const stopBuild = telemetry.span("cg.build");
  telemetry.count("cg.build.calls");

  // Reset the path-keyed memo caches at the start of every build. The transitive
  // closure and the dep-closure filesystem reads are invariant only WITHIN a
  // scan; a long-lived plugin process could otherwise re-scan the same path
  // after node_modules changed and read a stale (under-scoped) closure, which
  // would risk a false NOT_REACHABLE. Clearing here keeps the per-scan memo
  // benefit while guaranteeing freshness across scans.
  transitiveClosureCache.clear();
  clearDepClosureCaches();

  // Start a pool of isolated parser workers for this call graph build.
  // Each worker runs in a separate child process so a native oxc crash is
  // contained to that worker: the in-flight file resolves as kind:"unknown"
  // and that worker respawns, while all other workers continue unaffected.
  // A fresh pool per build means stop() cleanly terminates all workers
  // without affecting other concurrent or future scans.
  const pool = new ParserPool();
  pool.start();
  try {

  // Build project model to get declared deps and lockfile-resolved packages
  const stopModel = telemetry.span("cg.buildProjectModel");
  const model = await buildProjectModel(projectRoot);
  stopModel();

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

  // Union of the transitive declared closures of every reachable reduced/none
  // fidelity dependency. Collapses thousands of per-import-site closure copies
  // into one set (see the reduced-fidelity branch below); emitted as a single
  // frontier marker after the walk.
  const reducedReachableClosure = new Set<string>();

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

  // Bounded-concurrency BFS. Keeps up to DEFAULT_POOL_CONCURRENCY parses
  // in flight simultaneously while preserving deterministic OUTPUT:
  //   - Entrypoints are seeded in sorted order.
  //   - Each file's imports are enqueued in sorted order (by line/col, then
  //     resolved path alphabetically for first-party edges).
  //   - All order-sensitive outputs (importSites, unknownFrontiers) are sorted
  //     before return, so completion order does not affect the result.
  //
  // Concurrency contract: we never start more than DEFAULT_POOL_CONCURRENCY
  // parse operations simultaneously. The pool itself enforces this bound, and
  // we track inFlight here so we know when the BFS is truly done (queue empty
  // AND no parses outstanding).

  /**
   * Per-file synchronous work: build resolution context, apply bundle guard.
   * Returns null when the file should be skipped (guard fired); otherwise
   * returns the ResolveContext to use when processing the parse result.
   */
  function prepareFile(file: string): ResolveContext | null {
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

    // Bundle/minified guard: skip files before sending them to the isolated
    // parser worker. Size is checked via stat (no read for huge files); the
    // longest-line check reads the file to inspect line lengths. The worker
    // re-applies the same guard independently, so even if a file slips through
    // here (e.g. it grew between stat and parse), the worker is a second check.
    // A skipped file is treated as an unanalyzable boundary so unknown ≠ safe
    // still holds.
    let fileSize = 0;
    try {
      fileSize = fs.statSync(file).size;
    } catch {
      // stat failure → fall through; the worker will return kind:"unknown"
    }
    let source: string | undefined;
    let skip = fileSize > MAX_PARSE_BYTES;
    if (!skip && fileSize > 0) {
      try {
        source = fs.readFileSync(file, "utf8");
        if (hasLineLongerThan(source, MAX_LINE_BYTES)) skip = true;
      } catch {
        // read failure → fall through; the worker will return kind:"unknown"
        source = undefined;
      }
    }
    if (skip) {
      telemetry.count("cg.skippedBundle");
      if (inNodeModules) {
        // A dep's bundle could statically pull anything in the dep's transitive
        // closure; add that to the union UNKNOWN frontier (same treatment as a
        // reduced-fidelity dep).
        const pkgDir = packageDirForDepFile(file);
        if (pkgDir) {
          for (const dep of computeTransitiveDepClosure(pkgDir)) {
            reducedReachableClosure.add(dep);
          }
        }
      } else {
        // First-party bundle (rare): we cannot see its imports at all, so emit
        // a global UNKNOWN frontier (no couldReach scope).
        unknownFrontiers.push(
          makeUnknownMarker(
            "dynamic-specifier",
            `File skipped as a bundle/minified blob (${fileSize} bytes): ${file}`,
            file,
            0,
            0
          )
        );
      }
      return null; // skip: do not dispatch to parser
    }

    return ctx;
  }

  /**
   * Process a completed parse result for `file` using `ctx`.
   * Records import sites, enqueues newly discovered files, and accumulates
   * frontier markers. All mutations go to the shared accumulators above.
   */
  function processResult(
    file: string,
    ctx: ResolveContext,
    parsed: ParsedModule
  ): void {
    const inNodeModules = isInsideNodeModules(file);

    if (parsed.kind === "unknown") {
      // Parse error: emit UNKNOWN marker, do not traverse further from this file
      unknownFrontiers.push(
        makeUnknownMarker("parse-error", parsed.reason, file, 0, 0)
      );
      return;
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
        telemetry.count(`cg.depSource.${depSource.fidelity}`);

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
          //
          // We accumulate every reduced/none dep's closure into ONE union set
          // rather than emitting a per-import-site marker carrying its own copy
          // of the closure. On a large repo with a flat node_modules, each such
          // closure is ~the whole installed set and there are thousands of
          // import sites; storing a copy per site exhausts memory and the
          // verdict only needs the union (a target package is UNKNOWN-blocked
          // iff SOME reachable unanalyzable dep could load it). One union marker
          // anchored to a reachable file is emitted after the walk.
          const stopClosure = telemetry.span("cg.transitiveClosure");
          const transitiveClosure = computeTransitiveDepClosure(resolved.packageDir);
          stopClosure();
          telemetry.count("cg.transitiveClosure.calls");
          telemetry.observe("cg.transitiveClosure.size", transitiveClosure.length);
          for (const dep of transitiveClosure) reducedReachableClosure.add(dep);
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

  // BFS driver: keep up to DEFAULT_POOL_CONCURRENCY parses in flight.
  // Single-threaded JS means the callbacks below run serially (no locking
  // needed). We use a Promise-based loop: fill capacity, then await any
  // completion, process its result (which may add to the queue), then fill
  // capacity again. Repeat until queue is empty AND no parses are in flight.
  let head = 0;     // next queue index to dispatch (avoids O(N) splice)
  let inFlight = 0; // number of parses currently outstanding

  // Resolve handle used by a completing parse to wake the driver.
  let wakeDriver: (() => void) | null = null;

  async function driveLoop(): Promise<void> {
    while (true) {
      // Fill available capacity
      while (inFlight < DEFAULT_POOL_CONCURRENCY && head < queue.length) {
        const file = queue[head++];

        if (reachableFiles.has(file)) continue;
        reachableFiles.add(file);

        // Heartbeat: visible progress during long traversals.
        if (telemetry.isEnabled() && reachableFiles.size % 50 === 0) {
          process.stderr.write(
            `[hb] reachable=${reachableFiles.size} queue=${queue.length} inFlight=${inFlight} frontiers=${unknownFrontiers.length} heapMB=${(process.memoryUsage().heapUsed / 1048576) | 0} file=${file}\n`
          );
        }

        // Synchronous guard + context build (no await needed)
        const ctx = prepareFile(file);
        if (ctx === null) continue; // guard fired, file skipped

        // Dispatch parse (non-blocking)
        inFlight++;
        const stopParse = telemetry.span("cg.parseModule");
        pool.parse(file).then((parsed) => {
          stopParse();
          telemetry.count("cg.parseModule.calls");
          inFlight--;
          processResult(file, ctx, parsed);
          // Wake the driver so it can fill capacity and check termination
          if (wakeDriver !== null) {
            const wake = wakeDriver;
            wakeDriver = null;
            wake();
          }
        });
      }

      // If nothing is in flight and the queue is drained, we are done
      if (inFlight === 0 && head >= queue.length) break;

      // Wait for any in-flight parse to complete (it will call wake)
      await new Promise<void>((resolve) => {
        wakeDriver = resolve;
      });
    }
  }

  await driveLoop();

  // Emit ONE union frontier for all reachable reduced/none-fidelity deps.
  // Anchored to the first reachable file (insertion order = first entrypoint),
  // which the consumer's reachable-file filter accepts. A target package is
  // UNKNOWN (not NOT_REACHABLE) when it sits in this union and has no proven
  // static path — identical to the previous per-site markers, minus the
  // per-site memory blow-up.
  if (reducedReachableClosure.size > 0) {
    const anchor = reachableFiles.values().next().value;
    if (anchor !== undefined) {
      unknownFrontiers.push(
        makeUnknownMarker(
          "dynamic-specifier",
          "Reduced-fidelity dependencies are reachable but unanalyzable; their transitive deps may be loaded",
          anchor,
          0,
          0,
          [...reducedReachableClosure].sort()
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

  // Sort frontiers so the output order is independent of BFS visitation order
  // (which is no longer globally sorted — see the head-index loop above).
  unknownFrontiers.sort(
    (a, b) =>
      a.fromFile.localeCompare(b.fromFile) ||
      a.line - b.line ||
      a.column - b.column ||
      a.reason.localeCompare(b.reason) ||
      a.detail.localeCompare(b.detail)
  );

  telemetry.observe("cg.reachableFiles", reachableFiles.size);
  telemetry.observe("cg.importSites.packages", importSites.size);
  telemetry.observe("cg.unknownFrontiers", unknownFrontiers.length);
  stopBuild();

  return { reachableFiles, importSites, unknownFrontiers };

  } finally {
    // Always stop all pool workers when the scan finishes or throws.
    // This kills all child processes so none linger after the scan.
    pool.stop();
  }
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
 *
 * Memoized by pkgDir: the closure is invariant for a scan, and the same
 * dependency is reached from many import sites. Without this memo a large repo
 * recomputes the (≈whole) closure thousands of times — the dominant cost.
 * The underlying filesystem reads are also cached (see dep-closure.ts).
 */
const transitiveClosureCache = new Map<string, string[]>();

function computeTransitiveDepClosure(pkgDir: string): string[] {
  const cached = transitiveClosureCache.get(pkgDir);
  if (cached !== undefined) return cached;

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
  const result = [...closure].sort();
  transitiveClosureCache.set(pkgDir, result);
  return result;
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
