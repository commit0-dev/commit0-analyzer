/**
 * Node.js module resolution — owns the analysis layer.
 *
 * Resolution steps (mirrors the spec order):
 *   1. null specifier → UNKNOWN (dynamic require(var)/import(expr))
 *   2. Relative/absolute specifier → first-party file resolution
 *   3. Bare specifier → third-party package via lockfile-pinned dir
 *      - On miss: flat node_modules walk + phantom flag
 *   4. exports/imports map + conditions applied to the package's package.json
 *   5. Workspace sibling (in workspaceDirs map) → first-party source
 *
 * Invariants:
 *   - Never throws. Every unresolvable path returns kind:"unknown".
 *   - DETERMINISM: readdir results are sorted before use.
 *   - Phantom deps (hoisted/undeclared) always set phantom:true.
 *   - Third-party entries are opaque import boundaries — we return the
 *     package entry path for advisory matching, but P5 does not traverse into
 *     third-party internals.
 */

import fs from "node:fs";
import path from "node:path";
import type { ResolvedPackage } from "../project/model.js";
import {
  resolveExportsMap,
  parsePackageSpecifier,
  type ExportsMapValue,
} from "./exports-map.js";

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * Context provided by the caller for each resolution call.
 * All paths must be absolute.
 */
export interface ResolveContext {
  /** Absolute path of the file containing the import/require. */
  fromFile: string;
  /** Absolute path to the workspace root (not the project root). */
  workspaceDir: string;
  /**
   * Lockfile-pinned resolved packages for this workspace.
   * Key = declared package name (e.g. "lodash", "@scope/pkg").
   */
  deps: Map<string, ResolvedPackage>;
  /**
   * Active import conditions, highest priority first.
   * Defaults to ["import", "default"] when absent.
   */
  conditions?: string[];
  /**
   * Map of workspace sibling name → source directory.
   * When present and a bare specifier matches a key, it is resolved as
   * first-party (traversed), not third-party (opaque boundary).
   */
  workspaceDirs?: Map<string, string>;
  /**
   * Set of package names declared in the workspace manifest
   * (union of dependencies, devDependencies, optionalDependencies, peerDependencies keys).
   * When provided, a dep found only via flat node_modules walk is marked
   * phantom:true only when it is NOT in this set.
   * When absent, the legacy behaviour applies: any flat-walk dep is phantom:true.
   */
  declaredDeps?: Set<string>;
}

/** A successfully resolved first-party file. */
export interface ResolveResultFirstParty {
  kind: "first-party";
  resolvedPath: string;
  /** Set when this is a workspace sibling resolved to its source. */
  workspaceSibling?: boolean;
}

/** A successfully resolved third-party package import boundary. */
export interface ResolveResultThirdParty {
  kind: "third-party";
  packageName: string;
  version: string;
  /** Resolved entry path (package.json main / exports map target). */
  resolvedPath: string;
  /**
   * true when the dep was found via flat node_modules walk but was NOT
   * declared in the workspace's manifest (hoisted/phantom dep).
   */
  phantom?: boolean;
}

/** An unresolvable specifier — always emits an UNKNOWN marker. */
export interface ResolveResultUnknown {
  kind: "unknown";
  reason: string;
  /** Original specifier string, or null for dynamic. */
  specifier: string | null;
}

export type ResolveResult =
  | ResolveResultFirstParty
  | ResolveResultThirdParty
  | ResolveResultUnknown;

// ── Extension resolution order ────────────────────────────────────────────────

const EXTENSIONS = [".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"];

/**
 * Try to resolve a path to a real file by appending extensions or an
 * index file. Returns the resolved absolute path or null.
 */
function resolveFileWithExtensions(base: string): string | null {
  // 1. Exact path (already has extension)
  if (fs.existsSync(base) && fs.statSync(base).isFile()) return base;

  // 2. Try each extension
  for (const ext of EXTENSIONS) {
    const candidate = base + ext;
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  // 3. Try as directory: base/index.<ext>
  if (fs.existsSync(base) && fs.statSync(base).isDirectory()) {
    for (const ext of EXTENSIONS) {
      const candidate = path.join(base, "index" + ext);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    }
  }

  return null;
}

// ── Relative / absolute specifier resolution ──────────────────────────────────

function resolveRelative(
  specifier: string,
  fromFile: string
): ResolveResult {
  const fromDir = path.dirname(fromFile);
  const target = path.resolve(fromDir, specifier);
  const resolved = resolveFileWithExtensions(target);
  if (resolved) {
    return { kind: "first-party", resolvedPath: resolved };
  }
  return {
    kind: "unknown",
    reason: `File not found: "${target}" (from "${fromFile}")`,
    specifier,
  };
}

// ── Package entry resolution ──────────────────────────────────────────────────

interface PackageJson {
  name?: string;
  version?: string;
  main?: string;
  module?: string;
  exports?: ExportsMapValue;
  [key: string]: unknown;
}

/** Read and parse a package.json, returning null on any error. */
function readPackageJson(pkgDir: string): PackageJson | null {
  const pkgPath = path.join(pkgDir, "package.json");
  try {
    const raw = fs.readFileSync(pkgPath, "utf8");
    return JSON.parse(raw) as PackageJson;
  } catch {
    return null;
  }
}

/**
 * Resolve the entry file of a package directory given the subpath and
 * active conditions. Applies exports map when present, falls back to
 * main/module fields, then index.js.
 */
function resolvePackageEntry(
  pkgDir: string,
  subpath: string,
  conditions: string[]
): string | null {
  const pkg = readPackageJson(pkgDir);
  if (!pkg) return null;

  // Apply exports map when present
  if (pkg.exports !== undefined && pkg.exports !== null) {
    const mapped = resolveExportsMap(pkg.exports as ExportsMapValue, subpath, conditions);
    if (mapped === null) return null;
    const absolute = path.resolve(pkgDir, mapped);
    return resolveFileWithExtensions(absolute) ?? absolute;
  }

  // No exports map: only root entry "." is resolvable via main/module
  if (subpath !== ".") return null;

  // Prefer source/module field when conditions include "import"
  const preferModule = conditions.includes("import");
  if (preferModule && typeof pkg.module === "string") {
    const candidate = resolveFileWithExtensions(path.resolve(pkgDir, pkg.module));
    if (candidate) return candidate;
  }

  if (typeof pkg.main === "string") {
    const candidate = resolveFileWithExtensions(path.resolve(pkgDir, pkg.main));
    if (candidate) return candidate;
  }

  // Default: index.js
  return resolveFileWithExtensions(path.join(pkgDir, "index"));
}

// ── Flat node_modules walk for phantom resolution ─────────────────────────────

/**
 * Walk up from workspaceDir looking for node_modules/<pkgName>/package.json.
 * Returns the package directory or null.
 * DETERMINISM: no readdir needed — direct stat check is deterministic.
 */
function findInNodeModules(
  pkgName: string,
  workspaceDir: string
): string | null {
  // Check workspaceDir/node_modules/<pkg> and parent directories up to fs root
  let dir = workspaceDir;
  while (true) {
    const candidate = path.join(dir, "node_modules", pkgName);
    if (fs.existsSync(path.join(candidate, "package.json"))) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break; // reached fs root
    dir = parent;
  }
  return null;
}

// ── Main resolver ─────────────────────────────────────────────────────────────

/**
 * Resolve a single import/require specifier to a ResolveResult.
 *
 * Pass `specifier = null` for dynamic (non-literal) specifiers — they always
 * return kind:"unknown" with reason "dynamic specifier".
 */
export function resolveSpecifier(
  specifier: string | null,
  ctx: ResolveContext
): ResolveResult {
  // ── Step 1: Dynamic specifier ─────────────────────────────────────────────
  if (specifier === null) {
    return {
      kind: "unknown",
      reason: "dynamic specifier — cannot statically resolve non-literal import",
      specifier: null,
    };
  }

  const conditions = ctx.conditions ?? ["import", "default"];

  // ── Step 2: Relative / absolute ───────────────────────────────────────────
  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    return resolveRelative(specifier, ctx.fromFile);
  }

  // ── Step 3+4+5: Bare specifier ────────────────────────────────────────────
  const { name: pkgName, subpath } = parsePackageSpecifier(specifier);

  // Step 5: Workspace sibling (first-party, traversed)
  if (ctx.workspaceDirs?.has(pkgName)) {
    const siblingDir = ctx.workspaceDirs.get(pkgName)!;
    const entryPath = resolvePackageEntry(siblingDir, subpath, conditions);
    const resolved = entryPath ?? siblingDir;
    return {
      kind: "first-party",
      resolvedPath: resolved,
      workspaceSibling: true,
    };
  }

  // Step 3: Lockfile-pinned dep
  const pinnedPkg = ctx.deps.get(pkgName);
  if (pinnedPkg) {
    const pkg = readPackageJson(pinnedPkg.dir);
    const entryPath = resolvePackageEntry(pinnedPkg.dir, subpath, conditions);
    if (entryPath === null) {
      // exports map is present but the subpath (or root ".") has no matching
      // condition/entry — return UNKNOWN rather than a directory.
      if (pkg?.exports !== undefined && pkg?.exports !== null) {
        return {
          kind: "unknown",
          reason: subpath === "."
            ? `Root entry of "${pkgName}" has no resolvable condition in exports map`
            : `Subpath "${subpath}" not found in exports map of "${pkgName}"`,
          specifier,
        };
      }
      // No exports field — fall through to directory (main/index fallback handled
      // inside resolvePackageEntry, but if it returned null the dir is the best guess).
    }
    return {
      kind: "third-party",
      packageName: pkgName,
      version: pinnedPkg.version,
      resolvedPath: entryPath ?? pinnedPkg.dir,
      phantom: false,
    };
  }

  // Step 3 fallback: flat node_modules walk
  // A dep found here is phantom (undeclared) only when it is absent from
  // the declared dependency set. A declared dep that is simply missing from
  // the lockfile resolves here without the phantom flag.
  const phantomDir = findInNodeModules(pkgName, ctx.workspaceDir);
  if (phantomDir) {
    const phantomPkg = readPackageJson(phantomDir);
    const entryPath = resolvePackageEntry(phantomDir, subpath, conditions);
    const isDeclared = ctx.declaredDeps !== undefined
      ? ctx.declaredDeps.has(pkgName)
      : false; // no declared set provided → legacy: treat as phantom
    return {
      kind: "third-party",
      packageName: pkgName,
      version: phantomPkg?.version ?? "unknown",
      resolvedPath: entryPath ?? phantomDir,
      phantom: !isDeclared,
    };
  }

  // Completely unresolvable
  return {
    kind: "unknown",
    reason: `Package "${pkgName}" not found in lockfile or node_modules`,
    specifier,
  };
}
