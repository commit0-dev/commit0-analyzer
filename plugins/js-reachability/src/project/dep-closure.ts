/**
 * Workspace dependency closure computation.
 *
 * Walks the installed node_modules graph from a set of root packages,
 * following each package's declared dependencies (dependencies,
 * optionalDependencies, peerDependencies) recursively to produce the
 * full transitive closure.
 *
 * Attribution rule: a package reachable from ANY runtime root is runtime.
 * A package reachable only from dev roots is dev-only. Unknown ≠ safe:
 * unreadable/missing package.json on a branch → that branch is incomplete
 * (not silently dropped). Roots are always seeded from the lockfile-resolved
 * entries in ws.deps / ws.devDeps so a missing on-disk manifest never
 * causes a direct dep to vanish from the closure.
 *
 * Determinism: outputs are Maps whose iteration order matches sorted
 * insertion, produced by iterating dep names in sorted order at every step.
 */

import path from "node:path";
import fs from "node:fs";

// ── Public types ──────────────────────────────────────────────────────────────

/** One resolved installed package in the closure. */
export interface ClosurePkg {
  name: string;
  version: string;
  /** Absolute path to the installed package directory. */
  dir: string;
}

/**
 * Full closure split by attribution.
 *
 *   runtime    — reachable from any direct runtime dep (dependencies /
 *                optionalDependencies) of the workspace.
 *   dev        — reachable from direct devDependencies ONLY; every package
 *                also reachable from a runtime root is excluded from dev.
 *   incomplete — packages whose on-disk manifest could not be read, so
 *                their transitive children are unknown. The package itself
 *                is still present in runtime/dev (seeded from the lockfile).
 *
 * Both maps are keyed by package name (not dir, since the walk de-dupes by dir).
 */
export interface WorkspaceClosure {
  runtime: Map<string, ClosurePkg>;
  dev: Map<string, ClosurePkg>;
  /** Packages with unreadable manifests; their sub-trees could not be walked. */
  incomplete: Array<{ scope: string; reason: string }>;
}

import type { Workspace } from "./model.js";

/**
 * Compute the full installed closure for one workspace.
 *
 * Runtime roots: ws.deps (already-resolved direct runtime deps).
 * Dev roots: ws.devDeps (already-resolved direct dev deps).
 *
 * Roots are seeded directly from the lockfile-resolved entries in ws.deps /
 * ws.devDeps before any on-disk walk, so a missing or corrupt on-disk
 * manifest never silently drops a direct dep from the closure. Transitive
 * children are discovered by walking installed package.json files; if a
 * manifest is unreadable for a known dir, that branch is recorded in
 * `incomplete` and the sub-tree is conservatively omitted.
 *
 * Cycles are handled by tracking visited dirs.
 */
export function computeWorkspaceClosure(ws: Workspace): WorkspaceClosure {
  const incompleteEntries: Array<{ scope: string; reason: string }> = [];

  // ── Seed roots from lockfile-resolved entries ─────────────────────────────
  // This ensures every resolved direct dep appears in the closure even when
  // its on-disk manifest is absent or corrupt (unknown ≠ safe).

  const runtimeDirs = new Set<string>();
  const runtimeByDir = new Map<string, ClosurePkg>();

  for (const [, pkg] of [...ws.deps.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    // Seed from lockfile: always include the root itself.
    if (!runtimeDirs.has(pkg.dir)) {
      runtimeDirs.add(pkg.dir);
      runtimeByDir.set(pkg.dir, { name: pkg.name, version: pkg.version, dir: pkg.dir });
    }
    // Then expand transitive children via disk walk (skipping already-seeded root).
    walkDepTree(pkg.dir, runtimeDirs, runtimeByDir, incompleteEntries);
  }

  const devDirs = new Set<string>();
  const devByDir = new Map<string, ClosurePkg>();

  for (const [, pkg] of [...ws.devDeps.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (!devDirs.has(pkg.dir)) {
      devDirs.add(pkg.dir);
      devByDir.set(pkg.dir, { name: pkg.name, version: pkg.version, dir: pkg.dir });
    }
    walkDepTree(pkg.dir, devDirs, devByDir, incompleteEntries);
  }

  // runtime map keyed by name (sorted for determinism)
  const runtime = new Map<string, ClosurePkg>();
  for (const [, pkg] of [...runtimeByDir.values()]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((p) => [p.dir, p] as [string, ClosurePkg])) {
    runtime.set(pkg.name, pkg);
  }

  // dev-only map: packages reachable via dev roots but NOT in runtime
  const dev = new Map<string, ClosurePkg>();
  for (const [, pkg] of [...devByDir.values()]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((p) => [p.dir, p] as [string, ClosurePkg])) {
    if (!runtimeDirs.has(pkg.dir)) {
      dev.set(pkg.name, pkg);
    }
  }

  return { runtime, dev, incomplete: incompleteEntries };
}

/**
 * Recursively walk the installed dependency tree rooted at pkgDir.
 *
 * The caller is expected to have already added pkgDir to visitedDirs and
 * resultByDir (seeded from the lockfile). This function reads the manifest
 * to discover transitive children and recurses into them.
 *
 * For each child dir visited:
 *   1. Read package.json to get name, version, and declared dep names.
 *   2. For each dep name, locate the installed dir via findInstalledPackageDir.
 *   3. Recurse if not already visited.
 *
 * When a dir is in visitedDirs but its manifest is unreadable, an incomplete
 * entry is recorded and the sub-tree is conservatively omitted. The package
 * itself is still in resultByDir (seeded by the caller or a previous visit).
 *
 * visitedDirs tracks absolute dirs already expanded (cycle guard and de-dup).
 * resultByDir accumulates ClosurePkg entries keyed by absolute dir.
 * incomplete accumulates entries for dirs with unreadable manifests.
 */
function walkDepTree(
  pkgDir: string,
  visitedDirs: Set<string>,
  resultByDir: Map<string, ClosurePkg>,
  incomplete: Array<{ scope: string; reason: string }>
): void {
  // pkgDir is already in visitedDirs (seeded by the caller for roots, or by
  // a previous recursive call). We still need to read the manifest to get
  // declared transitive children.
  const info = readPackageInfo(pkgDir);
  if (info === null) {
    // Manifest unreadable — record incompleteness for the package itself if
    // it has a dir we know exists (i.e. it was seeded or found on disk).
    if (resultByDir.has(pkgDir)) {
      const pkg = resultByDir.get(pkgDir)!;
      incomplete.push({
        scope: pkg.name,
        reason: `manifest unreadable at ${pkgDir}/package.json — transitive children unknown`,
      });
    }
    return;
  }

  // Update the result entry with the on-disk name/version if we have them
  // (the seed used the lockfile version; prefer the on-disk version if readable).
  resultByDir.set(pkgDir, { name: info.name, version: info.version, dir: pkgDir });

  // Expand declared deps in sorted order for determinism
  for (const depName of info.depNames) {
    const installedDir = findInstalledPackageDir(depName, pkgDir);
    if (installedDir !== null && !visitedDirs.has(installedDir)) {
      visitedDirs.add(installedDir);
      const childInfo = readPackageInfo(installedDir);
      if (childInfo === null) {
        // Child dir exists but manifest is unreadable: seed with the dep name
        // and record incomplete. The child is in the closure (dir was found)
        // but its sub-tree cannot be expanded.
        resultByDir.set(installedDir, { name: depName, version: "0.0.0", dir: installedDir });
        incomplete.push({
          scope: depName,
          reason: `manifest unreadable at ${installedDir}/package.json — transitive children unknown`,
        });
      } else {
        resultByDir.set(installedDir, { name: childInfo.name, version: childInfo.version, dir: installedDir });
        walkDepTree(installedDir, visitedDirs, resultByDir, incomplete);
      }
    }
  }
}

// ── Memoization caches ────────────────────────────────────────────────────────
//
// The installed node_modules layout is read repeatedly during a scan: the
// per-workspace closure walk and the call graph's per-dependency transitive
// closure both resolve the same package directories and re-read the same
// package.json files thousands of times. Without caching this is the dominant
// cost on a large repo (a 1000+ dependency project triggers millions of
// statSync/readFileSync calls). The layout is immutable for the duration of a
// scan, so cache by absolute path. clearDepClosureCaches() resets them.
//
// Keys are absolute paths, so distinct projects never collide; the only
// staleness risk is re-installing node_modules in the same long-lived process,
// which a scan does not do.
const installedDirCache = new Map<string, string | null>();
const pkgInfoCache = new Map<string, PkgInfo | null>();

/** Clear the path-keyed filesystem caches (for tests / between unrelated scans). */
export function clearDepClosureCaches(): void {
  installedDirCache.clear();
  pkgInfoCache.clear();
}

// ── Exported resolution helpers (also used by cg/build.ts) ───────────────────

/**
 * Find the installed directory for a package name by walking up the
 * node_modules lookup chain from a starting directory.
 *
 * Mirrors Node.js module resolution: check <startDir>/node_modules/<name>,
 * then <parent>/node_modules/<name>, until the filesystem root.
 *
 * Returns the absolute path to the package directory or null if not found.
 * Memoized by (startDir, name) — the result is invariant for a scan.
 */
export function findInstalledPackageDir(name: string, startDir: string): string | null {
  const key = `${startDir}\0${name}`;
  const cached = installedDirCache.get(key);
  if (cached !== undefined) return cached;

  let current = startDir;
  let result: string | null = null;
  while (true) {
    const candidate = path.join(current, "node_modules", name);
    try {
      if (fs.statSync(candidate).isDirectory()) {
        result = candidate;
        break;
      }
    } catch {
      // not found at this level
    }
    const parent = path.dirname(current);
    if (parent === current) break; // filesystem root
    current = parent;
  }
  installedDirCache.set(key, result);
  return result;
}

/**
 * Read the declared runtime dependency names from a package's package.json.
 *
 * Returns the union of dependencies, peerDependencies, and optionalDependencies.
 * Returns an empty array if the package.json cannot be read or parsed.
 */
export function readDepDeclaredPackages(pkgDir: string): string[] {
  return readPackageInfo(pkgDir)?.depNames ?? [];
}

// ── Private helpers ───────────────────────────────────────────────────────────

interface PkgInfo {
  name: string;
  version: string;
  /** Sorted dep names to expand (dependencies + optionalDeps + peerDeps). */
  depNames: string[];
}

/** Read + parse a package.json once, memoized by directory. */
function readPackageInfo(pkgDir: string): PkgInfo | null {
  const cached = pkgInfoCache.get(pkgDir);
  if (cached !== undefined) return cached;

  let info: PkgInfo | null = null;
  try {
    const manifestPath = path.join(pkgDir, "package.json");
    const raw = fs.readFileSync(manifestPath, "utf8");
    const manifest = JSON.parse(raw) as Record<string, unknown>;
    const name = typeof manifest.name === "string" ? manifest.name : path.basename(pkgDir);
    const version = typeof manifest.version === "string" ? manifest.version : "0.0.0";
    const depNames = new Set<string>();
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
      const deps = manifest[field];
      if (deps && typeof deps === "object" && !Array.isArray(deps)) {
        for (const n of Object.keys(deps as Record<string, unknown>)) {
          depNames.add(n);
        }
      }
    }
    info = { name, version, depNames: [...depNames].sort() };
  } catch {
    info = null;
  }
  pkgInfoCache.set(pkgDir, info);
  return info;
}
