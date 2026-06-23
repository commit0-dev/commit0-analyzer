import fs from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import type { IncompleteEntry, LockfileGraph, ResolvedPackage } from "../project/model.js";
import { isPlatformExcluded } from "./platform-filter.js";

export interface PnpmParseResult {
  graph: LockfileGraph;
  /** Importer map: workspace-relative-dir → { depName → resolved version string } */
  importers: Map<string, Map<string, string>>;
  /** True when the lockfile exists but could not be parsed. */
  corrupt: boolean;
  /**
   * Incomplete entries for packages whose on-disk store path could not be
   * resolved (e.g. dangling symlink / missing .pnpm store entry).
   */
  incomplete: import("../project/model.js").IncompleteEntry[];
}

/**
 * Parse pnpm-lock.yaml (lockfileVersion 5, 6, 7).
 *
 * The `packages` block uses content-addressed keys of the form:
 *   /name@version                    (lockfileVersion ≤ 6)
 *   /name@version(peer@ver)          (peer-dep suffix — must be stripped before key lookup)
 *   name@version                     (lockfileVersion 7+, no leading slash)
 *
 * The `importers` block records per-workspace resolved versions:
 *   importers.<wsRelDir>.dependencies.<dep>.version → "4.17.21" or "4.17.21(react@18)"
 *
 * Resolution strategy:
 *   For each workspace we read importers.<wsRelDir>.dependencies.<dep>.version,
 *   strip the peer suffix, and look up "/name@version" in packages. This gives the
 *   EXACT version per workspace instead of first-name-match across all packages.
 *
 * On-disk location in the virtual store:
 *   <root>/node_modules/.pnpm/<name>@<version>/node_modules/<name>
 *
 * We follow the symlink (realpath) so callers get the canonical path.
 * On missing lockfile returns an empty/clean result — never throws.
 * On corrupt lockfile returns corrupt=true with empty graph.
 */
/** Optional host descriptor for deterministic platform filtering in tests. */
export interface HostDescriptor {
  platform?: string;
  arch?: string;
}

export async function parsePnpmLockfile(
  root: string,
  host?: HostDescriptor
): Promise<PnpmParseResult> {
  const empty: PnpmParseResult = {
    graph: new Map(),
    importers: new Map(),
    corrupt: false,
    incomplete: [],
  };

  let raw: string;
  try {
    raw = await fs.readFile(path.join(root, "pnpm-lock.yaml"), "utf8");
  } catch {
    return empty;
  }

  let lock: Record<string, unknown>;
  try {
    lock = (parseYaml(raw) as Record<string, unknown>) ?? {};
  } catch {
    // File exists but YAML is unparseable
    return { ...empty, corrupt: true };
  }

  const graph: LockfileGraph = new Map();
  const incomplete: IncompleteEntry[] = [];

  // List the .pnpm virtual store once so we can fall back to peer-dep-suffixed
  // directory names: pnpm appends "_<encoded-peers>" to a package's store dir
  // when it has resolved peer dependencies (e.g. the store dir for
  // @babel/helper-module-transforms@7.29.7 is @babel+helper-module-transforms@7.29.7_@babel+core@7.29.7).
  const pnpmStoreRoot = path.join(root, "node_modules", ".pnpm");
  let storeEntries: string[] = [];
  try {
    storeEntries = (await fs.readdir(pnpmStoreRoot)).sort();
  } catch {
    // No virtual store on disk (not installed / hoisted) — the fallback no-ops.
  }

  // ── 1. Parse packages block ───────────────────────────────────────────────
  const packagesRaw = lock["packages"] as Record<string, unknown> | undefined;
  if (packagesRaw && typeof packagesRaw === "object") {
    for (const rawKey of Object.keys(packagesRaw)) {
      // Normalise: ensure leading slash
      const key = rawKey.startsWith("/") ? rawKey : `/${rawKey}`;

      // Parse name and version, stripping any peer-dep suffix
      const parsed = parsePackageKey(key);
      if (!parsed) continue;

      const { name, version } = parsed;

      // Read platform constraints from the lockfile entry.
      const entry = packagesRaw[rawKey] as Record<string, unknown> | undefined;
      const entryOptional = entry?.["optional"] === true;
      const entryOs = Array.isArray(entry?.["os"])
        ? (entry["os"] as string[])
        : undefined;
      const entryCpu = Array.isArray(entry?.["cpu"])
        ? (entry["cpu"] as string[])
        : undefined;

      // Build the canonical store path. pnpm encodes the scope separator "/" as
      // "+" in the .pnpm store directory name (e.g. @actions/core@3.0.1 lives at
      // .pnpm/@actions+core@3.0.1/), while the inner node_modules/<name> keeps the
      // original slash. Without this encoding every scoped dependency fails to
      // resolve in the virtual store.
      const storeEntry = `${name.replace(/\//g, "+")}@${version}`;
      const storeDir = path.join(
        root,
        "node_modules",
        ".pnpm",
        storeEntry,
        "node_modules",
        name
      );

      let resolvedDir = storeDir;
      let resolved = false;
      try {
        resolvedDir = await fs.realpath(storeDir);
        resolved = true;
      } catch {
        // Exact store dir missing — pnpm may have suffixed it with a peer-dep
        // context ("<storeEntry>_<encoded-peers>"). Fall back to the first such
        // variant; they all materialise the same package version on disk.
        const peerMatch = storeEntries.find((e) =>
          e.startsWith(`${storeEntry}_`)
        );
        if (peerMatch) {
          try {
            resolvedDir = await fs.realpath(
              path.join(pnpmStoreRoot, peerMatch, "node_modules", name)
            );
            resolved = true;
          } catch {
            // fall through to incomplete
          }
        }
      }
      if (!resolved) {
        // Suppress dep-unresolved for optional packages whose os/cpu constraints
        // exclude the current host: they are legitimately not installed.
        const platformSkip =
          entryOptional &&
          isPlatformExcluded(entryOs, entryCpu, host?.platform, host?.arch);
        if (platformSkip) {
          // Platform-excluded optional package: do not insert a fabricated dir
          // into the graph so no downstream stage tries to read a path that
          // does not exist on the current platform.
          continue;
        }
        // Store entry absent or dangling symlink — surface as incomplete
        // so callers know the dir path is a fabricated fallback, not real.
        incomplete.push({
          scope: `${name}@${version}`,
          reason: `pnpm store path not found or dangling symlink: ${storeDir}`,
          kind: "dep-unresolved",
        });
      }

      const pkg: ResolvedPackage = { name, version, dir: resolvedDir };
      // Store under the normalised key (with leading slash, including peer suffix)
      graph.set(key, pkg);
    }
  }

  // ── 2. Parse importers block ──────────────────────────────────────────────
  // Produces a map: wsRelDir → (depName → resolvedVersion string without peer suffix).
  // Per-workspace exact versions from the importers block prevent version collisions
  // when two workspaces depend on different versions of the same package.
  const importersMap: Map<string, Map<string, string>> = new Map();

  const importersRaw = lock["importers"] as
    | Record<string, unknown>
    | undefined;
  if (importersRaw && typeof importersRaw === "object") {
    for (const [wsDir, wsData] of Object.entries(importersRaw)) {
      const depMap = new Map<string, string>();

      const wsObj = wsData as Record<string, unknown> | undefined;
      if (!wsObj) continue;

      // Merge all dep categories that get installed
      const depCategories = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
      ] as const;
      for (const category of depCategories) {
        const deps = wsObj[category] as
          | Record<string, unknown>
          | undefined;
        if (!deps || typeof deps !== "object") continue;

        for (const [depName, depData] of Object.entries(deps)) {
          const info = depData as Record<string, unknown> | undefined;
          if (!info) continue;

          const versionRaw = info["version"] as string | undefined;
          if (!versionRaw) continue;

          // Strip peer suffix from version string: "4.17.21(react@18.0.0)" → "4.17.21"
          const version = stripPeerSuffix(versionRaw);

          // Skip link: entries — those are local workspace references, not external deps
          if (version.startsWith("link:")) continue;

          depMap.set(depName, version);
        }
      }
      importersMap.set(wsDir, depMap);
    }
  }

  // Sort incomplete deterministically
  incomplete.sort((a, b) => a.scope.localeCompare(b.scope));

  return { graph, importers: importersMap, corrupt: false, incomplete };
}

/**
 * Strip the peer-dependency context suffix from a pnpm version string.
 * "4.17.21(react@18.0.0)" → "4.17.21"
 * "4.17.21"               → "4.17.21"  (no-op)
 */
function stripPeerSuffix(v: string): string {
  const parenIdx = v.indexOf("(");
  return parenIdx >= 0 ? v.slice(0, parenIdx) : v;
}

/**
 * Extract package name and version from a pnpm package key.
 * Handles peer-dep suffixes and scoped names.
 *
 * Key forms:
 *   /lodash@4.17.21
 *   /lodash@4.17.21(react@18.0.0)
 *   /@scope/pkg@1.0.0
 *   /@scope/pkg@1.0.0(peer@2.0.0)
 */
export function parsePackageKey(
  key: string
): { name: string; version: string } | null {
  // Strip leading slash
  let withoutSlash = key.startsWith("/") ? key.slice(1) : key;

  // Strip peer-dep suffix: strip everything from the first "(" that is NOT
  // inside the package name (i.e., after the version part starts).
  // The name never contains "(", so we can safely strip from the first "(".
  const parenIdx = withoutSlash.indexOf("(");
  if (parenIdx >= 0) {
    withoutSlash = withoutSlash.slice(0, parenIdx);
  }

  // Now withoutSlash is "name@version" or "@scope/name@version"
  // Find the "@" that separates version from name:
  //   For scoped packages like @scope/pkg@1.0.0, the first "@" is part of the name.
  //   We want the LAST "@" that comes after the package name boundary.
  //   Since package names may not contain "@" except as the leading scope indicator,
  //   the version "@" is the last "@" in the string.
  const atIdx = withoutSlash.lastIndexOf("@");
  if (atIdx <= 0) return null;

  const name = withoutSlash.slice(0, atIdx);
  const version = withoutSlash.slice(atIdx + 1);

  if (!name || !version) return null;
  return { name, version };
}
