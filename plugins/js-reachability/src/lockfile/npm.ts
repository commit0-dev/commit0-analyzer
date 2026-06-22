import fs from "node:fs/promises";
import path from "node:path";
import type { LockfileGraph, ResolvedPackage } from "../project/model.js";

interface NpmLockPackages {
  [key: string]: {
    version?: string;
    name?: string;
    resolved?: string;
    link?: boolean;
    dependencies?: Record<string, string>;
  };
}

interface NpmLockfile {
  lockfileVersion?: number;
  packages?: NpmLockPackages;
}

export interface NpmParseResult {
  graph: LockfileGraph;
  /** True when the lockfile file exists but could not be parsed. */
  corrupt: boolean;
}

/**
 * Parse package-lock.json v2/v3.
 *
 * The `packages` map keys are paths like:
 *   ""                                  → root (skip)
 *   "node_modules/foo"                  → hoisted at root
 *   "packages/app/node_modules/foo"     → workspace-local (different version)
 *
 * Returns a result with the parsed graph and a corrupt flag.
 * Never throws.
 */
export async function parseNpmLockfile(root: string): Promise<NpmParseResult> {
  const graph: LockfileGraph = new Map();

  let raw: string;
  let filename = "package-lock.json";
  try {
    raw = await fs.readFile(path.join(root, filename), "utf8");
  } catch {
    // Try npm-shrinkwrap.json as fallback
    filename = "npm-shrinkwrap.json";
    try {
      raw = await fs.readFile(path.join(root, filename), "utf8");
    } catch {
      return { graph, corrupt: false }; // no lockfile — not corrupt, just absent
    }
  }

  let lock: NpmLockfile;
  try {
    lock = JSON.parse(raw) as NpmLockfile;
  } catch {
    return { graph, corrupt: true }; // file exists but unparseable
  }

  if (!lock.packages || typeof lock.packages !== "object") {
    return { graph, corrupt: false };
  }

  for (const [key, entry] of Object.entries(lock.packages)) {
    // Skip the root entry (empty string key) and workspace package entries
    // that have no version (they're local workspace references).
    if (key === "") continue;
    if (!key.includes("node_modules")) continue;
    if (entry.link === true) continue;
    if (!entry.version) continue;

    // Derive package name from the key: last "node_modules/X" segment
    const nmIdx = key.lastIndexOf("node_modules/");
    const pkgName = key.slice(nmIdx + "node_modules/".length);

    const resolved: ResolvedPackage = {
      name: entry.name ?? pkgName,
      version: entry.version,
      dir: path.resolve(root, key),
    };
    graph.set(key, resolved);
  }

  return { graph, corrupt: false };
}
