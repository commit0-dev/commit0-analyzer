import fs from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import type { IncompleteEntry, PackageJson, Workspace } from "./model.js";

interface DiscoverResult {
  workspaces: Workspace[];
  incomplete: IncompleteEntry[];
}

/**
 * A directory path tagged with how it was produced:
 *   fromGlob=true  → produced by a wildcard expansion (/* or /**)
 *   fromGlob=false → listed literally in the workspaces array
 *
 * A glob-expanded path that has no package.json is silently skipped.
 * A literally-listed path that has no package.json may warrant an incomplete entry.
 */
interface CandidateDir {
  dir: string;
  fromGlob: boolean;
}

/** Expand a glob pattern of the form "prefix/*" or "prefix/**" relative to root.
 *  Only supports the trailing /* and /** wildcard — sufficient for workspace patterns.
 *  Results are sorted deterministically by directory name.
 */
async function expandGlob(
  root: string,
  pattern: string,
  incomplete: IncompleteEntry[]
): Promise<CandidateDir[]> {
  // Normalise: "packages/*" → base="packages", depth=1; "packages/**" → depth=2
  const singleStar = pattern.endsWith("/*");
  const doubleStar = pattern.endsWith("/**");

  if (!singleStar && !doubleStar) {
    // Literal path — no glob expansion
    const dir = path.resolve(root, pattern);
    try {
      const stat = await fs.stat(dir);
      if (stat.isDirectory()) return [{ dir, fromGlob: false }];
    } catch {
      incomplete.push({
        scope: pattern,
        reason: `Workspace pattern "${pattern}" matches no directory in ${root}.`,
        kind: "workspace-glob-empty",
      });
    }
    return [];
  }

  const base = pattern.slice(0, pattern.length - (singleStar ? 2 : 3));
  const baseDir = path.resolve(root, base);

  let entries: string[];
  try {
    const raw = await fs.readdir(baseDir, { withFileTypes: true });
    entries = raw
      .filter((e) => e.isDirectory() || e.isSymbolicLink())
      .map((e) => path.join(baseDir, e.name))
      .sort();
  } catch {
    incomplete.push({
      scope: pattern,
      reason: `Workspace pattern "${pattern}" base directory "${baseDir}" not found.`,
      kind: "workspace-glob-empty",
    });
    return [];
  }

  if (entries.length === 0) {
    incomplete.push({
      scope: pattern,
      reason: `Workspace glob "${pattern}" matched no directories under ${baseDir}.`,
      kind: "workspace-glob-empty",
    });
  }

  // All entries from a wildcard expansion are tagged fromGlob=true.
  // A matched directory with no package.json is an ordinary scaffolding or
  // intermediate container directory — not a workspace, not an error signal.
  return entries.map((dir) => ({ dir, fromGlob: true }));
}

async function readPackageJson(dir: string): Promise<PackageJson | null> {
  try {
    const raw = await fs.readFile(path.join(dir, "package.json"), "utf8");
    return JSON.parse(raw) as PackageJson;
  } catch {
    return null;
  }
}

/** Resolve workspace glob patterns from the root package.json or pnpm-workspace.yaml. */
async function resolveGlobs(
  root: string,
  manager: string,
  rootManifest: PackageJson,
  incomplete: IncompleteEntry[]
): Promise<CandidateDir[]> {
  let patterns: string[] = [];

  if (manager === "pnpm") {
    // pnpm uses pnpm-workspace.yaml
    try {
      const raw = await fs.readFile(
        path.join(root, "pnpm-workspace.yaml"),
        "utf8"
      );
      const doc = parseYaml(raw) as { packages?: string[] } | null;
      patterns = doc?.packages ?? [];
    } catch {
      // no pnpm-workspace.yaml — fall through to check package.json workspaces
    }
  }

  if (patterns.length === 0) {
    const ws = rootManifest.workspaces;
    if (Array.isArray(ws)) {
      patterns = ws;
    } else if (ws && typeof ws === "object" && Array.isArray(ws.packages)) {
      patterns = ws.packages;
    }
  }

  if (patterns.length === 0) {
    return []; // single-package repo
  }

  const candidates: CandidateDir[] = [];
  for (const pattern of patterns) {
    const expanded = await expandGlob(root, pattern, incomplete);
    candidates.push(...expanded);
  }
  return candidates;
}

/**
 * Enumerate all workspaces for a project.
 * For single-package repos (no workspaces field) returns one workspace at root.
 * Results are sorted deterministically by workspace name.
 */
export async function discoverWorkspaces(
  root: string,
  manager: string
): Promise<DiscoverResult> {
  const incomplete: IncompleteEntry[] = [];

  const rootManifest = await readPackageJson(root);
  if (!rootManifest) {
    incomplete.push({
      scope: root,
      reason: `Could not read package.json at ${root}.`,
      kind: "other",
    });
    return { workspaces: [], incomplete };
  }

  const candidates = await resolveGlobs(root, manager, rootManifest, incomplete);

  if (candidates.length === 0) {
    // Single-package repo
    const ws: Workspace = {
      name: rootManifest.name ?? path.basename(root),
      dir: root,
      manifest: rootManifest,
      deps: new Map(),
      devDeps: new Map(),
      localDeps: [],
    };
    return { workspaces: [ws], incomplete };
  }

  const workspaces: Workspace[] = [];
  for (const { dir, fromGlob } of candidates) {
    const manifest = await readPackageJson(dir);
    if (!manifest) {
      if (fromGlob) {
        // A glob-expanded directory without package.json is a normal scaffolding
        // or intermediate container dir in a monorepo — silently skip it.
        continue;
      }
      // An explicitly-listed (non-glob) workspace path with no package.json
      // is unexpected and surfaces as an incomplete signal.
      incomplete.push({
        scope: dir,
        reason: `No package.json found in workspace directory ${dir}.`,
        kind: "other",
      });
      continue;
    }
    workspaces.push({
      name: manifest.name ?? path.basename(dir),
      dir,
      manifest,
      deps: new Map(),
      devDeps: new Map(),
      localDeps: [],
    });
  }

  // Deterministic sort by name
  workspaces.sort((a, b) => a.name.localeCompare(b.name));

  return { workspaces, incomplete };
}
