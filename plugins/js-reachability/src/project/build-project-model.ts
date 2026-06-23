import path from "node:path";
import type {
  IncompleteEntry,
  LockfileGraph,
  ProjectModel,
  ResolvedPackage,
  Workspace,
} from "./model.js";
import { detectManager } from "./detect-manager.js";
import { discoverWorkspaces } from "./discover-workspaces.js";
import { parseLockfile, type LockfileParseResult, type HostDescriptor } from "../lockfile/index.js";
import type { PnpmParseResult } from "../lockfile/pnpm.js";
import { isPlatformExcluded } from "../lockfile/platform-filter.js";

/**
 * Find the resolved package for a declared dependency inside a workspace.
 *
 * npm hoisting: look for the dep at workspace-local path first, then root.
 *   workspace dir relative to root → "packages/app"
 *   local key  → "packages/app/node_modules/dep"
 *   hoisted key → "node_modules/dep"
 */
function resolveNpmDep(
  depName: string,
  wsRelDir: string,
  graph: LockfileGraph
): ResolvedPackage | undefined {
  // Try workspace-local first
  const localKey = `${wsRelDir}/node_modules/${depName}`;
  if (graph.has(localKey)) return graph.get(localKey);

  // Fall back to hoisted root
  const hoistedKey = `node_modules/${depName}`;
  return graph.get(hoistedKey);
}

/**
 * Resolve a pnpm dep using the per-workspace importer map.
 *
 * The importer block records the EXACT resolved version per workspace:
 *   importers["packages/app"].dependencies["lodash"].version = "4.16.6"
 *
 * We look up the version from the importer for this workspace, then key
 * into the packages graph as "/name@version". This gives the correct version
 * even when two workspaces depend on different versions of the same package.
 *
 * Falls back to name-scan only when the importer entry is absent (e.g. the
 * dep is declared in package.json but not yet in the importer — unusual).
 */
function resolvePnpmDep(
  depName: string,
  wsRelDir: string,
  graph: LockfileGraph,
  importers: PnpmParseResult["importers"]
): ResolvedPackage | undefined {
  // wsRelDir is "" for the root workspace; pnpm uses "." as the root importer key
  const importerKey = wsRelDir === "" ? "." : wsRelDir;
  const wsImporter = importers.get(importerKey);

  if (wsImporter) {
    const resolvedVersion = wsImporter.get(depName);
    if (resolvedVersion) {
      // Graph key is "/name@version" (normalised with leading slash in parser)
      const graphKey = `/${depName}@${resolvedVersion}`;
      const pkg = graph.get(graphKey);
      if (pkg) return pkg;
    }
  }

  // Fallback: name-scan (only used if importer data is absent/incomplete)
  for (const [, pkg] of graph) {
    if (pkg.name === depName) return pkg;
  }
  return undefined;
}

function resolveYarnDep(
  depName: string,
  specifier: string,
  graph: LockfileGraph
): ResolvedPackage | undefined {
  // yarn keyed by "name@range"
  const key = `${depName}@${specifier}`;
  if (graph.has(key)) return graph.get(key);

  // Fallback: scan for any entry with matching name
  for (const [, pkg] of graph) {
    if (pkg.name === depName) return pkg;
  }
  return undefined;
}

/** All declared runtime dep fields in package.json, split by optional flag. */
function allDeclaredDeps(manifest: Workspace["manifest"]): {
  required: Record<string, string>;
  optional: Record<string, string>;
} {
  return {
    required: { ...(manifest.dependencies ?? {}) },
    optional: { ...(manifest.optionalDependencies ?? {}) },
    // devDependencies and peerDependencies intentionally excluded — not installed at runtime
  };
}

/**
 * Check if a specifier looks like a workspace reference.
 * Bare "*" only counts as a workspace ref when the dep name is a known sibling
 * workspace — a plain "*" version range in a non-workspace dep must not be
 * treated as a local dep reference.
 */
function isWorkspaceRef(specifier: string, depName: string, wsNames: Set<string>): boolean {
  if (specifier.startsWith("workspace:") || specifier.startsWith("file:")) {
    return true;
  }
  // "*" is only a workspace ref when the name is actually a sibling workspace
  if (specifier === "*" && wsNames.has(depName)) {
    return true;
  }
  return false;
}

/**
 * Assemble the full ProjectModel for a project root.
 * Never throws — all errors surface as incomplete[] entries.
 *
 * The optional `host` descriptor is used for deterministic platform filtering
 * (primarily in tests). Production callers omit it; process.platform/arch are used.
 */
export async function buildProjectModel(
  root: string,
  host?: HostDescriptor
): Promise<ProjectModel> {
  const incomplete: IncompleteEntry[] = [];

  // 1. Detect package manager
  const { manager, incomplete: managerIncomplete } = await detectManager(root);
  incomplete.push(...managerIncomplete);

  // 2. Discover workspaces
  const { workspaces, incomplete: wsIncomplete } = await discoverWorkspaces(
    root,
    manager
  );
  incomplete.push(...wsIncomplete);

  // 3. Parse lockfile
  let graph: LockfileGraph = new Map();
  let importers: PnpmParseResult["importers"] = new Map();
  let optionalPlatformConstraints = new Map<string, { os?: string[]; cpu?: string[] }>();
  try {
    const lockResult: LockfileParseResult = await parseLockfile(root, manager, host);
    graph = lockResult.graph;
    importers = lockResult.importers;
    optionalPlatformConstraints = lockResult.optionalPlatformConstraints;
    incomplete.push(...lockResult.incomplete);
  } catch (err) {
    incomplete.push({
      scope: root,
      reason: `Lockfile parse error: ${String(err)}`,
      kind: "other",
    });
  }

  // 4. Build workspace name set for local dep detection
  const wsNames = new Set(workspaces.map((w) => w.name));

  // 5. Fill deps and localDeps for each workspace
  for (const ws of workspaces) {
    const { required, optional } = allDeclaredDeps(ws.manifest);
    const wsRelDir = path.relative(root, ws.dir);

    // Effective host values for platform exclusion checks (injectable for tests).
    const hostPlatform = host?.platform ?? process.platform;
    const hostArch = host?.arch ?? process.arch;

    // Process required deps — unresolvable ones → incomplete
    for (const [depName, specifier] of Object.entries(required)) {
      // Local (sibling) workspace reference
      if (wsNames.has(depName) || isWorkspaceRef(specifier, depName, wsNames)) {
        if (wsNames.has(depName) && !ws.localDeps.includes(depName)) {
          ws.localDeps.push(depName);
        }
        // Still try to resolve the package if it appears in the lockfile
        // (some tools hoist workspace packages); otherwise skip.
        const resolved = resolveByManager(
          manager,
          depName,
          specifier,
          wsRelDir,
          graph,
          importers
        );
        if (resolved) {
          ws.deps.set(depName, resolved);
        }
        continue;
      }

      const resolved = resolveByManager(
        manager,
        depName,
        specifier,
        wsRelDir,
        graph,
        importers
      );
      if (resolved) {
        ws.deps.set(depName, resolved);
      } else {
        // Emit incomplete whenever a required dep cannot be resolved, regardless
        // of whether the graph is empty or non-empty. Empty graph means the
        // manager is unknown or the lockfile is absent — each dep is unresolvable.
        incomplete.push({
          scope: `${ws.name}:${depName}`,
          reason: `Could not resolve "${depName}@${specifier}" in lockfile.`,
          kind: "dep-unresolved",
        });
      }
    }

    // Process optional deps — resolution failure is silenced only when the dep
    // is platform-excluded on the current host. A host-runnable optional dep that
    // is absent (not in the lockfile / node_modules) still emits dep-unresolved.
    for (const [depName, specifier] of Object.entries(optional)) {
      if (wsNames.has(depName) || isWorkspaceRef(specifier, depName, wsNames)) {
        if (wsNames.has(depName) && !ws.localDeps.includes(depName)) {
          ws.localDeps.push(depName);
        }
        const resolved = resolveByManager(
          manager,
          depName,
          specifier,
          wsRelDir,
          graph,
          importers
        );
        if (resolved) {
          ws.deps.set(depName, resolved);
        }
        continue;
      }

      const resolved = resolveByManager(
        manager,
        depName,
        specifier,
        wsRelDir,
        graph,
        importers
      );
      if (resolved) {
        ws.deps.set(depName, resolved);
      } else {
        // Determine whether this optional dep is excluded on the current host.
        // For npm: look up platform constraints from the lockfile entry.
        // For pnpm: platform-excluded packages are already skipped in the parser
        //           (they don't appear in the graph), so missing-from-graph means
        //           either platform-excluded (handled by pnpm parser) or truly absent.
        //           We only need to emit dep-unresolved for npm here.
        if (manager === "npm") {
          const localKey = `${wsRelDir ? wsRelDir + "/" : ""}node_modules/${depName}`;
          const hoistedKey = `node_modules/${depName}`;
          const constraints =
            optionalPlatformConstraints.get(localKey) ??
            optionalPlatformConstraints.get(hoistedKey);
          const platformExcluded =
            constraints !== undefined &&
            isPlatformExcluded(constraints.os, constraints.cpu, hostPlatform, hostArch);
          if (!platformExcluded) {
            incomplete.push({
              scope: `${ws.name}:${depName}`,
              reason: `Could not resolve optional "${depName}@${specifier}" in lockfile.`,
              kind: "dep-unresolved",
            });
          }
        }
        // For pnpm/yarn: platform-excluded optionals are already suppressed at the
        // lockfile-parse stage; remaining unresolved optionals surface dep-unresolved
        // only if they appeared in the lockfile but the store path was fabricated.
        // Those are already in incomplete[] from the parser. Unresolved optionals
        // that never appeared in the lockfile at all are silently ignored (the
        // package manager itself decided not to install them).
      }
    }

    // Sort localDeps deterministically
    ws.localDeps.sort();
  }

  // Workspaces already sorted by discoverWorkspaces; sort incomplete by scope too.
  incomplete.sort((a, b) => a.scope.localeCompare(b.scope));

  return {
    root,
    manager,
    workspaces,
    incomplete,
  };
}

function resolveByManager(
  manager: ProjectModel["manager"],
  depName: string,
  specifier: string,
  wsRelDir: string,
  graph: LockfileGraph,
  importers: PnpmParseResult["importers"]
): ResolvedPackage | undefined {
  switch (manager) {
    case "npm":
      return resolveNpmDep(depName, wsRelDir, graph);
    case "pnpm":
      return resolvePnpmDep(depName, wsRelDir, graph, importers);
    case "yarn":
      return resolveYarnDep(depName, specifier, graph);
    default:
      return undefined;
  }
}
