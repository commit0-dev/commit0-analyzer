/**
 * Core types for the monorepo project model.
 * All paths are absolute. Maps are keyed by package name.
 */

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  workspaces?: string[] | { packages: string[] };
  [key: string]: unknown;
}

/** A single resolved installed package — exact version + real on-disk dir. */
export interface ResolvedPackage {
  name: string;
  version: string;
  /** Absolute realpath of the installed package directory. */
  dir: string;
}

/** One workspace (or the whole repo for single-package projects). */
export interface Workspace {
  name: string;
  /** Absolute path to the workspace root (where package.json lives). */
  dir: string;
  manifest: PackageJson;
  /** Declared dependency name → resolved installed package. */
  deps: Map<string, ResolvedPackage>;
  /** Names of sibling workspaces this workspace depends on. */
  localDeps: string[];
}

/**
 * Category of incomplete signal. Error-level kinds (lockfile-corrupt) must
 * always mark the scan incomplete regardless of declared dep count. Advisory
 * kinds (dep-unresolved, lockfile-missing) are suppressible when no deps are
 * declared, because there is nothing to resolve.
 */
export type IncompleteKind =
  | "lockfile-corrupt"    // lockfile present but unparseable — always an error
  | "lockfile-missing"    // no lockfile found for a manager that uses one
  | "dep-unresolved"      // declared runtime dep not found in lockfile graph
  | "manager-unknown"     // could not detect package manager
  | "workspace-glob-empty" // workspace glob matched no packages
  | "other";              // catch-all for unexpected incomplete causes

/** Diagnostic entry — signals that a scope could not be fully resolved. */
export interface IncompleteEntry {
  scope: string;
  reason: string;
  /** Category used by the CLI to decide whether the signal suppresses a clean exit. */
  kind: IncompleteKind;
}

/** Resolved project model: manager, workspaces, and unresolved scopes. */
export interface ProjectModel {
  root: string;
  manager: "npm" | "yarn" | "pnpm" | "unknown";
  workspaces: Workspace[];
  incomplete: IncompleteEntry[];
}

/**
 * Raw lockfile graph: a flat map of lockfile-path-key → ResolvedPackage.
 * The key format varies per parser:
 *   npm  : the packages-map key, e.g. "node_modules/foo" or "packages/a/node_modules/foo"
 *   pnpm : "/name@version"
 *   yarn : "name@range"
 */
export type LockfileGraph = Map<string, ResolvedPackage>;
