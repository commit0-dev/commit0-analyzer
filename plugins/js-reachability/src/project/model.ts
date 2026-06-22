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

/** Diagnostic entry — signals that a scope could not be fully resolved. */
export interface IncompleteEntry {
  scope: string;
  reason: string;
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
