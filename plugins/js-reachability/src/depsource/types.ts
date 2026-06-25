/**
 * Types for the dependency source resolution layer.
 *
 * Fidelity describes how analyzable the resolved entry is:
 *   source  — readable, parseable code; full static analysis is possible.
 *   reduced — minified or bundled output; analysis is lower-fidelity
 *             (symbol names are mangled, structure is collapsed). Callers
 *             should bias results as UNKNOWN rather than NOT_REACHABLE.
 *   none    — no runtime entry could be resolved (types-only, missing dir,
 *             or package.json with no resolvable entry field).
 */
export type Fidelity = "source" | "reduced" | "none";

export interface DepSource {
  /** Package name as declared in the consuming manifest. */
  package: string;
  /** Exact installed version from the package's own package.json. */
  version: string;
  /** Absolute path to the installed package directory. */
  dir: string;
  /**
   * Absolute path to the best analyzable entry file found, or null when no
   * runtime entry can be resolved.
   */
  entryFile: string | null;
  /**
   * Classification of how analyzable entryFile is.
   * When entryFile is null, fidelity is always "none".
   */
  fidelity: Fidelity;
  /** Human-readable explanation of the fidelity classification. */
  reason?: string;
}
