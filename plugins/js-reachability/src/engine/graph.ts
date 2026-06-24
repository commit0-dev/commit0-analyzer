/**
 * EngineGraph scaffold — the shared type surface that the front-end (P4)
 * populates and the call-graph stage (P5) consumes.
 *
 * Design invariants:
 *  - unknown ≠ safe: every unresolved/dynamic/parse-error path emits an
 *    UnknownMarker; nothing is silently dropped.
 *  - Minimal by YAGNI: P5 will extend this with call-graph edges.
 *  - All path strings are absolute. All collections are kept sorted by the
 *    producer so consumers can assume deterministic iteration order.
 */

// ── UNKNOWN markers ───────────────────────────────────────────────────────────

/** Reason categories for UNKNOWN markers. */
export type UnknownReason =
  | "dynamic-specifier"     // require(var) / import(expr) — non-literal source
  | "unresolved-specifier"  // specifier could not be mapped to a file
  | "parse-error"           // file could not be parsed (syntax error, missing file)
  | "missing-file"          // file resolved but does not exist on disk
  | "unknown-condition"     // exports/imports map: condition not matched + no default
  | "phantom-dep"           // importable but not declared in the manifest
  | "dynamic-dispatch";     // eval/Function/computed-member-call/aliased-require in reachable code

/** A single UNKNOWN event at a source location. */
export interface UnknownMarker {
  /** Reason category — drives policy gate and reporting. */
  reason: UnknownReason;
  /** Human-readable detail (specifier text, error message, etc.). */
  detail: string;
  /** Absolute path of the file containing the import/require. */
  fromFile: string;
  /** 1-based line number in the source file. */
  line: number;
  /** 1-based column number (character offset within the line). */
  column: number;
  /**
   * Package names that this frontier could lead to at runtime.
   * When set, the frontier makes those specific packages UNKNOWN-eligible
   * even when they have no static import site and the frontier is not
   * from a first-party file.
   *
   * Used for:
   *   - dynamic specifiers in reachable dep source files: the dep's declared
   *     dependencies that could be loaded by the dynamic require/import.
   *   - reduced/none fidelity deps: the dep's declared dependencies that we
   *     cannot prove are unreachable because we cannot analyze the dep's code.
   */
  couldReach?: string[];
}

// ── First-party module node ───────────────────────────────────────────────────

/**
 * A single first-party source file as a node in the module graph.
 * Third-party dep entries are handled separately via ResolveResult.
 */
export interface ModuleNode {
  /** Absolute path to the source file. */
  file: string;
  /** Workspace name this module belongs to. */
  workspace: string;
}

// ── EngineGraph scaffold ─────────────────────────────────────────────────────

/**
 * Minimal graph structure produced by the P4 front-end and consumed by P5.
 *
 * P5 will add:
 *  - call-graph edges (first-party → first-party function calls)
 *  - third-party import edges (first-party → dep package)
 *  - reachability sets per entrypoint
 */
export interface EngineGraph {
  /** All first-party modules discovered (sorted by file path). */
  modules: ModuleNode[];

  /** All UNKNOWN events encountered during resolution and parsing. */
  unknowns: UnknownMarker[];

  /**
   * Entrypoints per workspace name.
   * Produced by detect-entrypoints and stored here for P5 BFS roots.
   */
  entrypoints: Map<string, EntrypointInfo[]>;
}

/** An entrypoint as produced by detect-entrypoints. */
export interface EntrypointInfo {
  /** Absolute path to the entrypoint file. */
  file: string;
  /** How the entrypoint was detected. */
  kind: "bin" | "main" | "exports" | "explicit";
}

/** Create a new empty EngineGraph. */
export function createEngineGraph(): EngineGraph {
  return {
    modules: [],
    unknowns: [],
    entrypoints: new Map(),
  };
}
