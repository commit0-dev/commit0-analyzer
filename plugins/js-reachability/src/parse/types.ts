/**
 * Parser-agnostic normalized types for a parsed module.
 *
 * P5 (call-graph) must never import oxc types directly — it uses only these
 * normalized shapes. Swapping oxc for another parser requires updating only
 * oxc-backend.ts, not any downstream consumer.
 */

// ── Import record ─────────────────────────────────────────────────────────────

/** A single import or require() call extracted from a source file. */
export interface ImportRecord {
  /**
   * The literal specifier string, e.g. "./foo", "lodash", "@scope/pkg/utils".
   * null when the specifier is not a string literal (dynamic require(var) or
   * import(expr)) — these always become UNKNOWN markers.
   */
  specifier: string | null;

  /** true for import() expressions and dynamic require(variable) calls. */
  isDynamic: boolean;

  /** Import style — affects which condition set is applied during resolution. */
  importKind: "static-esm" | "dynamic-esm" | "cjs-require" | "reexport";

  /** 1-based line number of the import/require in the source file. */
  line: number;

  /** 1-based column number (character offset from start of line). */
  column: number;

  /**
   * Named bindings extracted from this import statement, when statically
   * determinable. Populated for:
   *   - ESM named imports: `import { a, b } from "pkg"` → ["a", "b"]
   *   - CJS destructured requires: `const { a } = require("pkg")` → ["a"]
   *   - Default import: `import def from "pkg"` → ["default"]
   *   - Namespace import: `import * as ns from "pkg"` → ["*"]
   *
   * Undefined (not an empty array) when binding information cannot be
   * determined statically (e.g. `const x = require("pkg")`).
   */
  bindings?: string[];
}

// ── Export record ─────────────────────────────────────────────────────────────

/** A single export extracted from a source file. */
export interface ExportRecord {
  /**
   * Exported name, or "default" for default exports, or "*" for
   * namespace re-exports.
   */
  name: string;

  /** true when this is a re-export (export { x } from "..."). */
  isReexport: boolean;

  /** Source specifier for re-exports, null otherwise. */
  fromSpecifier: string | null;

  line: number;
  column: number;
}

// ── Dynamic dispatch site ─────────────────────────────────────────────────────

/**
 * A non-import dynamic dispatch construct detected in a source file.
 * These cannot be statically resolved to a target and must emit UNKNOWN
 * frontiers so the reachability engine never returns NOT_REACHABLE when such
 * a construct sits on the only candidate path.
 */
export interface DynamicDispatchSite {
  /**
   * What kind of dynamic construct was detected.
   * - "eval"            — direct eval() or indirect eval via a variable
   * - "Function-ctor"   — new Function(...) / Function(...) constructor
   * - "computed-call"   — obj[expr]() computed member call
   * - "aliased-require" — require bound to a variable then called (const r=require; r(x))
   */
  kind: "eval" | "Function-ctor" | "computed-call" | "aliased-require";
  /** Human-readable description for the UNKNOWN marker detail. */
  detail: string;
  /** 1-based line of the dispatch construct. */
  line: number;
  /** 1-based column of the dispatch construct. */
  column: number;
}

// ── ParsedModule ─────────────────────────────────────────────────────────────

/** Successful parse result for a single source file. */
export interface ParsedModuleOk {
  kind: "parsed";
  /** Absolute path of the parsed file. */
  file: string;
  /** All import/require calls found in the file. */
  imports: ImportRecord[];
  /** All exports found in the file. */
  exports: ExportRecord[];
  /**
   * Source type detected or inferred from file extension and content.
   * Drives the default condition set for resolution.
   */
  sourceType: "module" | "commonjs" | "unknown";
  /**
   * Non-import dynamic dispatch constructs (eval, computed calls, aliased
   * require, Function constructor). Each becomes a "dynamic-dispatch"
   * UNKNOWN marker in the call graph when the file is reachable.
   */
  dynamicDispatchSites: DynamicDispatchSite[];
}

/** Failed parse — becomes an UNKNOWN marker; never propagated as an error. */
export interface ParsedModuleUnknown {
  kind: "unknown";
  /** Absolute path of the file that could not be parsed. */
  file: string;
  /** Human-readable reason (parse error message or "file not found"). */
  reason: string;
}

export type ParsedModule = ParsedModuleOk | ParsedModuleUnknown;
