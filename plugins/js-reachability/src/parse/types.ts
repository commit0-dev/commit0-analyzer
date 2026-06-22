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
