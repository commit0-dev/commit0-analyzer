/**
 * Extract the exported symbols whose implementations were modified by a
 * security-fix patch.
 *
 * Algorithm per file:
 *   1. Parse newContent with oxc-parser to get the AST.
 *   2. Build a flat list of "symbol regions": every top-level exported
 *      declaration (function / class / const-arrow / default) with its
 *      [startLine, endLine] span, plus every method of exported classes
 *      (exportName = "Class.method", kind = "method").
 *      For CJS files, scan AssignmentExpression nodes for exports.foo and
 *      module.exports.foo patterns.
 *   3. For each changed line, find the innermost symbol region that contains
 *      it.  Prefer method-level over class-level.
 *   4. If no exported symbol encloses the changed line, emit a "module-level"
 *      marker (unknown ≠ safe — never silently drop a changed region).
 *   5. Deduplicate, sort by file then exportName, return.
 */

import path from "node:path";
import { parseSync } from "oxc-parser";
import type { ChangedFile, VulnerableSymbol } from "./types.js";

// ── oxc AST node (untyped — we only use what we need) ─────────────────────────
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AstNode = any;

// ── source-type inference ─────────────────────────────────────────────────────

const CJS_EXTS = new Set([".cjs", ".cts"]);
const ESM_EXTS = new Set([".mjs", ".mts"]);

function oxcSourceType(filePath: string): "module" | "script" | "unambiguous" {
  const ext = path.extname(filePath).toLowerCase();
  if (CJS_EXTS.has(ext)) return "script";
  if (ESM_EXTS.has(ext)) return "module";
  return "unambiguous";
}

// ── offset → line conversion ──────────────────────────────────────────────────

/** Build a lookup array: lineOffsets[i] = character offset of line i+1 start. */
function buildLineOffsets(source: string): number[] {
  const offsets = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\n") offsets.push(i + 1);
  }
  return offsets;
}

/** Convert a character offset to a 1-based line number using the offset table. */
function offsetToLine(offset: number, lineOffsets: number[]): number {
  let lo = 0;
  let hi = lineOffsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineOffsets[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1; // 1-based
}

// ── symbol region ─────────────────────────────────────────────────────────────

interface SymbolRegion {
  exportName: string;
  kind: VulnerableSymbol["kind"];
  startLine: number;
  endLine: number;
  /** Nesting depth — higher depth wins when multiple regions overlap. */
  depth: number;
}

// ── AST extraction helpers ────────────────────────────────────────────────────

/**
 * Build a flat list of SymbolRegions from the top-level body of a parsed ESM
 * program.  Handles ExportNamedDeclaration, ExportDefaultDeclaration, and
 * class methods.
 */
function collectEsmRegions(program: AstNode, lineOffsets: number[]): SymbolRegion[] {
  const regions: SymbolRegion[] = [];

  for (const node of program.body ?? []) {
    // ── export default ──────────────────────────────────────────────────────
    if (node.type === "ExportDefaultDeclaration") {
      const startLine = offsetToLine(node.start, lineOffsets);
      const endLine = offsetToLine(node.end, lineOffsets);
      const decl = node.declaration;
      let kind: VulnerableSymbol["kind"] = "function";
      if (decl?.type === "ClassDeclaration" || decl?.type === "ClassExpression") {
        kind = "class";
      }
      regions.push({ exportName: "default", kind, startLine, endLine, depth: 1 });
      continue;
    }

    // ── export { ... } / export function / export class / export const ──────
    if (node.type === "ExportNamedDeclaration") {
      const decl = node.declaration;
      if (!decl) continue; // export { x } re-export style — no body to attribute

      const startLine = offsetToLine(node.start, lineOffsets);
      const endLine = offsetToLine(node.end, lineOffsets);

      if (decl.type === "FunctionDeclaration") {
        const name = decl.id?.name ?? "default";
        regions.push({ exportName: name, kind: "function", startLine, endLine, depth: 1 });

      } else if (decl.type === "ClassDeclaration") {
        const className = decl.id?.name ?? "default";
        regions.push({ exportName: className, kind: "class", startLine, endLine, depth: 1 });

        // Add method-level regions (depth 2 so they win over the class region).
        // Only MethodDefinition nodes get their own sub-region; PropertyDefinition
        // (class fields) stay under the class-level region.
        for (const member of decl.body?.body ?? []) {
          if (member.type !== "MethodDefinition") continue;
          const methodName: string =
            member.key?.name ?? member.key?.value ?? "";
          if (!methodName) continue;
          const mStart = offsetToLine(member.start, lineOffsets);
          const mEnd = offsetToLine(member.end, lineOffsets);
          regions.push({
            exportName: `${className}.${methodName}`,
            kind: "method",
            startLine: mStart,
            endLine: mEnd,
            depth: 2,
          });
        }

      } else if (decl.type === "VariableDeclaration") {
        // Use each declarator's own span so a change on the second declarator
        // (e.g. `export const f = ..., g = ...`) correctly attributes to g, not f.
        for (const d of decl.declarations ?? []) {
          const name: string | undefined = d.id?.name;
          if (!name) continue;
          const init = d.init;
          const isArrowOrFn =
            init?.type === "ArrowFunctionExpression" ||
            init?.type === "FunctionExpression";
          const dStartLine = offsetToLine(d.start, lineOffsets);
          const dEndLine = offsetToLine(d.end, lineOffsets);
          regions.push({
            exportName: name,
            kind: isArrowOrFn ? "function" : "variable",
            startLine: dStartLine,
            endLine: dEndLine,
            depth: 1,
          });
        }

      } else if (decl.type === "TSEnumDeclaration") {
        const name: string = decl.id?.name ?? "default";
        regions.push({ exportName: name, kind: "variable", startLine, endLine, depth: 1 });

      } else if (decl.type === "TSModuleDeclaration") {
        // Covers `export namespace Foo { ... }` and `export module Foo { ... }`
        const name: string = decl.id?.name ?? decl.id?.value ?? "default";
        regions.push({ exportName: name, kind: "class", startLine, endLine, depth: 1 });
      }
      // Known coarsening cases (currently → module-level, which is safe):
      // `export { a, b }` list-form re-exports and `module.exports = { foo, bar }` object literals.
    }
  }

  return regions;
}

/**
 * Build SymbolRegions from CJS-style exports in a script-mode program.
 *
 * Patterns recognised (best-effort):
 *   exports.foo = ...
 *   module.exports.foo = ...
 *   Object.defineProperty(exports, "foo", { ... })
 */
function collectCjsRegions(program: AstNode, lineOffsets: number[]): SymbolRegion[] {
  const regions: SymbolRegion[] = [];

  for (const stmt of program.body ?? []) {
    if (stmt.type !== "ExpressionStatement") continue;
    const expr = stmt.expression;

    // exports.foo = ... or module.exports.foo = ...
    if (expr?.type === "AssignmentExpression") {
      const left = expr.left;
      if (left?.type !== "MemberExpression") continue;

      let exportName: string | null = null;
      const propName: string = left.property?.name ?? left.property?.value ?? "";

      // exports.foo = ...
      if (left.object?.type === "Identifier" && left.object.name === "exports" && propName) {
        exportName = propName;
      }
      // module.exports.foo = ...
      else if (
        left.object?.type === "MemberExpression" &&
        left.object.object?.name === "module" &&
        left.object.property?.name === "exports" &&
        propName
      ) {
        exportName = propName;
      }

      if (!exportName) continue;

      const startLine = offsetToLine(stmt.start, lineOffsets);
      const endLine = offsetToLine(stmt.end, lineOffsets);

      const rhs = expr.right;
      const kind: VulnerableSymbol["kind"] =
        rhs?.type === "FunctionExpression" ||
        rhs?.type === "ArrowFunctionExpression"
          ? "function"
          : "variable";

      regions.push({ exportName, kind, startLine, endLine, depth: 1 });
      continue;
    }

    // Object.defineProperty(exports, "foo", { ... })
    if (
      expr?.type === "CallExpression" &&
      expr.callee?.type === "MemberExpression" &&
      expr.callee.object?.name === "Object" &&
      expr.callee.property?.name === "defineProperty"
    ) {
      const args: AstNode[] = expr.arguments ?? [];
      const targetArg = args[0];
      const nameArg = args[1];

      const targetsExports =
        (targetArg?.type === "Identifier" && targetArg.name === "exports") ||
        (targetArg?.type === "MemberExpression" &&
          targetArg.object?.name === "module" &&
          targetArg.property?.name === "exports");

      if (!targetsExports) continue;

      const exportName: string | undefined =
        nameArg?.type === "Literal" ? String(nameArg.value) : undefined;
      if (!exportName) continue;

      const startLine = offsetToLine(stmt.start, lineOffsets);
      const endLine = offsetToLine(stmt.end, lineOffsets);
      regions.push({ exportName, kind: "variable", startLine, endLine, depth: 1 });
    }
  }

  return regions;
}

// ── per-file extraction ───────────────────────────────────────────────────────

/**
 * For a single ChangedFile, parse its content and return the VulnerableSymbol
 * entries whose line ranges overlap the changedLines set.
 */
function extractFromFile(changed: ChangedFile): VulnerableSymbol[] {
  if (!changed.changedLines.length || !changed.newContent) return [];

  const { path: filePath, newContent, changedLines } = changed;
  const changedSet = new Set(changedLines);

  // Parse
  const sourceType = oxcSourceType(filePath);
  let result: ReturnType<typeof parseSync>;
  try {
    result = parseSync(filePath, newContent, { sourceType });
  } catch {
    return [];
  }

  // Bail on hard parse failure
  if (!result.program || (result.errors?.some((e: AstNode) => e.severity === "Error") &&
      (result.program.body?.length ?? 0) === 0)) {
    return [];
  }

  const program = result.program;
  const lineOffsets = buildLineOffsets(newContent);

  // Determine whether we're in CJS mode
  const isCjs =
    sourceType === "script" ||
    (sourceType === "unambiguous" && result.module?.hasModuleSyntax !== true);

  const regions = isCjs
    ? collectCjsRegions(program, lineOffsets)
    : collectEsmRegions(program, lineOffsets);

  // For each changed line, find the best (deepest) enclosing region
  const emitted = new Map<string, VulnerableSymbol>(); // key = exportName
  let needsModuleLevel = false;

  for (const line of changedSet) {
    let best: SymbolRegion | null = null;
    for (const region of regions) {
      if (line >= region.startLine && line <= region.endLine) {
        if (best === null || region.depth > best.depth) {
          best = region;
        }
      }
    }

    if (best) {
      if (!emitted.has(best.exportName)) {
        emitted.set(best.exportName, {
          file: filePath,
          exportName: best.exportName,
          kind: best.kind,
        });
      }
    } else {
      // No exported symbol encloses this line → module-level marker
      needsModuleLevel = true;
    }
  }

  const symbols: VulnerableSymbol[] = Array.from(emitted.values());
  if (needsModuleLevel && !emitted.has("module-level")) {
    symbols.push({ file: filePath, exportName: "module-level", kind: "variable" });
  }

  return symbols;
}

// ── public API ────────────────────────────────────────────────────────────────

/**
 * Given a list of changed files (produced by parseUnifiedDiff after content is
 * hydrated), return the exported symbols whose implementations were modified.
 *
 * Results are sorted by file path then exportName for determinism.
 */
export function extractVulnerableSymbols(changed: ChangedFile[]): VulnerableSymbol[] {
  const all: VulnerableSymbol[] = [];

  for (const f of changed) {
    try {
      const symbols = extractFromFile(f);
      all.push(...symbols);
    } catch {
      // Never throw out of here — one bad file must not abort the whole batch
    }
  }

  // Stable sort: file path first, then exportName
  all.sort((a, b) => {
    const fc = a.file.localeCompare(b.file);
    if (fc !== 0) return fc;
    return a.exportName.localeCompare(b.exportName);
  });

  return all;
}
