/**
 * oxc-parser backend for the parser seam.
 *
 * Wraps oxc-parser's parseSync API and normalises its output into the
 * parser-agnostic ParsedModule shape. The rest of the codebase only ever
 * imports from parse/index.ts — never from this file directly.
 *
 * Design notes:
 *  - Never throws. Parse errors → ParsedModuleUnknown.
 *  - sourceType is inferred from the file extension, then confirmed by
 *    oxc's hasModuleSyntax flag.
 *  - Dynamic import() with a non-literal source → specifier=null, isDynamic=true.
 *  - require(nonLiteral) → specifier=null, isDynamic=true.
 *  - Re-exports (export { x } from "...") are recorded in both imports and
 *    exports for complete graph coverage.
 *  - Column numbers are converted from 0-based byte offsets (oxc) to 1-based.
 */

import fs from "node:fs";
import path from "node:path";
import { parseSync } from "oxc-parser";
import type {
  ParsedModule,
  ImportRecord,
  ExportRecord,
} from "./types.js";

// ── Source type detection ────────────────────────────────────────────────────

/** Source type as accepted by oxc-parser's sourceType option. */
type OxcSourceType = "module" | "script" | "unambiguous";

/** Whether a file is inherently CJS by extension (affects sourceType inference). */
const CJS_EXTENSIONS = new Set([".cjs", ".cts"]);
const ESM_EXTENSIONS = new Set([".mjs", ".mts"]);

function inferSourceType(filePath: string): OxcSourceType {
  const ext = path.extname(filePath).toLowerCase();
  // CJS extensions: parse as script (no module syntax)
  if (CJS_EXTENSIONS.has(ext)) return "script";
  if (ESM_EXTENSIONS.has(ext)) return "module";
  // .js/.jsx/.ts/.tsx — let oxc decide via "unambiguous" (checks for
  // import/export syntax); hasModuleSyntax confirms the result.
  return "unambiguous";
}

/** True when a file path has a CJS-only extension. */
function isCjsExtension(filePath: string): boolean {
  return CJS_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

// ── AST walker helpers ───────────────────────────────────────────────────────

/** Compute 1-based line from a character offset in source text. */
function offsetToLine(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source[i] === "\n") line++;
  }
  return line;
}

/** Compute 1-based column from a character offset in source text. */
function offsetToColumn(source: string, offset: number): number {
  let col = 1;
  for (let i = offset - 1; i >= 0 && source[i] !== "\n"; i--) {
    col++;
  }
  return col;
}

// oxc AST node types (minimal subset we need — not importing the full type defs)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AstNode = any;

/** Walk an AST node recursively, calling visitor for each node. */
function walk(node: AstNode, visitor: (n: AstNode) => void): void {
  if (!node || typeof node !== "object") return;
  visitor(node);
  for (const key of Object.keys(node)) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) walk(item, visitor);
    } else if (child && typeof child === "object" && child.type) {
      walk(child, visitor);
    }
  }
}

// ── Import extraction ────────────────────────────────────────────────────────

function extractImports(
  program: AstNode,
  source: string,
  moduleInfo: AstNode
): ImportRecord[] {
  const imports: ImportRecord[] = [];

  // 1. ESM static imports — use oxc's module.staticImports for reliability
  if (moduleInfo?.staticImports) {
    for (const si of moduleInfo.staticImports) {
      const specifier: string = si.moduleRequest?.value ?? si.moduleRequest?.source ?? "";
      const offset: number = si.start ?? 0;

      // Extract named bindings from the import entries so downstream symbol
      // resolution can verify whether a specific named export is used.
      const bindings: string[] = [];
      for (const entry of si.entries ?? []) {
        const kind = entry.importName?.kind;
        if (kind === "Name") {
          bindings.push(entry.importName.name as string);
        } else if (kind === "Default") {
          bindings.push("default");
        } else if (kind === "NamespaceObject") {
          bindings.push("*");
        }
      }

      imports.push({
        specifier: specifier || null,
        isDynamic: false,
        importKind: "static-esm",
        line: offsetToLine(source, offset),
        column: offsetToColumn(source, offset),
        bindings: bindings.length > 0 ? bindings : undefined,
      });
    }
  }

  // 2. Dynamic import() — use oxc module.dynamicImports
  if (moduleInfo?.dynamicImports) {
    for (const di of moduleInfo.dynamicImports) {
      // Determine if the source argument is a literal by inspecting the AST node
      // at the recorded offsets. We walk the program to find the ImportExpression.
      const diStart: number = di.start ?? 0;
      let resolvedSpecifier: string | null = null;
      let foundLiteral = false;

      walk(program, (node: AstNode) => {
        if (node.type === "ImportExpression" && node.start === diStart) {
          if (node.source?.type === "Literal" && typeof node.source.value === "string") {
            resolvedSpecifier = node.source.value as string;
            foundLiteral = true;
          }
          // Template literal or identifier → stays null
        }
      });

      imports.push({
        specifier: foundLiteral ? resolvedSpecifier : null,
        isDynamic: true,
        importKind: "dynamic-esm",
        line: offsetToLine(source, diStart),
        column: offsetToColumn(source, diStart),
      });
    }
  }

  // 3. CJS require() calls — walk AST looking for CallExpression(callee=require)
  //
  // We also collect named bindings when the require() is the init of a
  // destructured VariableDeclarator (e.g. `const { a, b } = require("pkg")`).
  // To do this in a single pass, we build a map from CallExpression.start →
  // bindings[] by examining VariableDeclarator parent nodes first.
  const requireBindingsByOffset = new Map<number, string[]>();
  walk(program, (node: AstNode) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "ObjectPattern" &&
      node.init?.type === "CallExpression" &&
      node.init?.callee?.type === "Identifier" &&
      node.init?.callee?.name === "require"
    ) {
      const callStart: number = node.init.start ?? -1;
      const names: string[] = [];
      for (const prop of node.id.properties ?? []) {
        const keyName: string | undefined = prop.key?.name ?? prop.key?.value;
        if (keyName) names.push(keyName);
      }
      if (names.length > 0) {
        requireBindingsByOffset.set(callStart, names);
      }
    }
  });

  walk(program, (node: AstNode) => {
    if (
      node.type === "CallExpression" &&
      node.callee?.type === "Identifier" &&
      node.callee?.name === "require"
    ) {
      const args = node.arguments ?? [];
      const firstArg = args[0];
      const offset: number = node.start ?? 0;
      const bindings = requireBindingsByOffset.get(offset);

      if (firstArg?.type === "Literal" && typeof firstArg.value === "string") {
        imports.push({
          specifier: firstArg.value as string,
          isDynamic: false,
          importKind: "cjs-require",
          line: offsetToLine(source, offset),
          column: offsetToColumn(source, offset),
          bindings,
        });
      } else if (firstArg !== undefined) {
        // Dynamic require(variable/expression)
        imports.push({
          specifier: null,
          isDynamic: true,
          importKind: "cjs-require",
          line: offsetToLine(source, offset),
          column: offsetToColumn(source, offset),
        });
      }
    }
  });

  // 4. Re-export sources — walk AST for export * from and export { x } from
  //    These are not in staticImports (they're recorded as exports by oxc),
  //    so we must explicitly emit an ImportRecord for each re-export source.
  walk(program, (node: AstNode) => {
    if (node.type === "ExportAllDeclaration" && node.source?.value) {
      const offset: number = node.start ?? 0;
      imports.push({
        specifier: node.source.value as string,
        isDynamic: false,
        importKind: "reexport",
        line: offsetToLine(source, offset),
        column: offsetToColumn(source, offset),
      });
    } else if (node.type === "ExportNamedDeclaration" && node.source?.value) {
      const offset: number = node.start ?? 0;
      imports.push({
        specifier: node.source.value as string,
        isDynamic: false,
        importKind: "reexport",
        line: offsetToLine(source, offset),
        column: offsetToColumn(source, offset),
      });
    }
  });

  return imports;
}

// ── Dynamic dispatch detection ────────────────────────────────────────────────

import type { DynamicDispatchSite } from "./types.js";

/**
 * Detect non-import dynamic dispatch constructs in the parsed AST.
 *
 * Constructs detected (per spec M1):
 *   - eval(...)            — direct eval call
 *   - new Function(...)    — Function constructor (arbitrary code execution)
 *   - obj[expr]()          — computed member call (unknown method)
 *   - aliased require      — require bound to a variable then invoked
 *     (const req = require; req(name))
 *
 * Each match becomes a DynamicDispatchSite that the call-graph builder
 * converts to a "dynamic-dispatch" UNKNOWN marker for any reachable file.
 *
 * Note: apply/call on unknown callee (`fn.apply(...)`) would require tracking
 * whether `fn` is statically knowable — left for a future pass. The four
 * constructs above cover the required M1 cases (eval, Function, computed
 * member, aliased-require).
 */
function extractDynamicDispatch(
  program: AstNode,
  source: string
): DynamicDispatchSite[] {
  const sites: DynamicDispatchSite[] = [];

  // Collect names that are assigned `require` at the module level so we can
  // detect aliased-require calls (const req = require; req(name)).
  const requireAliases = new Set<string>();
  walk(program, (node: AstNode) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.init?.type === "Identifier" &&
      node.init?.name === "require"
    ) {
      requireAliases.add(node.id.name as string);
    }
  });

  walk(program, (node: AstNode) => {
    if (node.type !== "CallExpression") return;

    const offset: number = node.start ?? 0;
    const line = offsetToLine(source, offset);
    const column = offsetToColumn(source, offset);
    const callee = node.callee;

    // eval(...)
    if (callee?.type === "Identifier" && callee.name === "eval") {
      sites.push({ kind: "eval", detail: `eval() at ${line}:${column}`, line, column });
      return;
    }

    // new Function(...) — the CallExpression wrapping a NewExpression(Function)
    if (
      callee?.type === "NewExpression" &&
      callee.callee?.type === "Identifier" &&
      callee.callee?.name === "Function"
    ) {
      sites.push({
        kind: "Function-ctor",
        detail: `new Function() at ${line}:${column}`,
        line,
        column,
      });
      return;
    }

    // Function(...) called directly (without new)
    if (callee?.type === "Identifier" && callee.name === "Function") {
      sites.push({
        kind: "Function-ctor",
        detail: `Function() at ${line}:${column}`,
        line,
        column,
      });
      return;
    }

    // obj[expr]() — computed member call
    if (callee?.type === "MemberExpression" && callee.computed === true) {
      sites.push({
        kind: "computed-call",
        detail: `computed member call at ${line}:${column}`,
        line,
        column,
      });
      return;
    }

    // aliased-require: req(name) where req is known to alias require
    if (
      callee?.type === "Identifier" &&
      requireAliases.has(callee.name as string)
    ) {
      sites.push({
        kind: "aliased-require",
        detail: `aliased require (${callee.name}) at ${line}:${column}`,
        line,
        column,
      });
      return;
    }
  });

  // Sort for determinism
  sites.sort((a, b) => a.line - b.line || a.column - b.column);

  return sites;
}

// ── Export extraction ────────────────────────────────────────────────────────

function extractExports(
  program: AstNode,
  source: string,
  moduleInfo: AstNode
): ExportRecord[] {
  const exports: ExportRecord[] = [];

  if (moduleInfo?.staticExports) {
    for (const se of moduleInfo.staticExports) {
      const offset: number = se.start ?? 0;
      const line = offsetToLine(source, offset);
      const column = offsetToColumn(source, offset);

      for (const entry of se.entries ?? []) {
        const exportName =
          entry.exportName?.value ?? entry.exportName?.kind ?? "*";
        const fromSpecifier: string | null =
          se.moduleRequest?.value ?? null;

        exports.push({
          name: exportName,
          isReexport: fromSpecifier !== null,
          fromSpecifier,
          line,
          column,
        });

        // If this is a re-export, also record the import side
        // (handled separately in extractImports via staticImports for ESM).
      }
    }
  }

  // Walk AST for export declarations not captured by moduleInfo
  walk(program, (node: AstNode) => {
    const offset: number = node.start ?? 0;
    const line = offsetToLine(source, offset);
    const col = offsetToColumn(source, offset);

    if (node.type === "ExportDefaultDeclaration") {
      exports.push({
        name: "default",
        isReexport: false,
        fromSpecifier: null,
        line,
        column: col,
      });
    } else if (node.type === "ExportAllDeclaration") {
      exports.push({
        name: "*",
        isReexport: true,
        fromSpecifier: node.source?.value ?? null,
        line,
        column: col,
      });
    } else if (node.type === "ExportNamedDeclaration" && node.source?.value) {
      // Named re-exports: export { x } from "./m" or export { x as y } from "./m"
      const fromSpecifier = node.source.value as string;
      for (const spec of node.specifiers ?? []) {
        const name = spec.exported?.name ?? spec.exported?.value ?? "";
        if (name) {
          exports.push({
            name,
            isReexport: true,
            fromSpecifier,
            line,
            column: col,
          });
        }
      }
    } else if (node.type === "ExportNamedDeclaration" && !node.source) {
      // Named exports without re-export source
      for (const spec of node.specifiers ?? []) {
        const name = spec.exported?.name ?? spec.exported?.value ?? "";
        if (name) {
          exports.push({
            name,
            isReexport: false,
            fromSpecifier: null,
            line,
            column: col,
          });
        }
      }
      // Inline declaration: export function foo() {} / export const x = 1
      if (node.declaration) {
        const decl = node.declaration;
        if (decl.type === "FunctionDeclaration" && decl.id?.name) {
          exports.push({
            name: decl.id.name,
            isReexport: false,
            fromSpecifier: null,
            line,
            column: col,
          });
        } else if (decl.type === "VariableDeclaration") {
          for (const d of decl.declarations ?? []) {
            const name = d.id?.name;
            if (name) {
              exports.push({
                name,
                isReexport: false,
                fromSpecifier: null,
                line,
                column: col,
              });
            }
          }
        }
      }
    }
  });

  return exports;
}

// ── Public parse function ────────────────────────────────────────────────────

/**
 * Parse a single source file using oxc-parser and return a normalized
 * ParsedModule. Never throws — errors become ParsedModuleUnknown.
 */
export async function parseModuleWithOxc(file: string): Promise<ParsedModule> {
  // Read the source file
  let source: string;
  try {
    source = fs.readFileSync(file, "utf8");
  } catch (err) {
    return {
      kind: "unknown",
      file,
      reason: `Could not read file: ${String(err)}`,
    };
  }

  // Determine source type for oxc
  const oxcSourceType = inferSourceType(file);

  // Parse with oxc
  let result: ReturnType<typeof parseSync>;
  try {
    result = parseSync(file, source, { sourceType: oxcSourceType });
  } catch (err) {
    return {
      kind: "unknown",
      file,
      reason: `Parse error: ${String(err)}`,
    };
  }

  // If oxc returned errors and the program is likely broken, surface as UNKNOWN
  if (result.errors && result.errors.length > 0) {
    // oxc is error-tolerant and returns a partial AST even on errors.
    // For hard syntax errors (where the program body is empty or the error
    // is fatal), treat as UNKNOWN. For recoverable errors, proceed with
    // the partial result.
    const hasFatalError = result.errors.some(
      (e: AstNode) => e.severity === "Error"
    );
    if (hasFatalError && (result.program?.body?.length ?? 0) === 0) {
      const firstError = result.errors[0];
      return {
        kind: "unknown",
        file,
        reason: `Parse error: ${firstError?.message ?? "syntax error"}`,
      };
    }
    // Recoverable: continue but the partial AST may miss some nodes.
    // The missing imports become implicit UNKNOWN at resolution time.
    if (hasFatalError) {
      return {
        kind: "unknown",
        file,
        reason: `Parse error: ${result.errors[0]?.message ?? "syntax error"}`,
      };
    }
  }

  const program = result.program;
  const moduleInfo = result.module;

  const imports = extractImports(program, source, moduleInfo);
  const exports_ = extractExports(program, source, moduleInfo);
  const dynamicDispatchSites = extractDynamicDispatch(program, source);

  // Determine final sourceType
  const isModule = moduleInfo?.hasModuleSyntax === true ||
    oxcSourceType === "module";
  const isCjs = (oxcSourceType === "script" && isCjsExtension(file));

  // Infer CJS for a .js (or .ts) file that parses as "unambiguous" (no ESM
  // module syntax) but contains require() calls and no static import/export.
  // oxc reports sourceType:"unknown" for these; we tighten it to "commonjs"
  // so the resolver picks the correct condition set (["require","default"]).
  const hasRequire = imports.some((i) => i.importKind === "cjs-require");
  const inferredCjs = !isModule && !isCjs && hasRequire;

  const sourceType: "module" | "commonjs" | "unknown" =
    isModule ? "module" : (isCjs || inferredCjs) ? "commonjs" : "unknown";

  // Deduplicate: static ESM entries appear in both staticImports and
  // ExportNamedDeclaration with a source — avoid double-counting re-exports.
  const exportsSeen = new Set<string>();
  const dedupedExports: ExportRecord[] = [];
  for (const exp of exports_) {
    const key = `${exp.name}:${exp.line}:${exp.column}`;
    if (!exportsSeen.has(key)) {
      exportsSeen.add(key);
      dedupedExports.push(exp);
    }
  }

  return {
    kind: "parsed",
    file,
    imports,
    exports: dedupedExports,
    sourceType,
    dynamicDispatchSites,
  };
}
