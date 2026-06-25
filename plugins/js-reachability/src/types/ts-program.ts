/**
 * Per-workspace ts-morph Project cache and call-target resolution helper.
 *
 * Design:
 *  - One ts-morph Project per workspace, created lazily on first use.
 *  - Type info is ADVISORY: when it disambiguates a call, use it (precision);
 *    when absent (JS files, no tsconfig), fall back silently (soundness).
 *  - Never throws — all errors degrade to null (caller over-approximates).
 *  - Project creation and source-file loading are deferred until resolveCallTarget
 *    is actually called, so startup cost is bounded by actual usage.
 *
 * P5 will call resolveCallTarget() for each call expression it encounters
 * while traversing first-party source files.
 */

import path from "node:path";
import fs from "node:fs";
import { Project, type Node, SyntaxKind } from "ts-morph";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Resolved call target returned by resolveCallTarget.
 * Identifies the declaration site of the callee.
 */
export interface CallTarget {
  /** Absolute path of the file containing the declaration. */
  file: string;
  /** 1-based line number of the declaration. */
  line: number;
  /** Unqualified symbol name. */
  name: string;
  /**
   * Whether type resolution was precise (true) or a best-effort
   * over-approximation (false). P5 uses this to choose confidence tier.
   */
  precise: boolean;
}

/**
 * A lightweight call-expression descriptor passed by P5.
 * The actual AST node type is kept abstract so P5 can pass either an oxc
 * node (serialised position) or a ts-morph Node — the resolver handles both.
 */
export interface CallExprDescriptor {
  /** Absolute path of the file containing the call. */
  file: string;
  /** 1-based line of the call expression in the source. */
  line: number;
  /**
   * Optional: the ts-morph Node for the call expression. When present,
   * type resolution is precise. When absent, returns null (no over-approx
   * at this layer — P5 uses name-based heuristics instead).
   */
  tsMorphNode?: Node;
}

// ── Project cache ─────────────────────────────────────────────────────────────

/** Internal cache entry for a single workspace. */
interface WorkspaceEntry {
  project: Project;
  /** True once the project has had source files added. */
  loaded: boolean;
}

const cache = new Map<string, WorkspaceEntry>();

/**
 * Get (or lazily create) the ts-morph Project for a workspace directory.
 * Uses the workspace's tsconfig.json when present; otherwise creates a
 * default-config project that can still type-check TypeScript files.
 */
function getOrCreateProject(workspaceDir: string): Project {
  const existing = cache.get(workspaceDir);
  if (existing) return existing.project;

  const tsconfigPath = path.join(workspaceDir, "tsconfig.json");
  const hasTsconfig = fs.existsSync(tsconfigPath);

  const project = hasTsconfig
    ? new Project({
        tsConfigFilePath: tsconfigPath,
        // Do not add files automatically — add only files we actually traverse
        skipAddingFilesFromTsConfig: true,
        skipFileDependencyResolution: false,
      })
    : new Project({
        compilerOptions: {
          // Permissive defaults for JS-heavy projects
          allowJs: true,
          checkJs: false,
          strict: false,
          noEmit: true,
          resolveJsonModule: true,
        },
      });

  cache.set(workspaceDir, { project, loaded: false });
  return project;
}

/**
 * Add a source file to the workspace Project if not already present.
 * Safe to call multiple times for the same file.
 */
function ensureSourceFile(project: Project, filePath: string): void {
  try {
    if (!project.getSourceFile(filePath)) {
      project.addSourceFileAtPathIfExists(filePath);
    }
  } catch {
    // Non-fatal: type resolution degrades to null
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Resolve the declaration site of a call expression using ts-morph type info.
 *
 * Returns null when:
 *  - The file is JavaScript-only (no type info available)
 *  - The tsconfig is absent or malformed
 *  - The call expression cannot be resolved (overloads, dynamic dispatch)
 *  - Any internal ts-morph error occurs
 *
 * P5 must treat null as "over-approximate" (include all plausible targets).
 *
 * @param workspaceDir  Absolute path to the workspace root.
 * @param descriptor    Call expression location and optional ts-morph node.
 */
export function resolveCallTarget(
  workspaceDir: string,
  descriptor: CallExprDescriptor
): CallTarget | null {
  // No ts-morph node provided — cannot resolve at this layer
  if (!descriptor.tsMorphNode) return null;

  const project = getOrCreateProject(workspaceDir);
  ensureSourceFile(project, descriptor.file);

  try {
    const node = descriptor.tsMorphNode;

    // Navigate to the call expression node if needed
    const callExpr =
      node.getKind() === SyntaxKind.CallExpression
        ? node
        : node.getFirstAncestorByKind(SyntaxKind.CallExpression);

    if (!callExpr) return null;

    // Get the callee expression (the thing being called)
    const exprNode = callExpr.getFirstChildByKind(SyntaxKind.Identifier) ??
      callExpr.getFirstChildByKind(SyntaxKind.PropertyAccessExpression);

    if (!exprNode) return null;

    // Resolve the symbol of the callee
    const symbol = exprNode.getSymbol();
    if (!symbol) return null;

    // Get the declaration
    const declarations = symbol.getDeclarations();
    if (declarations.length === 0) return null;

    // Prefer the first non-ambient declaration
    const decl = declarations.find((d) => !d.getSourceFile().isFromExternalLibrary())
      ?? declarations[0];

    const declFile = decl.getSourceFile().getFilePath();
    const declLine = decl.getStartLineNumber();
    const name = symbol.getName();

    return {
      file: declFile,
      line: declLine,
      name,
      precise: true,
    };
  } catch {
    // Any ts-morph internal error → degrade silently
    return null;
  }
}

/**
 * Pre-load a set of source files into the workspace Project so that
 * subsequent resolveCallTarget calls on those files have type context.
 * Call this once per workspace before beginning P5 traversal.
 *
 * @param workspaceDir  Absolute path to the workspace root.
 * @param files         Absolute paths of first-party source files to pre-load.
 */
export function preloadWorkspaceFiles(
  workspaceDir: string,
  files: readonly string[]
): void {
  const project = getOrCreateProject(workspaceDir);
  for (const f of files) {
    ensureSourceFile(project, f);
  }
}

/**
 * Evict a workspace Project from the cache (e.g. when memory pressure is high
 * or when testing requires isolation between fixture runs).
 */
export function evictWorkspaceProject(workspaceDir: string): void {
  cache.delete(workspaceDir);
}

/** Evict all cached projects. Useful in test teardown. */
export function evictAllProjects(): void {
  cache.clear();
}
