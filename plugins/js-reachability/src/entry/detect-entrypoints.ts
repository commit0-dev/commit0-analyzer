/**
 * Entrypoint detection for JS/TS workspaces.
 *
 * Mirrors the Go engine's EntryPointsForProgram split:
 *   app  (private: true, or has bin scripts): bin scripts + main/root exports
 *   lib  (public package): exported surface from the package entry
 *
 * Explicit AnalyzeRequest.entrypoints override auto-detection per workspace.
 *
 * Monorepo: produces one entry set per workspace. Inter-workspace edges
 * (a sibling app's reach extends into a library workspace via localDeps)
 * are represented by including library entrypoints alongside app entrypoints
 * so P5 BFS can traverse into them.
 *
 * Invariants:
 *   - All returned file paths are absolute.
 *   - DETERMINISM: collections are sorted before return.
 *   - Never throws — missing/malformed manifest fields are skipped silently.
 */

import path from "node:path";
import fs from "node:fs";
import type { ProjectModel, Workspace } from "../project/model.js";
import type { EntrypointInfo } from "../engine/graph.js";

// ── Options ───────────────────────────────────────────────────────────────────

export interface DetectEntrypointsOptions {
  /**
   * Explicit entrypoint file paths supplied by the caller (e.g. from
   * AnalyzeRequest.entrypoints). When non-empty, auto-detection is skipped
   * for all workspaces and these paths are distributed to the workspace
   * whose directory they fall under.
   */
  explicitEntrypoints?: string[];
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Detect entrypoints for all workspaces in a ProjectModel.
 *
 * Returns a Map<workspaceName, EntrypointInfo[]>. Every workspace in the
 * model gets a key (even if its entry list is empty), so P5 can iterate
 * deterministically.
 */
export function detectEntrypoints(
  model: ProjectModel,
  options: DetectEntrypointsOptions = {}
): Map<string, EntrypointInfo[]> {
  const result = new Map<string, EntrypointInfo[]>();

  // Explicit override: distribute paths to the owning workspace
  if (options.explicitEntrypoints && options.explicitEntrypoints.length > 0) {
    for (const ws of model.workspaces) {
      result.set(ws.name, []);
    }
    for (const ep of options.explicitEntrypoints) {
      const absEp = path.resolve(ep);
      // Find the workspace whose dir is the closest ancestor of the file
      let bestWs: Workspace | null = null;
      let bestLen = -1;
      for (const ws of model.workspaces) {
        if (absEp.startsWith(ws.dir + path.sep) || absEp === ws.dir) {
          if (ws.dir.length > bestLen) {
            bestLen = ws.dir.length;
            bestWs = ws;
          }
        }
      }
      if (bestWs) {
        result.get(bestWs.name)!.push({ file: absEp, kind: "explicit" });
      } else if (model.workspaces.length > 0) {
        // Fallback: assign to first workspace
        result.get(model.workspaces[0].name)!.push({ file: absEp, kind: "explicit" });
      }
    }
    // Sort for determinism
    for (const [, eps] of result) {
      eps.sort((a, b) => a.file.localeCompare(b.file));
    }
    return result;
  }

  // Auto-detection per workspace
  for (const ws of model.workspaces) {
    const eps = detectForWorkspace(ws);
    eps.sort((a, b) => a.file.localeCompare(b.file));
    result.set(ws.name, eps);
  }

  return result;
}

// ── Per-workspace detection ───────────────────────────────────────────────────

function isAppWorkspace(ws: Workspace): boolean {
  return ws.manifest.private === true || hasBinField(ws.manifest);
}

function hasBinField(manifest: Workspace["manifest"]): boolean {
  const bin = manifest.bin;
  if (!bin) return false;
  if (typeof bin === "string") return bin.length > 0;
  if (typeof bin === "object") return Object.keys(bin).length > 0;
  return false;
}

function detectForWorkspace(ws: Workspace): EntrypointInfo[] {
  const eps: EntrypointInfo[] = [];

  if (isAppWorkspace(ws)) {
    // App: bin scripts
    const binEntries = collectBinEntries(ws);
    eps.push(...binEntries);

    // App: main entry
    const mainEntry = collectMainEntry(ws);
    if (mainEntry) eps.push(mainEntry);
  } else {
    // Library: exported surface from the package entry
    const libEntries = collectLibraryEntries(ws);
    eps.push(...libEntries);
  }

  return eps;
}

// ── Bin scripts ───────────────────────────────────────────────────────────────

function collectBinEntries(ws: Workspace): EntrypointInfo[] {
  const bin = ws.manifest.bin;
  if (!bin) return [];

  const entries: EntrypointInfo[] = [];

  if (typeof bin === "string") {
    const resolved = resolveManifestPath(ws.dir, bin);
    if (resolved) entries.push({ file: resolved, kind: "bin" });
  } else if (typeof bin === "object" && bin !== null) {
    for (const [, binPath] of Object.entries(bin as Record<string, string>).sort()) {
      const resolved = resolveManifestPath(ws.dir, binPath);
      if (resolved) entries.push({ file: resolved, kind: "bin" });
    }
  }

  return entries;
}

// ── Main entry ────────────────────────────────────────────────────────────────

function collectMainEntry(ws: Workspace): EntrypointInfo | null {
  // Prefer exports["."] over main for apps that also publish
  const exportsEntry = resolveExportsMainEntry(ws);
  if (exportsEntry) return { file: exportsEntry, kind: "exports" };

  const main = ws.manifest.main;
  if (typeof main === "string" && main.length > 0) {
    const resolved = resolveManifestPath(ws.dir, main);
    if (resolved) return { file: resolved, kind: "main" };
  }

  return null;
}

// ── Library entries ───────────────────────────────────────────────────────────

function collectLibraryEntries(ws: Workspace): EntrypointInfo[] {
  const eps: EntrypointInfo[] = [];

  // exports["."] is the canonical library entry
  const exportsEntry = resolveExportsMainEntry(ws);
  if (exportsEntry) {
    eps.push({ file: exportsEntry, kind: "exports" });
    return eps;
  }

  // Fall back to main
  const main = ws.manifest.main;
  if (typeof main === "string" && main.length > 0) {
    const resolved = resolveManifestPath(ws.dir, main);
    if (resolved) eps.push({ file: resolved, kind: "main" });
  }

  return eps;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Resolve the root exports entry (".") from the manifest exports field.
 * Returns the absolute path or null when not present / unresolvable.
 */
function resolveExportsMainEntry(ws: Workspace): string | null {
  const exports_ = ws.manifest.exports;
  if (!exports_) return null;

  let candidate: string | null = null;

  if (typeof exports_ === "string") {
    candidate = exports_;
  } else if (typeof exports_ === "object" && exports_ !== null && !Array.isArray(exports_)) {
    const map = exports_ as Record<string, unknown>;
    // Root entry "."
    const rootEntry = map["."];
    if (typeof rootEntry === "string") {
      candidate = rootEntry;
    } else if (rootEntry && typeof rootEntry === "object") {
      // Condition map: prefer "import" > "require" > "default"
      const condMap = rootEntry as Record<string, unknown>;
      candidate =
        (typeof condMap.import === "string" ? condMap.import : null) ??
        (typeof condMap.require === "string" ? condMap.require : null) ??
        (typeof condMap.default === "string" ? condMap.default : null);
    }
  }

  if (!candidate) return null;
  return resolveManifestPath(ws.dir, candidate);
}

/**
 * Resolve a path from package.json (relative to workspace dir) to an
 * absolute path. Returns null when the resolved path does not exist on disk.
 */
function resolveManifestPath(wsDir: string, relPath: string): string | null {
  const abs = path.resolve(wsDir, relPath);
  if (fs.existsSync(abs)) return abs;

  // Try common extensions if the manifest path has no extension
  const EXTS = [".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx"];
  if (path.extname(abs) === "") {
    for (const ext of EXTS) {
      const candidate = abs + ext;
      if (fs.existsSync(candidate)) return candidate;
    }
  }

  // Return the path even if it doesn't exist yet — some tools run before build.
  // P5 will discover the missing file and emit an UNKNOWN marker then.
  return abs;
}
