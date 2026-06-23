/**
 * Resolve an installed dependency to its most analyzable entry file and
 * classify how faithfully it can be statically analyzed.
 *
 * Resolution priority (mirrors the Node.js spec order used in the resolver):
 *   1. exports["."] — import > default > require conditions
 *   2. module field (ESM source hint)
 *   3. main field
 *   4. index.{js,cjs,mjs} fallback
 *
 * Fidelity classification is purely file-content based — no parsing needed:
 *   source  — file exists AND is not minified (avg line length ≤ 500 chars)
 *   reduced — file exists BUT looks minified (avg line length > 500 chars,
 *             or a single line > 50 000 chars)
 *   none    — no runtime entry resolved
 *
 * Never throws. All failure modes return fidelity:"none", entryFile:null.
 */

import fs from "node:fs";
import path from "node:path";
import { resolveExportsMap, type ExportsMapValue } from "../resolve/exports-map.js";
import type { DepSource, Fidelity } from "./types.js";

// ── Constants ─────────────────────────────────────────────────────────────────

/** Average line length above which a file is considered minified. */
const MINIFIED_AVG_LINE_LENGTH = 500;

/** A single line exceeding this byte count is treated as a minified bundle. */
const MINIFIED_SINGLE_LINE_MAX = 50_000;

/** Conditions tried when resolving an exports map entry, in priority order. */
const ENTRY_CONDITIONS: string[] = ["import", "default", "require"];

/** Extension candidates for bare index fallback. */
const INDEX_EXTENSIONS = [".js", ".cjs", ".mjs"];

// ── Package.json shape ────────────────────────────────────────────────────────

interface PkgJson {
  main?: string;
  module?: string;
  exports?: ExportsMapValue;
  [k: string]: unknown;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function readPkgJson(dir: string): PkgJson | null {
  try {
    const raw = fs.readFileSync(path.join(dir, "package.json"), "utf8");
    return JSON.parse(raw) as PkgJson;
  } catch {
    return null;
  }
}

/**
 * Resolve a relative path from pkg dir to an existing file.
 * Returns absolute path if the file exists, null otherwise.
 */
function resolveRelative(pkgDir: string, rel: string): string | null {
  const abs = path.resolve(pkgDir, rel);
  try {
    if (fs.statSync(abs).isFile()) return abs;
  } catch {
    // not found or stat error
  }
  return null;
}

/**
 * Try index.<ext> fallbacks in pkgDir.
 */
function resolveIndex(pkgDir: string): string | null {
  for (const ext of INDEX_EXTENSIONS) {
    const candidate = path.join(pkgDir, "index" + ext);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // not found
    }
  }
  return null;
}

/**
 * Classify whether a file's content looks minified.
 * Reads the file; on any I/O error returns "none".
 */
function classifyFile(filePath: string): Fidelity {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return "none";
  }

  if (content.length === 0) return "source";

  const lines = content.split("\n");
  // Strip trailing empty line created by a final newline
  const nonEmpty = lines.filter((l) => l.length > 0);

  if (nonEmpty.length === 0) return "source";

  // Single line over the hard limit → definitely minified
  if (nonEmpty.length === 1 && nonEmpty[0].length > MINIFIED_SINGLE_LINE_MAX) {
    return "reduced";
  }

  const totalChars = nonEmpty.reduce((sum, l) => sum + l.length, 0);
  const avgLen = totalChars / nonEmpty.length;

  return avgLen > MINIFIED_AVG_LINE_LENGTH ? "reduced" : "source";
}

// ── Entry resolution ──────────────────────────────────────────────────────────

/**
 * Resolve the runtime entry file for a package directory.
 * Returns absolute path or null if nothing resolvable exists.
 */
function resolveEntry(pkgDir: string, pkg: PkgJson): string | null {
  // 1. exports["."] with conditions
  if (pkg.exports !== undefined && pkg.exports !== null) {
    const rel = resolveExportsMap(pkg.exports, ".", ENTRY_CONDITIONS);
    if (rel !== null) {
      return resolveRelative(pkgDir, rel);
    }
    // exports map present but no matching condition → no fallback (spec behaviour)
    return null;
  }

  // 2. module field (ESM hint, no exports map)
  if (typeof pkg.module === "string") {
    const resolved = resolveRelative(pkgDir, pkg.module);
    if (resolved !== null) return resolved;
  }

  // 3. main field
  if (typeof pkg.main === "string") {
    const resolved = resolveRelative(pkgDir, pkg.main);
    if (resolved !== null) return resolved;
  }

  // 4. index.js / index.cjs / index.mjs fallback
  return resolveIndex(pkgDir);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Resolve an installed package to its most analyzable entry and classify
 * fidelity. Never throws.
 */
export function resolveDepSource(pkg: {
  name: string;
  version: string;
  dir: string;
}): DepSource {
  const base: Omit<DepSource, "entryFile" | "fidelity" | "reason"> = {
    package: pkg.name,
    version: pkg.version,
    dir: pkg.dir,
  };

  const pkgJson = readPkgJson(pkg.dir);
  if (pkgJson === null) {
    return {
      ...base,
      entryFile: null,
      fidelity: "none",
      reason: "package.json missing or unreadable",
    };
  }

  const entryFile = resolveEntry(pkg.dir, pkgJson);
  if (entryFile === null) {
    return {
      ...base,
      entryFile: null,
      fidelity: "none",
      reason: "no resolvable runtime entry (types-only or missing entry field)",
    };
  }

  const fidelity = classifyFile(entryFile);
  const reason =
    fidelity === "reduced"
      ? "entry file appears minified or bundled (high avg line length)"
      : undefined;

  return { ...base, entryFile, fidelity, reason };
}
