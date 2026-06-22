import fs from "node:fs/promises";
import path from "node:path";
import type { IncompleteEntry, LockfileGraph, ResolvedPackage } from "../project/model.js";

export interface YarnParseResult {
  graph: LockfileGraph;
  incomplete: IncompleteEntry[];
  /** True when the lockfile exists but could not be parsed. */
  corrupt: boolean;
}

/**
 * Parse yarn.lock (v1 classic format).
 *
 * v1 grammar (simplified):
 *   name@range, name@range2:     ← one or more specifiers on the header line
 *     version "x.y.z"
 *     resolved "url"
 *     ...
 *
 * Berry (v2+) uses a YAML-based format with a "__metadata" block.
 * We detect berry by the presence of `__metadata:` and parse versions from it,
 * but surface an incomplete entry because PnP path resolution is out of scope
 * (H1 fix).
 *
 * A corrupt lockfile (exists but unrecognizable structure — e.g. no headers found
 * and no __metadata) returns corrupt=true (H2 fix).
 *
 * Returns a YarnParseResult. On missing file returns empty/clean. Never throws.
 */
export async function parseYarnLockfile(root: string): Promise<YarnParseResult> {
  const empty: YarnParseResult = {
    graph: new Map(),
    incomplete: [],
    corrupt: false,
  };

  let raw: string;
  try {
    raw = await fs.readFile(path.join(root, "yarn.lock"), "utf8");
  } catch {
    return empty;
  }

  // Detect berry (yarn v2+): has a __metadata block
  const isBerry = raw.includes("__metadata:");

  if (isBerry) {
    return parseBerryLockfile(root, raw);
  }

  return parseV1Lockfile(root, raw);
}

/** Parse yarn v1 classic lockfile. */
function parseV1Lockfile(root: string, raw: string): YarnParseResult {
  const graph: LockfileGraph = new Map();
  const lines = raw.split("\n");
  let i = 0;
  let foundAnyBlock = false;

  while (i < lines.length) {
    const line = lines[i];

    // Skip comments and blank lines
    if (line.startsWith("#") || line.trim() === "") {
      i++;
      continue;
    }

    // Header line: one or more specifiers ending with ":"
    // Examples:
    //   lodash@^4.17.21:
    //   "lodash@^4.17.21", "lodash@^4.16.0":
    if (!line.startsWith(" ") && !line.startsWith("\t") && line.endsWith(":")) {
      const headerRaw = line.slice(0, -1); // strip trailing colon
      const specifiers = splitSpecifiers(headerRaw);

      // Read the block below until next blank line or unindented line
      i++;
      let version: string | null = null;

      while (i < lines.length) {
        const inner = lines[i];
        if (inner === "" || (!inner.startsWith(" ") && !inner.startsWith("\t"))) {
          break;
        }
        const trimmed = inner.trim();
        if (trimmed.startsWith("version ")) {
          version = trimmed.slice(8).replace(/"/g, "").trim();
        }
        i++;
      }

      if (version) {
        foundAnyBlock = true;
        for (const spec of specifiers) {
          const pkgName = extractNameFromSpecifier(spec);
          if (!pkgName) continue;
          const dir = path.join(root, "node_modules", pkgName);
          const pkg: ResolvedPackage = { name: pkgName, version, dir };
          graph.set(spec, pkg);
        }
      }

      continue;
    }

    i++;
  }

  // H2: if the file existed but we found no valid blocks, it is corrupt.
  // A file with only comments/blanks is considered corrupt since a valid
  // yarn.lock always has at least the header comment + one block.
  const hasContent = raw
    .split("\n")
    .some((l) => l.trim() !== "" && !l.startsWith("#"));

  if (hasContent && !foundAnyBlock) {
    return { graph: new Map(), incomplete: [], corrupt: true };
  }

  return { graph, incomplete: [], corrupt: false };
}

/**
 * Parse yarn berry (v2+) lockfile.
 * Berry uses YAML with package blocks keyed by specifier strings.
 * We extract version from each block; PnP path resolution is out of scope.
 * Surfaces an incomplete entry to signal this limitation (H1 fix).
 */
function parseBerryLockfile(root: string, raw: string): YarnParseResult {
  const graph: LockfileGraph = new Map();
  const lines = raw.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Skip comments, blank lines, and the __metadata block
    if (
      line.startsWith("#") ||
      line.trim() === "" ||
      line.startsWith("__metadata:")
    ) {
      i++;
      continue;
    }

    // Berry block header: quoted specifier(s) followed by ":"
    // Example: '"lodash@npm:^4.17.21":'
    if (!line.startsWith(" ") && !line.startsWith("\t") && line.endsWith(":")) {
      const headerRaw = line.slice(0, -1).trim();
      const specifiers = splitBerrySpecifiers(headerRaw);

      i++;
      let version: string | null = null;

      while (i < lines.length) {
        const inner = lines[i];
        if (inner === "" || (!inner.startsWith(" ") && !inner.startsWith("\t"))) {
          break;
        }
        const trimmed = inner.trim();
        if (trimmed.startsWith("version:")) {
          version = trimmed.slice(8).replace(/"/g, "").trim();
        }
        i++;
      }

      if (version) {
        for (const spec of specifiers) {
          const pkgName = extractNameFromBerrySpecifier(spec);
          if (!pkgName) continue;
          // Berry PnP path resolution is out of scope; use node_modules as best-effort
          const dir = path.join(root, "node_modules", pkgName);
          const pkg: ResolvedPackage = { name: pkgName, version, dir };
          graph.set(spec, pkg);
        }
      }

      continue;
    }

    i++;
  }

  // H1: always surface an incomplete entry for berry PnP
  const incomplete: IncompleteEntry[] = [
    {
      scope: root,
      reason:
        "Yarn berry (v2+) detected: PnP path resolution is out of scope; " +
        "package versions are resolved from the lockfile but on-disk dirs " +
        "may not reflect the actual PnP installation.",
    },
  ];

  return { graph, incomplete, corrupt: false };
}

/**
 * Split a yarn v1 header into individual specifiers.
 * Input examples:
 *   'lodash@^4.17.21'
 *   '"lodash@^4.17.21", "lodash@^4.16.0"'
 */
function splitSpecifiers(header: string): string[] {
  return header
    .split(",")
    .map((s) => s.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

/**
 * Split a berry header into individual specifiers.
 * Input: '"lodash@npm:^4.17.21, lodash@npm:^4.16.0"'
 */
function splitBerrySpecifiers(header: string): string[] {
  return header
    .replace(/^"|"$/g, "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Extract package name from a yarn v1 specifier like "lodash@^4.17.21"
 * or "@scope/pkg@^1.0.0".
 */
function extractNameFromSpecifier(specifier: string): string | null {
  // Find the "@" that separates name from range (not the scope prefix)
  const start = specifier.startsWith("@") ? 1 : 0;
  const atIdx = specifier.indexOf("@", start);
  if (atIdx < 0) return specifier || null;
  return specifier.slice(0, atIdx) || null;
}

/**
 * Extract package name from a berry specifier like "lodash@npm:^4.17.21".
 */
function extractNameFromBerrySpecifier(specifier: string): string | null {
  const start = specifier.startsWith("@") ? 1 : 0;
  const atIdx = specifier.indexOf("@", start);
  if (atIdx < 0) return specifier || null;
  return specifier.slice(0, atIdx) || null;
}
