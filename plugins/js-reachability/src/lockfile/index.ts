import type { IncompleteEntry, LockfileGraph } from "../project/model.js";
import { parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile, type PnpmParseResult } from "./pnpm.js";
import { parseYarnLockfile } from "./yarn.js";

export interface LockfileParseResult {
  graph: LockfileGraph;
  incomplete: IncompleteEntry[];
  /**
   * Importer map from pnpm: workspace-relative-dir → (depName → resolved version).
   * Populated only for pnpm; empty map for other managers.
   */
  importers: PnpmParseResult["importers"];
}

/**
 * Dispatch to the correct lockfile parser based on detected manager.
 * Returns an empty graph (not an error) for unknown managers.
 * Corruption is surfaced via incomplete entries — never throws.
 */
export async function parseLockfile(
  root: string,
  manager: "npm" | "yarn" | "pnpm" | "unknown"
): Promise<LockfileParseResult> {
  const incomplete: IncompleteEntry[] = [];
  const emptyImporters: PnpmParseResult["importers"] = new Map();

  switch (manager) {
    case "npm": {
      const result = await parseNpmLockfile(root);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "package-lock.json exists but could not be parsed (corrupt or invalid JSON).",
        });
      }
      return { graph: result.graph, incomplete, importers: emptyImporters };
    }
    case "pnpm": {
      const result = await parsePnpmLockfile(root);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "pnpm-lock.yaml exists but could not be parsed (corrupt or invalid YAML).",
        });
      }
      incomplete.push(...result.incomplete);
      return { graph: result.graph, incomplete, importers: result.importers };
    }
    case "yarn": {
      const result = await parseYarnLockfile(root);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "yarn.lock exists but could not be parsed (corrupt or unrecognized format).",
        });
      }
      incomplete.push(...result.incomplete);
      return { graph: result.graph, incomplete, importers: emptyImporters };
    }
    default:
      return { graph: new Map(), incomplete, importers: emptyImporters };
  }
}
