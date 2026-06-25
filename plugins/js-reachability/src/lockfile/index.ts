import type { IncompleteEntry, LockfileGraph } from "../project/model.js";
import { parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile, type PnpmParseResult, type HostDescriptor } from "./pnpm.js";
import { parseYarnLockfile } from "./yarn.js";

export type { HostDescriptor };

export interface LockfileParseResult {
  graph: LockfileGraph;
  incomplete: IncompleteEntry[];
  /**
   * Importer map from pnpm: workspace-relative-dir → (depName → resolved version).
   * Populated only for pnpm; empty map for other managers.
   */
  importers: PnpmParseResult["importers"];
  /**
   * Platform constraints for optional npm lockfile entries.
   * Populated only for npm; empty map for other managers.
   * Keyed by the lockfile packages-map key (e.g. "node_modules/foo").
   */
  optionalPlatformConstraints: Map<string, { os?: string[]; cpu?: string[] }>;
}

/**
 * Dispatch to the correct lockfile parser based on detected manager.
 * Returns an empty graph (not an error) for unknown managers.
 * Corruption is surfaced via incomplete entries — never throws.
 */
export async function parseLockfile(
  root: string,
  manager: "npm" | "yarn" | "pnpm" | "unknown",
  host?: HostDescriptor
): Promise<LockfileParseResult> {
  const incomplete: IncompleteEntry[] = [];
  const emptyImporters: PnpmParseResult["importers"] = new Map();
  const emptyOptionalConstraints = new Map<string, { os?: string[]; cpu?: string[] }>();

  switch (manager) {
    case "npm": {
      const result = await parseNpmLockfile(root, host);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "package-lock.json exists but could not be parsed (corrupt or invalid JSON).",
          kind: "lockfile-corrupt",
        });
      }
      return {
        graph: result.graph,
        incomplete,
        importers: emptyImporters,
        optionalPlatformConstraints: result.optionalPlatformConstraints,
      };
    }
    case "pnpm": {
      const result = await parsePnpmLockfile(root, host);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "pnpm-lock.yaml exists but could not be parsed (corrupt or invalid YAML).",
          kind: "lockfile-corrupt",
        });
      }
      incomplete.push(...result.incomplete);
      return {
        graph: result.graph,
        incomplete,
        importers: result.importers,
        optionalPlatformConstraints: emptyOptionalConstraints,
      };
    }
    case "yarn": {
      const result = await parseYarnLockfile(root);
      if (result.corrupt) {
        incomplete.push({
          scope: root,
          reason:
            "yarn.lock exists but could not be parsed (corrupt or unrecognized format).",
          kind: "lockfile-corrupt",
        });
      }
      incomplete.push(...result.incomplete);
      return {
        graph: result.graph,
        incomplete,
        importers: emptyImporters,
        optionalPlatformConstraints: emptyOptionalConstraints,
      };
    }
    default:
      return {
        graph: new Map(),
        incomplete,
        importers: emptyImporters,
        optionalPlatformConstraints: emptyOptionalConstraints,
      };
  }
}
