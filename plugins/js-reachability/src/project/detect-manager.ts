import fs from "node:fs/promises";
import path from "node:path";
import type { IncompleteEntry } from "./model.js";

type Manager = "npm" | "yarn" | "pnpm" | "unknown";

interface DetectResult {
  manager: Manager;
  incomplete: IncompleteEntry[];
}

/**
 * Determine the package manager for a project root by inspecting lockfiles.
 * The lockfile filename is authoritative — presence beats any engines/packageManager field.
 * Priority when multiple exist: pnpm-lock.yaml > yarn.lock > package-lock.json / npm-shrinkwrap.json
 * (In practice a repo has exactly one, but we pick the most specific if ambiguous.)
 */
export async function detectManager(root: string): Promise<DetectResult> {
  const checks: Array<[string, Manager]> = [
    ["pnpm-lock.yaml", "pnpm"],
    ["yarn.lock", "yarn"],
    ["package-lock.json", "npm"],
    ["npm-shrinkwrap.json", "npm"],
  ];

  for (const [filename, manager] of checks) {
    try {
      await fs.access(path.join(root, filename));
      return { manager, incomplete: [] };
    } catch {
      // file absent — try next
    }
  }

  const scope = path.basename(root);
  return {
    manager: "unknown",
    incomplete: [
      {
        scope,
        reason:
          `No recognized lockfile found in ${root}. ` +
          "Expected pnpm-lock.yaml, yarn.lock, package-lock.json, or npm-shrinkwrap.json.",
        kind: "manager-unknown",
      },
    ],
  };
}
