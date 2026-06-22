/**
 * Tests for entrypoint detection (app vs library, explicit override, monorepo).
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { detectEntrypoints } from "../../entry/detect-entrypoints.js";
import type { ProjectModel } from "../../project/model.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(__dirname, "../../../testdata/projects");
const resolveFixtures = path.join(fixtures, "resolve-fixtures");

// ── app workspace: bin + main ─────────────────────────────────────────────────

describe("detectEntrypoints – app workspace", () => {
  it("returns the bin script as an entrypoint for an app with bin field", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "my-app",
          dir: path.join(resolveFixtures, "packages", "app"),
          manifest: {
            name: "my-app",
            version: "1.0.0",
            private: true,
            bin: { "my-app": "./bin/cli.js" },
            main: "./src/index.js",
          },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const eps = detectEntrypoints(model);
    const appEps = eps.get("my-app") ?? [];
    const paths = appEps.map((e) => e.file);
    expect(paths.some((p) => p.includes("cli.js"))).toBe(true);
  });

  it("includes main as an entrypoint for a private (app) workspace", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "my-app",
          dir: path.join(resolveFixtures, "packages", "app"),
          manifest: {
            name: "my-app",
            version: "1.0.0",
            private: true,
            main: "./src/index.js",
          },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const eps = detectEntrypoints(model);
    const appEps = eps.get("my-app") ?? [];
    expect(appEps.some((e) => e.file.includes("index.js"))).toBe(true);
  });
});

// ── library workspace: exported surface ───────────────────────────────────────

describe("detectEntrypoints – library workspace", () => {
  it("returns the exports main entry for a public library package", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "@ws/utils",
          dir: path.join(resolveFixtures, "packages", "utils"),
          manifest: {
            name: "@ws/utils",
            version: "1.0.0",
            // public: no private flag
            main: "./src/index.js",
            exports: {
              ".": "./src/index.js",
            },
          },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const eps = detectEntrypoints(model);
    const libEps = eps.get("@ws/utils") ?? [];
    expect(libEps.length).toBeGreaterThan(0);
    expect(libEps.some((e) => e.file.includes("index.js"))).toBe(true);
  });
});

// ── explicit override ─────────────────────────────────────────────────────────

describe("detectEntrypoints – explicit override", () => {
  it("uses explicit entrypoints when provided, ignoring auto-detection", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "my-app",
          dir: path.join(resolveFixtures, "packages", "app"),
          manifest: {
            name: "my-app",
            version: "1.0.0",
            private: true,
            main: "./src/index.js",
          },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const explicit = [path.join(resolveFixtures, "packages", "app", "src", "custom-entry.js")];
    const eps = detectEntrypoints(model, { explicitEntrypoints: explicit });
    const appEps = eps.get("my-app") ?? [];
    expect(appEps.some((e) => e.file.includes("custom-entry.js"))).toBe(true);
  });
});

// ── monorepo: inter-workspace edges ──────────────────────────────────────────

describe("detectEntrypoints – monorepo", () => {
  it("produces entries for each workspace in a monorepo", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "@ws/app",
          dir: path.join(resolveFixtures, "packages", "app"),
          manifest: {
            name: "@ws/app",
            version: "1.0.0",
            private: true,
            main: "./src/index.js",
          },
          deps: new Map(),
          localDeps: ["@ws/utils"],
        },
        {
          name: "@ws/utils",
          dir: path.join(resolveFixtures, "packages", "utils"),
          manifest: {
            name: "@ws/utils",
            version: "1.0.0",
            main: "./src/index.js",
          },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const eps = detectEntrypoints(model);
    expect(eps.has("@ws/app")).toBe(true);
    expect(eps.has("@ws/utils")).toBe(true);
  });
});

// ── no manifest main/bin/exports → empty ─────────────────────────────────────

describe("detectEntrypoints – missing entry fields", () => {
  it("returns no entrypoints for a workspace with no main/bin/exports", () => {
    const model: ProjectModel = {
      root: resolveFixtures,
      manager: "npm",
      workspaces: [
        {
          name: "empty-pkg",
          dir: path.join(resolveFixtures, "packages", "empty"),
          manifest: { name: "empty-pkg", version: "1.0.0" },
          deps: new Map(),
          localDeps: [],
        },
      ],
      incomplete: [],
    };
    const eps = detectEntrypoints(model);
    const emptyEps = eps.get("empty-pkg") ?? [];
    expect(emptyEps).toHaveLength(0);
  });
});
