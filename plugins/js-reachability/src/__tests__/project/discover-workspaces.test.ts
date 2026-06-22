import { describe, it, expect } from "vitest";
import path from "node:path";
import { discoverWorkspaces } from "../../project/discover-workspaces.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("discoverWorkspaces", () => {
  it("single-package repo yields one workspace at root", async () => {
    const result = await discoverWorkspaces(path.join(fixtures, "single-pkg"), "npm");
    expect(result.workspaces).toHaveLength(1);
    expect(result.workspaces[0].name).toBe("single-pkg");
    expect(result.workspaces[0].dir).toBe(path.join(fixtures, "single-pkg"));
    expect(result.incomplete).toHaveLength(0);
  });

  it("npm workspaces glob packages/* yields sorted workspace list", async () => {
    const result = await discoverWorkspaces(path.join(fixtures, "npm-ws"), "npm");
    expect(result.workspaces).toHaveLength(2);
    // sorted by name
    expect(result.workspaces[0].name).toBe("@npm-ws/app");
    expect(result.workspaces[1].name).toBe("@npm-ws/utils");
    // dirs are absolute
    expect(result.workspaces[0].dir).toBe(path.join(fixtures, "npm-ws/packages/app"));
    expect(result.workspaces[1].dir).toBe(path.join(fixtures, "npm-ws/packages/utils"));
    expect(result.incomplete).toHaveLength(0);
  });

  it("yarn workspaces object form {packages:[]} is handled", async () => {
    const result = await discoverWorkspaces(path.join(fixtures, "yarn-ws"), "yarn");
    expect(result.workspaces).toHaveLength(2);
    expect(result.workspaces.map((w) => w.name).sort()).toEqual([
      "@yarn-ws/app",
      "@yarn-ws/utils",
    ]);
    expect(result.incomplete).toHaveLength(0);
  });

  it("pnpm reads pnpm-workspace.yaml for glob patterns", async () => {
    const result = await discoverWorkspaces(path.join(fixtures, "pnpm-ws"), "pnpm");
    expect(result.workspaces).toHaveLength(2);
    expect(result.workspaces.map((w) => w.name).sort()).toEqual([
      "@pnpm-ws/app",
      "@pnpm-ws/utils",
    ]);
    expect(result.incomplete).toHaveLength(0);
  });

  it("workspaces are sorted deterministically", async () => {
    const r1 = await discoverWorkspaces(path.join(fixtures, "npm-ws"), "npm");
    const r2 = await discoverWorkspaces(path.join(fixtures, "npm-ws"), "npm");
    expect(r1.workspaces.map((w) => w.name)).toEqual(
      r2.workspaces.map((w) => w.name)
    );
  });

  it("glob match on a directory with no package.json is silently skipped", async () => {
    // packages/config exists but has no package.json — must be skipped with
    // no incomplete entry and must not prevent the other workspace from loading.
    const result = await discoverWorkspaces(
      path.join(fixtures, "npm-ws-glob-empty-dir"),
      "npm"
    );
    expect(result.workspaces).toHaveLength(1);
    expect(result.workspaces[0].name).toBe("@glob-empty/app");
    expect(result.incomplete).toHaveLength(0);
  });

  it("nested workspace glob (packages/app/*) discovers all child packages", async () => {
    const result = await discoverWorkspaces(
      path.join(fixtures, "npm-ws-nested"),
      "npm"
    );
    expect(result.workspaces).toHaveLength(2);
    const names = result.workspaces.map((w) => w.name).sort();
    expect(names).toEqual(["@nested/core", "@nested/utils"]);
    expect(result.incomplete).toHaveLength(0);
  });

  it("workspace manifest is loaded into .manifest", async () => {
    const result = await discoverWorkspaces(path.join(fixtures, "npm-ws"), "npm");
    const app = result.workspaces.find((w) => w.name === "@npm-ws/app");
    expect(app?.manifest.name).toBe("@npm-ws/app");
    expect(app?.manifest.dependencies?.lodash).toBe("^4.17.21");
  });
});
