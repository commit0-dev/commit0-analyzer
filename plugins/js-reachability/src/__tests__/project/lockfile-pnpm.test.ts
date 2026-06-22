import { describe, it, expect } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { parsePnpmLockfile } from "../../lockfile/pnpm.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("parsePnpmLockfile – pnpm workspace", () => {
  it("resolves lodash 4.17.21 for packages/app", async () => {
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-ws"));
    const entry = graph.get("/lodash@4.17.21");
    expect(entry?.version).toBe("4.17.21");
  });

  it("resolves semver 7.6.0", async () => {
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-ws"));
    const entry = graph.get("/semver@7.6.0");
    expect(entry?.version).toBe("7.6.0");
  });

  it("resolved dir for lodash follows symlink to real .pnpm store path", async () => {
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-ws"));
    const entry = graph.get("/lodash@4.17.21");
    expect(entry?.dir).toBeDefined();
    // Must be the realpath (not a symlink)
    const realDir = fs.realpathSync(
      path.join(
        fixtures,
        "pnpm-ws",
        "node_modules",
        ".pnpm",
        "lodash@4.17.21",
        "node_modules",
        "lodash"
      )
    );
    expect(entry?.dir).toBe(realDir);
  });

  it("resolved dir for semver follows symlink to real .pnpm store path", async () => {
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-ws"));
    const entry = graph.get("/semver@7.6.0");
    expect(entry?.dir).toBeDefined();
    const realDir = fs.realpathSync(
      path.join(
        fixtures,
        "pnpm-ws",
        "node_modules",
        ".pnpm",
        "semver@7.6.0",
        "node_modules",
        "semver"
      )
    );
    expect(entry?.dir).toBe(realDir);
  });

  it("importers map contains packages/app with lodash version", async () => {
    const { importers } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-ws")
    );
    const appImporter = importers.get("packages/app");
    expect(appImporter?.get("lodash")).toBe("4.17.21");
  });

  it("corrupt flag is false for valid lockfile", async () => {
    const { corrupt } = await parsePnpmLockfile(path.join(fixtures, "pnpm-ws"));
    expect(corrupt).toBe(false);
  });
});

describe("parsePnpmLockfile – missing lockfile", () => {
  it("returns empty graph without throwing", async () => {
    const { graph } = await parsePnpmLockfile(
      path.join(fixtures, "missing-lock")
    );
    expect(graph.size).toBe(0);
  });

  it("corrupt flag is false for absent lockfile", async () => {
    const { corrupt } = await parsePnpmLockfile(
      path.join(fixtures, "missing-lock")
    );
    expect(corrupt).toBe(false);
  });
});

describe("parsePnpmLockfile – corrupt lockfile", () => {
  it("returns empty graph for corrupt pnpm-lock.yaml", async () => {
    const { graph } = await parsePnpmLockfile(
      path.join(fixtures, "corrupt-pnpm")
    );
    expect(graph.size).toBe(0);
  });

  it("sets corrupt flag for corrupt pnpm-lock.yaml", async () => {
    const { corrupt } = await parsePnpmLockfile(
      path.join(fixtures, "corrupt-pnpm")
    );
    expect(corrupt).toBe(true);
  });
});
