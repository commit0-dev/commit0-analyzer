import { describe, it, expect } from "vitest";
import path from "node:path";
import { parseNpmLockfile } from "../../lockfile/npm.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("parseNpmLockfile – single-package", () => {
  it("resolves lodash to exact version", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "single-pkg"));
    const entry = graph.get("node_modules/lodash");
    expect(entry).toBeDefined();
    expect(entry?.version).toBe("4.17.21");
  });

  it("resolved dir points to node_modules/lodash under the root", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "single-pkg"));
    const entry = graph.get("node_modules/lodash");
    expect(entry?.dir).toBe(
      path.join(fixtures, "single-pkg", "node_modules", "lodash")
    );
  });
});

describe("parseNpmLockfile – npm workspace with hoisted multi-version", () => {
  it("resolves root-level lodash 4.17.21 at node_modules/lodash", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "npm-ws"));
    const entry = graph.get("node_modules/lodash");
    expect(entry?.version).toBe("4.17.21");
  });

  it("resolves app-local lodash 4.16.6 at packages/app/node_modules/lodash", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "npm-ws"));
    const entry = graph.get("packages/app/node_modules/lodash");
    expect(entry?.version).toBe("4.16.6");
  });

  it("resolved dir for hoisted lodash is under root node_modules", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "npm-ws"));
    const entry = graph.get("node_modules/lodash");
    expect(entry?.dir).toBe(
      path.join(fixtures, "npm-ws", "node_modules", "lodash")
    );
  });

  it("resolved dir for app-local lodash is under packages/app/node_modules", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "npm-ws"));
    const entry = graph.get("packages/app/node_modules/lodash");
    expect(entry?.dir).toBe(
      path.join(fixtures, "npm-ws", "packages", "app", "node_modules", "lodash")
    );
  });

  it("resolves semver", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "npm-ws"));
    const entry = graph.get("node_modules/semver");
    expect(entry?.version).toBe("7.6.0");
  });
});

describe("parseNpmLockfile – corrupt lockfile", () => {
  it("returns an empty graph and does not throw", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "corrupt-lock"));
    expect(graph.size).toBe(0);
  });

  it("sets corrupt flag when lockfile cannot be parsed", async () => {
    const result = await parseNpmLockfile(path.join(fixtures, "corrupt-lock"));
    expect(result.corrupt).toBe(true);
  });
});

describe("parseNpmLockfile – missing lockfile", () => {
  it("returns an empty graph and does not throw", async () => {
    const { graph } = await parseNpmLockfile(path.join(fixtures, "missing-lock"));
    expect(graph.size).toBe(0);
  });

  it("does not set corrupt flag for absent lockfile", async () => {
    const result = await parseNpmLockfile(path.join(fixtures, "missing-lock"));
    expect(result.corrupt).toBe(false);
  });
});
