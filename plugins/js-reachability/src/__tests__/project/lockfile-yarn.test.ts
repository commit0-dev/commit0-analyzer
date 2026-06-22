import { describe, it, expect } from "vitest";
import path from "node:path";
import { parseYarnLockfile } from "../../lockfile/yarn.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("parseYarnLockfile – yarn v1", () => {
  it("resolves lodash@^4.17.21 to 4.17.21", async () => {
    const { graph } = await parseYarnLockfile(path.join(fixtures, "yarn-ws"));
    const entry = graph.get("lodash@^4.17.21");
    expect(entry?.version).toBe("4.17.21");
  });

  it("resolves semver@^7.6.0 to 7.6.0", async () => {
    const { graph } = await parseYarnLockfile(path.join(fixtures, "yarn-ws"));
    const entry = graph.get("semver@^7.6.0");
    expect(entry?.version).toBe("7.6.0");
  });

  it("resolved dir points under root node_modules", async () => {
    const { graph } = await parseYarnLockfile(path.join(fixtures, "yarn-ws"));
    const entry = graph.get("lodash@^4.17.21");
    expect(entry?.dir).toBe(
      path.join(fixtures, "yarn-ws", "node_modules", "lodash")
    );
  });

  it("corrupt flag is false for valid yarn.lock", async () => {
    const { corrupt } = await parseYarnLockfile(path.join(fixtures, "yarn-ws"));
    expect(corrupt).toBe(false);
  });

  it("incomplete is empty for yarn v1 (no PnP)", async () => {
    const { incomplete } = await parseYarnLockfile(
      path.join(fixtures, "yarn-ws")
    );
    expect(incomplete).toHaveLength(0);
  });
});

describe("parseYarnLockfile – missing lockfile", () => {
  it("returns empty graph without throwing", async () => {
    const { graph } = await parseYarnLockfile(
      path.join(fixtures, "missing-lock")
    );
    expect(graph.size).toBe(0);
  });

  it("corrupt flag is false for absent lockfile", async () => {
    const { corrupt } = await parseYarnLockfile(
      path.join(fixtures, "missing-lock")
    );
    expect(corrupt).toBe(false);
  });
});

describe("parseYarnLockfile – corrupt yarn.lock", () => {
  it("returns empty graph for corrupt yarn.lock", async () => {
    const { graph } = await parseYarnLockfile(
      path.join(fixtures, "corrupt-yarn")
    );
    expect(graph.size).toBe(0);
  });

  it("sets corrupt flag for corrupt yarn.lock", async () => {
    const { corrupt } = await parseYarnLockfile(
      path.join(fixtures, "corrupt-yarn")
    );
    expect(corrupt).toBe(true);
  });
});
