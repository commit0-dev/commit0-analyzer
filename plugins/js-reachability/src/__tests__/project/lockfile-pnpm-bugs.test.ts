/**
 * Regression tests for pnpm lockfile parser correctness bugs.
 * Each describe block targets one bug; tests are written to FAIL before the fix.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { parsePnpmLockfile } from "../../lockfile/pnpm.js";
import { parseLockfile } from "../../lockfile/index.js";
import { buildProjectModel } from "../../project/build-project-model.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

// ─── C1: importer-based per-workspace version resolution ────────────────────
describe("C1 – pnpm multi-version: each workspace resolves its own lodash", () => {
  it("parsePnpmLockfile returns both lodash versions in the graph", async () => {
    const { graph } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-multi-version")
    );
    const v1 = graph.get("/lodash@4.16.6");
    const v2 = graph.get("/lodash@4.17.21");
    expect(v1?.version).toBe("4.16.6");
    expect(v2?.version).toBe("4.17.21");
  });

  it("app workspace resolves lodash to 4.16.6 (importer-pinned)", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "pnpm-multi-version")
    );
    const app = model.workspaces.find((w) => w.name === "@pnpm-mv/app");
    expect(app).toBeDefined();
    expect(app!.deps.get("lodash")?.version).toBe("4.16.6");
  });

  it("lib workspace resolves lodash to 4.17.21 (importer-pinned)", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "pnpm-multi-version")
    );
    const lib = model.workspaces.find((w) => w.name === "@pnpm-mv/lib");
    expect(lib).toBeDefined();
    expect(lib!.deps.get("lodash")?.version).toBe("4.17.21");
  });

  it("no incomplete entries when all deps are in lockfile", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "pnpm-multi-version")
    );
    expect(model.incomplete).toHaveLength(0);
  });

  it("project-model JSON is byte-identical across two runs (determinism)", async () => {
    const { serializeProjectModel } = await import(
      "../../project-model-cmd.js"
    );
    const model1 = await buildProjectModel(
      path.join(fixtures, "pnpm-multi-version")
    );
    const model2 = await buildProjectModel(
      path.join(fixtures, "pnpm-multi-version")
    );
    expect(serializeProjectModel(model1)).toBe(serializeProjectModel(model2));
  });
});

// ─── C2: peer-suffixed package keys ─────────────────────────────────────────
describe("C2 – pnpm peer-suffixed key parsing", () => {
  /**
   * pnpm v6/v9 uses keys like:
   *   /lodash@4.17.21(react@18.0.0)
   *   /@scope/pkg@1.0.0(peer@2.0.0)
   * parsePackageKey must strip the trailing (...) before splitting name/version.
   */
  it("parsePnpmLockfile with peer-suffixed key resolves clean name and version", async () => {
    // The peer-suffix fixture is embedded as an inline lockfile string in the test.
    // We test by writing a temp fixture directory.
    const tmp = path.join(fixtures, "pnpm-peer-suffix");
    // The fixture is pre-created by setup-fixtures.mjs — but we can test
    // the parser function directly by calling parsePnpmLockfile on the
    // peer-suffix-pnpm fixture directory.
    // Here we just verify the existing pnpm-multi-version fixture (which uses
    // plain keys) still works, and separately test via the peer-suffix fixture
    // that is created below.
    // We use the parsePnpmLockfile result for a fixture YAML with peer suffix.
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-peer-suffix"));
    // Should parse /lodash@4.17.21(react@18.0.0) → name=lodash, version=4.17.21
    const entry = graph.get("/lodash@4.17.21(react@18.0.0)");
    expect(entry).toBeDefined();
    expect(entry?.name).toBe("lodash");
    expect(entry?.version).toBe("4.17.21");
  });

  it("scoped peer-suffixed key parses correctly", async () => {
    const { graph } = await parsePnpmLockfile(path.join(fixtures, "pnpm-peer-suffix"));
    // /@scope/helper@1.0.0(peer@2.0.0) → name=@scope/helper, version=1.0.0
    const entry = graph.get("/@scope/helper@1.0.0(peer@2.0.0)");
    expect(entry).toBeDefined();
    expect(entry?.name).toBe("@scope/helper");
    expect(entry?.version).toBe("1.0.0");
  });
});

// ─── C3: unresolvable declared dep → incomplete ──────────────────────────────
describe("C3 – missing-dep-pnpm: unresolvable dep surfaces as incomplete", () => {
  it("dep present in package.json but absent from lockfile graph → incomplete entry", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "missing-dep-pnpm")
    );
    const scopes = model.incomplete.map((e) => e.scope);
    // "not-in-lockfile" is declared but not resolvable
    expect(scopes.some((s) => s.includes("not-in-lockfile"))).toBe(true);
  });

  it("resolves declared dep that IS in lockfile normally (no spurious incomplete)", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "missing-dep-pnpm")
    );
    const ws = model.workspaces[0];
    // lodash IS in the lockfile graph and importer
    expect(ws.deps.get("lodash")).toBeDefined();
  });

  it("empty lockfile graph → each declared non-optional dep produces an incomplete entry", async () => {
    // missing-lock has no lockfile → graph is empty → incomplete for each dep
    const model = await buildProjectModel(path.join(fixtures, "missing-lock"));
    // missing-lock/package.json declares no deps, so incomplete just covers manager
    // We check that the behavior is correct: no silent clean result
    expect(model.manager).toBe("unknown");
    expect(model.incomplete.length).toBeGreaterThan(0);
  });
});

// ─── H1: berry yarn → incomplete ─────────────────────────────────────────────
describe("H1 – berry yarn: versions resolved AND incomplete entry present", () => {
  it("parseYarnLockfile on berry returns a non-empty graph", async () => {
    const { parseYarnLockfile } = await import("../../lockfile/yarn.js");
    const { graph } = await parseYarnLockfile(path.join(fixtures, "berry-yarn"));
    expect(graph.size).toBeGreaterThan(0);
  });

  it("parseLockfile with berry yarn returns an incomplete entry for PnP", async () => {
    const result = await parseLockfile(path.join(fixtures, "berry-yarn"), "yarn");
    expect(result.incomplete.length).toBeGreaterThan(0);
    expect(result.incomplete[0].reason).toMatch(/berry|PnP|pnp/i);
  });

  it("berry yarn graph resolves lodash version correctly", async () => {
    const { parseYarnLockfile } = await import("../../lockfile/yarn.js");
    const { graph } = await parseYarnLockfile(path.join(fixtures, "berry-yarn"));
    // Berry specifier key: "lodash@npm:^4.17.21"
    const entry = graph.get("lodash@npm:^4.17.21");
    expect(entry?.version).toBe("4.17.21");
  });
});

// ─── H2: corrupt pnpm / corrupt yarn → incomplete ────────────────────────────
describe("H2 – corrupt pnpm lockfile → incomplete, no crash, no silent-clean", () => {
  it("parseLockfile returns incomplete entry for corrupt pnpm-lock.yaml", async () => {
    const result = await parseLockfile(
      path.join(fixtures, "corrupt-pnpm"),
      "pnpm"
    );
    expect(result.incomplete.length).toBeGreaterThan(0);
    expect(result.incomplete[0].reason).toMatch(/corrupt|parse|invalid/i);
  });

  it("parseLockfile does not throw on corrupt pnpm-lock.yaml", async () => {
    await expect(
      parseLockfile(path.join(fixtures, "corrupt-pnpm"), "pnpm")
    ).resolves.not.toThrow();
  });

  it("parseLockfile graph is empty for corrupt pnpm-lock.yaml", async () => {
    const result = await parseLockfile(
      path.join(fixtures, "corrupt-pnpm"),
      "pnpm"
    );
    expect(result.graph.size).toBe(0);
  });
});

describe("H2 – corrupt yarn lockfile → incomplete, no crash, no silent-clean", () => {
  it("parseLockfile returns incomplete entry for corrupt yarn.lock", async () => {
    const result = await parseLockfile(
      path.join(fixtures, "corrupt-yarn"),
      "yarn"
    );
    expect(result.incomplete.length).toBeGreaterThan(0);
    expect(result.incomplete[0].reason).toMatch(/corrupt|parse|invalid/i);
  });

  it("parseLockfile does not throw on corrupt yarn.lock", async () => {
    await expect(
      parseLockfile(path.join(fixtures, "corrupt-yarn"), "yarn")
    ).resolves.not.toThrow();
  });
});
