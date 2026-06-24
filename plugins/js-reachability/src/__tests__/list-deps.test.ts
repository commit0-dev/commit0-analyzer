import { describe, it, expect } from "vitest";
import path from "node:path";
import { listDeps } from "../list-deps.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../testdata/projects"
);

describe("listDeps – single-package npm project", () => {
  it("emits one dep entry with ecosystem=npm", async () => {
    const out = await listDeps(path.join(fixtures, "single-pkg"));
    expect(out.incomplete).toHaveLength(0);
    expect(out.deps.length).toBeGreaterThan(0);
    for (const d of out.deps) {
      expect(d.ecosystem).toBe("npm");
    }
  });

  it("lodash resolves to 4.17.21 in the root workspace", async () => {
    const out = await listDeps(path.join(fixtures, "single-pkg"));
    const lodash = out.deps.find((d) => d.name === "lodash");
    expect(lodash).toBeDefined();
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.workspace).toBe("single-pkg");
  });

  it("output is deterministic (byte-identical on two calls)", async () => {
    const root = path.join(fixtures, "single-pkg");
    const run1 = await listDeps(root);
    const run2 = await listDeps(root);
    expect(JSON.stringify(run1)).toBe(JSON.stringify(run2));
  });
});

describe("listDeps – npm workspace with multi-version hoisting", () => {
  it("produces entries for both workspaces", async () => {
    const out = await listDeps(path.join(fixtures, "npm-ws"));
    const workspaces = new Set(out.deps.map((d) => d.workspace));
    expect(workspaces.has("@npm-ws/app")).toBe(true);
    expect(workspaces.has("@npm-ws/utils")).toBe(true);
  });

  it("app workspace has lodash@4.16.6 (workspace-local version)", async () => {
    const out = await listDeps(path.join(fixtures, "npm-ws"));
    const appLodash = out.deps.find(
      (d) => d.workspace === "@npm-ws/app" && d.name === "lodash"
    );
    expect(appLodash?.version).toBe("4.16.6");
  });

  it("utils workspace has lodash@4.17.21 (root-hoisted version)", async () => {
    const out = await listDeps(path.join(fixtures, "npm-ws"));
    const utilsLodash = out.deps.find(
      (d) => d.workspace === "@npm-ws/utils" && d.name === "lodash"
    );
    expect(utilsLodash?.version).toBe("4.17.21");
  });

  it("deps are sorted workspace → name → version", async () => {
    const out = await listDeps(path.join(fixtures, "npm-ws"));
    for (let i = 1; i < out.deps.length; i++) {
      const prev = out.deps[i - 1];
      const curr = out.deps[i];
      const ws = prev.workspace.localeCompare(curr.workspace);
      if (ws !== 0) {
        expect(ws).toBeLessThan(0);
        continue;
      }
      const nm = prev.name.localeCompare(curr.name);
      if (nm !== 0) {
        expect(nm).toBeLessThan(0);
        continue;
      }
      expect(prev.version.localeCompare(curr.version)).toBeLessThanOrEqual(0);
    }
  });

  it("no duplicate (workspace,name,version) triples", async () => {
    const out = await listDeps(path.join(fixtures, "npm-ws"));
    const keys = out.deps.map((d) => `${d.workspace}\0${d.name}\0${d.version}`);
    const unique = new Set(keys);
    expect(unique.size).toBe(keys.length);
  });
});

describe("listDeps – incomplete project (missing lock)", () => {
  it("surfaces incomplete entries when lockfile is absent", async () => {
    const out = await listDeps(path.join(fixtures, "missing-lock"));
    // incomplete must be non-empty since no lockfile can be parsed
    expect(out.incomplete.length).toBeGreaterThan(0);
    for (const e of out.incomplete) {
      expect(typeof e.scope).toBe("string");
      expect(typeof e.reason).toBe("string");
    }
  });
});

// ── Transitive deps: the full resolved package set ───────────────────────────
// listDeps must emit the FULL resolved set (direct + transitive), each tagged
// with direct:boolean and dev:boolean. The fixture transitive-cross-pkg has:
//   direct runtime deps: dep-a, dep-b, dep-c, dep-e
//   (dep-b is both a direct dep and a transitive dep of dep-a — both tags apply
//    from the declared dep perspective)

describe("listDeps – transitive dep set with direct/dev tags", () => {
  it("emits all installed packages including transitive ones", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    const names = out.deps.map((d) => d.name);
    // All declared direct deps must appear
    expect(names).toContain("dep-a");
    expect(names).toContain("dep-b");
    expect(names).toContain("dep-c");
    expect(names).toContain("dep-e");
  });

  it("direct deps have direct:true", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    const depA = out.deps.find((d) => d.name === "dep-a");
    expect(depA).toBeDefined();
    expect(depA!.direct).toBe(true);
  });

  it("dev-only deps have dev:true", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    const depDev = out.deps.find((d) => d.name === "dep-dev");
    expect(depDev).toBeDefined();
    expect(depDev!.dev).toBe(true);
    expect(depDev!.direct).toBe(false);
  });

  it("output is deterministic with transitive flag fields", async () => {
    const root = path.join(fixtures, "transitive-cross-pkg");
    const run1 = await listDeps(root);
    const run2 = await listDeps(root);
    expect(JSON.stringify(run1)).toBe(JSON.stringify(run2));
  });
});

// H1: corrupt lockfile with zero runtime deps must still be marked incomplete.
// A corrupt lockfile is an error-level signal regardless of declared dep count.
// declaredDepCount=0 must NOT suppress it (only truly-empty projects stay clean).
describe("listDeps – corrupt lockfile with zero runtime deps (H1)", () => {
  it("surfaces a lockfile-corrupt incomplete entry even when declaredDepCount=0", async () => {
    const out = await listDeps(path.join(fixtures, "corrupt-lock-dev-only"));
    // The corrupt lockfile must produce at least one incomplete entry.
    expect(out.incomplete.length).toBeGreaterThan(0);
    // That entry must carry kind='lockfile-corrupt' so the CLI can categorize it.
    const corruptEntry = out.incomplete.find(
      (e) => e.kind === "lockfile-corrupt"
    );
    expect(corruptEntry).toBeDefined();
  });

  it("declaredDepCount is 0 for a devDependencies-only project", async () => {
    const out = await listDeps(path.join(fixtures, "corrupt-lock-dev-only"));
    // Only devDependencies declared — no runtime deps.
    expect(out.declaredDepCount).toBe(0);
  });
});
