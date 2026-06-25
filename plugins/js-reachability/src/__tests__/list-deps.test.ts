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
// with direct:boolean and dev:boolean.
//
// Fixture transitive-cross-pkg:
//   direct runtime deps (ws.deps):     dep-a, dep-b, dep-c, dep-e
//   transitive runtime (via dep-a):    dep-d (dep-a declares it)
//   transitive runtime (via dep-e→dep-f): dep-f, deep-vuln
//   direct dev deps (ws.devDeps):      dep-dev
//
// dep-b is both a direct runtime dep AND transitively reachable via dep-a.
// The emitted entry for dep-b has direct:true (it is declared directly).

describe("listDeps – transitive dep set with direct/dev tags", () => {
  it("emits all installed packages including transitive ones", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    const names = out.deps.map((d) => d.name);
    // All declared direct runtime deps must appear
    expect(names).toContain("dep-a");
    expect(names).toContain("dep-b");
    expect(names).toContain("dep-c");
    expect(names).toContain("dep-e");
    // Transitive packages installed by direct deps must also appear
    expect(names).toContain("dep-d");   // transitive via dep-a
    expect(names).toContain("dep-f");   // transitive via dep-e (minified)
    expect(names).toContain("deep-vuln"); // transitive via dep-e → dep-f
  });

  it("direct runtime deps have direct:true and dev:false", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    const depA = out.deps.find((d) => d.name === "dep-a");
    expect(depA).toBeDefined();
    expect(depA!.direct).toBe(true);
    expect(depA!.dev).toBe(false);
  });

  it("transitive-only runtime packages have direct:false and dev:false", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    // dep-d is installed as a transitive dep of dep-a; not declared at root
    const depD = out.deps.find((d) => d.name === "dep-d");
    expect(depD).toBeDefined();
    expect(depD!.direct).toBe(false);
    expect(depD!.dev).toBe(false);
  });

  it("dev-only direct deps have dev:true and direct:true", async () => {
    const out = await listDeps(path.join(fixtures, "transitive-cross-pkg"));
    // dep-dev is declared in devDependencies at the root and has no runtime path
    const depDev = out.deps.find((d) => d.name === "dep-dev");
    expect(depDev).toBeDefined();
    expect(depDev!.dev).toBe(true);
    // dep-dev is a direct devDependency — but the current list-deps emits
    // devDep direct as false (devDeps walk uses direct:false by design in the
    // old code; new closure code uses directDevNames). dep-dev IS in
    // devDependencies so direct should be true now.
    expect(depDev!.direct).toBe(true);
  });

  it("output is deterministic with transitive flag fields", async () => {
    const root = path.join(fixtures, "transitive-cross-pkg");
    const run1 = await listDeps(root);
    const run2 = await listDeps(root);
    expect(JSON.stringify(run1)).toBe(JSON.stringify(run2));
  });
});

// C1: a direct runtime dep whose on-disk package.json is absent must STILL be
// emitted by list-deps (seeded from lockfile) AND trigger an incomplete entry.
// The sound "unknown" outcome: the dep is scanned for advisories, the scan is
// marked incomplete (exit 3 from the Go CLI).
describe("listDeps – missing on-disk manifest for a direct runtime dep (C1 soundness)", () => {
  it("still emits vuln-pkg even though its package.json is absent on disk", async () => {
    const out = await listDeps(path.join(fixtures, "missing-manifest-root"));
    const vulnPkg = out.deps.find((d) => d.name === "vuln-pkg");
    expect(vulnPkg).toBeDefined();
  });

  it("emits vuln-pkg with version from lockfile (2.0.0)", async () => {
    const out = await listDeps(path.join(fixtures, "missing-manifest-root"));
    const vulnPkg = out.deps.find((d) => d.name === "vuln-pkg");
    expect(vulnPkg?.version).toBe("2.0.0");
  });

  it("emits an incomplete entry for the unreadable manifest so the scan is marked incomplete", async () => {
    const out = await listDeps(path.join(fixtures, "missing-manifest-root"));
    // At least one incomplete entry must exist (for vuln-pkg's missing manifest)
    expect(out.incomplete.length).toBeGreaterThan(0);
    const vuln = out.incomplete.find((e) => e.scope === "vuln-pkg");
    expect(vuln).toBeDefined();
  });

  it("emits an incomplete entry for the unreadable transitive branch (transitive-unreadable)", async () => {
    const out = await listDeps(path.join(fixtures, "missing-manifest-root"));
    const transitive = out.incomplete.find((e) => e.scope === "transitive-unreadable");
    expect(transitive).toBeDefined();
  });

  it("incomplete entry for the missing root manifest has kind dep-unresolved", async () => {
    const out = await listDeps(path.join(fixtures, "missing-manifest-root"));
    const vuln = out.incomplete.find((e) => e.scope === "vuln-pkg");
    expect(vuln?.kind).toBe("dep-unresolved");
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
