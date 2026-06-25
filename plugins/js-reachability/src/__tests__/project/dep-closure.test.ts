/**
 * Unit tests for computeWorkspaceClosure.
 *
 * Fixture: dep-closure-fixture (built by build-fixtures.mjs globalSetup)
 *
 *   Runtime deps (ws.deps):   pkg-a@1.0.0 (declares pkg-b@2.0.0), pkg-e@3.0.0
 *   Dev deps (ws.devDeps):    pkg-c@1.0.0 (declares pkg-d@1.0.0 and pkg-e@3.0.0)
 *
 *   Expected runtime closure:  pkg-a, pkg-b (transitive via pkg-a), pkg-e
 *   Expected dev-only closure:  pkg-c, pkg-d
 *   pkg-e reachable from BOTH runtime and dev roots → must be runtime only
 *
 * Versions are derived from the actual fixture package.json files written by
 * build-fixtures.mjs (pkg-b@2.0.0, pkg-e@3.0.0 are distinct to catch bugs
 * where the walk reads the wrong dir).
 *
 * Fixture: missing-manifest-root (built by build-fixtures.mjs globalSetup)
 *
 *   Runtime deps: vuln-pkg@2.0.0 (no on-disk package.json), dep-with-child@1.0.0
 *   dep-with-child declares transitive-unreadable (no on-disk package.json)
 *
 *   Expected: vuln-pkg IS in runtime (seeded from lockfile version 2.0.0)
 *             dep-with-child IS in runtime (manifest readable)
 *             incomplete[] has entries for vuln-pkg and transitive-unreadable
 */

import { describe, it, expect } from "vitest";
import path from "node:path";
import { buildProjectModel } from "../../project/build-project-model.js";
import { computeWorkspaceClosure } from "../../project/dep-closure.js";

const fixture = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects/dep-closure-fixture"
);

async function getWorkspace() {
  const model = await buildProjectModel(fixture);
  const ws = model.workspaces[0];
  if (!ws) throw new Error("fixture has no workspaces");
  return ws;
}

describe("computeWorkspaceClosure – runtime closure", () => {
  it("contains the direct runtime dep pkg-a", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.has("pkg-a")).toBe(true);
  });

  it("contains pkg-b as a transitive dep of pkg-a", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.has("pkg-b")).toBe(true);
  });

  it("contains the direct runtime dep pkg-e", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.has("pkg-e")).toBe(true);
  });

  it("reads pkg-b version from its installed package.json (2.0.0)", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.get("pkg-b")?.version).toBe("2.0.0");
  });

  it("reads pkg-e version from its installed package.json (3.0.0)", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.get("pkg-e")?.version).toBe("3.0.0");
  });

  it("runtime closure is exactly {pkg-a, pkg-b, pkg-e}", async () => {
    const ws = await getWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect([...runtime.keys()].sort()).toEqual(["pkg-a", "pkg-b", "pkg-e"]);
  });
});

describe("computeWorkspaceClosure – dev-only closure", () => {
  it("contains the direct dev dep pkg-c", async () => {
    const ws = await getWorkspace();
    const { dev } = computeWorkspaceClosure(ws);
    expect(dev.has("pkg-c")).toBe(true);
  });

  it("contains pkg-d as a transitive dep of pkg-c", async () => {
    const ws = await getWorkspace();
    const { dev } = computeWorkspaceClosure(ws);
    expect(dev.has("pkg-d")).toBe(true);
  });

  it("does NOT contain pkg-e (reachable from runtime — runtime wins)", async () => {
    const ws = await getWorkspace();
    const { dev } = computeWorkspaceClosure(ws);
    expect(dev.has("pkg-e")).toBe(false);
  });

  it("dev-only closure is exactly {pkg-c, pkg-d}", async () => {
    const ws = await getWorkspace();
    const { dev } = computeWorkspaceClosure(ws);
    expect([...dev.keys()].sort()).toEqual(["pkg-c", "pkg-d"]);
  });
});

describe("computeWorkspaceClosure – determinism", () => {
  it("two calls produce byte-identical results", async () => {
    const ws = await getWorkspace();
    const r1 = computeWorkspaceClosure(ws);
    const r2 = computeWorkspaceClosure(ws);
    const serialize = (c: typeof r1) =>
      JSON.stringify({
        runtime: [...c.runtime.entries()].sort(([a], [b]) => a.localeCompare(b)),
        dev: [...c.dev.entries()].sort(([a], [b]) => a.localeCompare(b)),
      });
    expect(serialize(r1)).toBe(serialize(r2));
  });
});

// ── C1: missing on-disk manifest — root still seeded from lockfile ────────────
// Fixture: missing-manifest-root
//   vuln-pkg is in the lockfile at version 2.0.0 but its on-disk package.json
//   is absent. The closure must still include it (seeded from the lockfile entry)
//   and the incomplete[] array must record the unreadable manifest.
//
// dep-with-child has a readable manifest that declares transitive-unreadable,
// whose on-disk package.json is also absent. That transitive unreadable branch
// must also surface an incomplete entry.

const missingManifestFixture = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects/missing-manifest-root"
);

async function getMissingManifestWorkspace() {
  const model = await buildProjectModel(missingManifestFixture);
  const ws = model.workspaces[0];
  if (!ws) throw new Error("missing-manifest-root fixture has no workspaces");
  return ws;
}

describe("computeWorkspaceClosure – missing on-disk manifest (C1 soundness)", () => {
  it("includes vuln-pkg in runtime closure even though its package.json is absent", async () => {
    const ws = await getMissingManifestWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.has("vuln-pkg")).toBe(true);
  });

  it("uses lockfile version 2.0.0 for vuln-pkg (seeded from lockfile, no on-disk read)", async () => {
    const ws = await getMissingManifestWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.get("vuln-pkg")?.version).toBe("2.0.0");
  });

  it("includes dep-with-child in runtime closure (its manifest IS readable)", async () => {
    const ws = await getMissingManifestWorkspace();
    const { runtime } = computeWorkspaceClosure(ws);
    expect(runtime.has("dep-with-child")).toBe(true);
  });

  it("records incomplete entry for vuln-pkg (unreadable root manifest)", async () => {
    const ws = await getMissingManifestWorkspace();
    const { incomplete } = computeWorkspaceClosure(ws);
    const vuln = incomplete.find((e) => e.scope === "vuln-pkg");
    expect(vuln).toBeDefined();
  });

  it("records incomplete entry for transitive-unreadable (unreadable transitive manifest)", async () => {
    const ws = await getMissingManifestWorkspace();
    const { incomplete } = computeWorkspaceClosure(ws);
    const transitive = incomplete.find((e) => e.scope === "transitive-unreadable");
    expect(transitive).toBeDefined();
  });
});
