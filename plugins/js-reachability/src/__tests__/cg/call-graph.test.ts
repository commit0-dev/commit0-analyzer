/**
 * Tests for the call-graph builder (src/cg/build.ts).
 *
 * Exercises demand-driven call-graph construction from entrypoints, edge
 * types (direct calls, imported symbols, dynamic calls → UNKNOWN frontier),
 * and the import-boundary model (third-party deps are opaque nodes).
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCallGraph } from "../../cg/build.js";
import type { CallGraphResult } from "../../cg/build.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(__dirname, "../../../testdata/projects");

// ── Tier (a): imported and called vuln package → PACKAGE_REACHABLE ────────────
// These tests verify that the call graph correctly identifies paths from
// entrypoints through to third-party import sites.

describe("call-graph – import site tracking", () => {
  it("records third-party import sites when a file imports a package", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const result = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
    });
    // The entrypoint imports 'serialize-javascript'; its import site should be recorded
    const sites = result.importSites.get("serialize-javascript");
    expect(sites).toBeDefined();
    expect(sites!.length).toBeGreaterThan(0);
  });

  it("marks the entrypoint file as reachable from roots", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const result = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
    });
    expect(result.reachableFiles.has(path.join(gate, "src", "index.js"))).toBe(true);
  });
});

// ── Tier (c): dynamic require(var) → UNKNOWN frontier ────────────────────────
// The engine must emit an UNKNOWN frontier marker for non-literal specifiers.

describe("call-graph – dynamic require → UNKNOWN frontier", () => {
  it("emits an UNKNOWN frontier marker for dynamic require(var)", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const result = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "dyn-require.js")],
    });
    const hasDynamic = result.unknownFrontiers.some(
      (u) => u.reason === "dynamic-specifier"
    );
    expect(hasDynamic).toBe(true);
  });

  it("does NOT classify dynamic require as NOT_REACHABLE — emits UNKNOWN", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const result = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "dyn-require.js")],
    });
    // UNKNOWN frontier must be present; the graph must not silently drop it
    const unknownCount = result.unknownFrontiers.filter(
      (u) => u.reason === "dynamic-specifier"
    ).length;
    expect(unknownCount).toBeGreaterThan(0);
  });
});

// ── Import boundary model ─────────────────────────────────────────────────────
// Third-party packages are opaque: the call graph records the import site
// but does NOT traverse into the package's internals.

describe("call-graph – import boundary model", () => {
  it("records import site for a third-party package without traversing its internals", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const result = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
    });
    // Import site should be the FIRST-PARTY file that imports the dep, not the dep itself
    const sites = result.importSites.get("serialize-javascript");
    expect(sites).toBeDefined();
    const firstPartyFile = path.join(gate, "src", "index.js");
    expect(sites!.some((s) => s.fromFile === firstPartyFile)).toBe(true);
  });
});

// ── Determinism ───────────────────────────────────────────────────────────────

describe("call-graph – determinism", () => {
  it("produces the same import sites across two invocations", async () => {
    const gate = path.join(fixtures, "gate-g1");
    const opts = { projectRoot: gate, entrypoints: [path.join(gate, "src", "index.js")] };
    const r1 = await buildCallGraph(opts);
    const r2 = await buildCallGraph(opts);
    // Compare serialized import sites
    const sites1 = JSON.stringify([...r1.importSites.entries()].sort());
    const sites2 = JSON.stringify([...r2.importSites.entries()].sort());
    expect(sites1).toBe(sites2);
  });
});
