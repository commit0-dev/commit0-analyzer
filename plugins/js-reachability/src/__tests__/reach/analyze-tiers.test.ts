/**
 * Tests that the four reachability tiers produce correct verdicts through the
 * SHIPPED analyze() path (not the dead queryReachability path).
 *
 * These tests drive both correctness and path parity with queryReachability.
 * Tiers:
 *   (a) imported+called vuln pkg          → PACKAGE_REACHABLE
 *   (b) installed-not-imported            → NOT_REACHABLE
 *   (c) dynamic require(var) only path    → UNKNOWN (never NOT_REACHABLE)
 *   (d) symbol-level with resolvable sym  → SYMBOL_REACHABLE
 *
 * C2 fix: tier-(c) must be proven through analyze() so the shipped path is
 * covered. Before the C1 fix in bfs.ts this test will be RED.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../../engine/analyze.js";
import { Confidence } from "../../gen/commit0/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const gate = path.resolve(__dirname, "../../../testdata/projects/gate-g1");

const baseAdvisory = {
  id: "GHSA-h9rv-jmmf-4pgx",
  module: "serialize-javascript",
  versionRange: "<3.1.0",
  symbols: [] as Array<{ package: string; name: string }>,
  symbolLevel: false,
  sources: ["osv"],
};

// ── Tier (a): imported and called → PACKAGE_REACHABLE via analyze() ───────────

describe("analyze() tier (a): imported and called → PACKAGE_REACHABLE", () => {
  it("returns PACKAGE_REACHABLE when package is statically imported from entrypoint", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisories: [{ ...baseAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});

// ── Tier (b): installed-not-imported → NOT_REACHABLE via analyze() ────────────

describe("analyze() tier (b): installed but not imported → NOT_REACHABLE", () => {
  it("returns NOT_REACHABLE for lodash which is installed but never imported", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisories: [
        {
          id: "GHSA-lodash-not-imported",
          module: "lodash",
          versionRange: "<4.17.21",
          symbols: [],
          symbolLevel: false,
          sources: ["synthetic"],
        },
      ],
    });
    const f = findings.find((f) => f.module === "lodash");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Tier (c): dynamic require(var) only path → UNKNOWN via analyze() ──────────
// This is the C1/C2 regression: before the bfs.ts fix, analyze() returns
// NOT_REACHABLE because bfsReachable early-returns with unknownFrontierBlocks=false
// when importSites.length === 0, bypassing the reachable-frontier check.
// After the fix, importSites.length===0 must still consult reachable UNKNOWN
// frontiers and return CONFIDENCE_UNKNOWN.

describe("analyze() tier (c): dynamic-require-only path → UNKNOWN (not NOT_REACHABLE)", () => {
  it("returns CONFIDENCE_UNKNOWN when the only path uses a dynamic specifier (dyn-require.js entrypoint)", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "dyn-require.js")],
      advisories: [{ ...baseAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    // Must be UNKNOWN — unknown ≠ safe. Before the C1 fix this fails with NOT_REACHABLE.
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(f!.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });

  it("is deterministic: two consecutive analyze() calls return byte-identical JSON for the dynamic-require case", async () => {
    const req = {
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "dyn-require.js")],
      advisories: [{ ...baseAdvisory }],
    };
    const run1 = JSON.stringify(await analyze(req));
    const run2 = JSON.stringify(await analyze(req));
    expect(run1).toBe(run2);
  });
});

// ── Tier (d): SYMBOL_REACHABLE via analyze() ─────────────────────────────────

describe("analyze() tier (d): symbol-level advisory with resolvable symbol → SYMBOL_REACHABLE", () => {
  it("returns SYMBOL_REACHABLE with a path when symbol-level advisory matches a real import", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "symbol-caller.js")],
      advisories: [
        {
          id: "GHSA-synth-sym-001",
          module: "serialize-javascript",
          versionRange: "<3.1.0",
          symbols: [{ package: "serialize-javascript", name: "serialize" }],
          symbolLevel: true,
          sources: ["synthetic"],
        },
      ],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_SYMBOL_REACHABLE);
    expect(f!.path).toBeDefined();
    expect(f!.path!.steps.length).toBeGreaterThan(0);
  });
});

// ── No entrypoint: UNKNOWN, never NOT_REACHABLE ───────────────────────────────
// A private package that declares and imports a vulnerable dependency but has
// no bin/main/exports yields no entrypoint. With no root to traverse from, the
// engine must report UNKNOWN — concluding NOT_REACHABLE would be a false
// negative (the dep is genuinely used; we simply cannot prove a path).

const noEntry = path.resolve(
  __dirname,
  "../../../testdata/projects/no-entrypoint-ws"
);

describe("analyze() no entrypoint → UNKNOWN, never NOT_REACHABLE", () => {
  it("returns UNKNOWN for a declared+imported dep when the workspace has no resolvable entrypoint", async () => {
    const findings = await analyze({
      moduleRoot: noEntry,
      entrypoints: [], // force auto-detection, which finds none
      advisories: [{ ...baseAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(f!.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Default index entry: package with no main but index.js → analyzable ───────
// Node resolves a package with no main/exports to index.js. The engine must
// detect that default entry and report PACKAGE_REACHABLE, not UNKNOWN.

const defaultIndex = path.resolve(
  __dirname,
  "../../../testdata/projects/default-index-ws"
);

describe("analyze() default index.js entry → PACKAGE_REACHABLE", () => {
  it("detects index.js as the entry when no main/exports is declared", async () => {
    const findings = await analyze({
      moduleRoot: defaultIndex,
      entrypoints: [], // force auto-detection → should find index.js
      advisories: [{ ...baseAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});
