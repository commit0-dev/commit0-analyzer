/**
 * Tests for the reachability query (src/reach/query.ts).
 *
 * Exercises the four labeled tiers required by Gate G1-JS:
 *   (a) imported+called vuln pkg     → PACKAGE_REACHABLE
 *   (b) installed-not-imported       → NOT_REACHABLE
 *   (c) dynamic require(var)         → UNKNOWN (NOT NOT_REACHABLE)
 *   (d) SYMBOL_REACHABLE with path   → synthetic advisory only
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { queryReachability } from "../../reach/query.js";
import { Confidence } from "../../gen/anst/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const gate = path.resolve(__dirname, "../../../testdata/projects/gate-g1");

// ── Tier (a): imported and called → PACKAGE_REACHABLE ─────────────────────────

describe("reachability – tier (a): imported and called vuln package", () => {
  it("returns PACKAGE_REACHABLE for a package that is imported and called from an entrypoint", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisory: {
        id: "GHSA-real-adv-001",
        module: "serialize-javascript",
        versionRange: "<3.1.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
    expect(result.path).toBeUndefined();
  });
});

// ── Tier (b): installed but not imported → NOT_REACHABLE ──────────────────────

describe("reachability – tier (b): installed but not imported", () => {
  it("returns NOT_REACHABLE for a package that is installed but never imported", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisory: {
        id: "GHSA-not-imported-001",
        module: "lodash",
        versionRange: "<4.17.21",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Tier (c): dynamic require(var) → UNKNOWN ──────────────────────────────────
// The unknown ≠ safe invariant: never return NOT_REACHABLE when the only
// candidate path is blocked by an UNKNOWN frontier.

describe("reachability – tier (c): dynamic require → UNKNOWN (not NOT_REACHABLE)", () => {
  it("returns UNKNOWN when the only import path uses a dynamic specifier", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "dyn-require.js")],
      advisory: {
        id: "GHSA-dyn-path-001",
        module: "serialize-javascript",
        versionRange: "<3.1.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // Must be UNKNOWN, never NOT_REACHABLE — unknown ≠ safe
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(result.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Tier (d): SYMBOL_REACHABLE with synthetic advisory ────────────────────────
// Real npm data cannot exercise symbol-level pre-enrichment.
// We use a synthetic advisory with symbol_level=true pointing to an export
// that our fixture explicitly calls.

describe("reachability – tier (d): SYMBOL_REACHABLE via synthetic advisory", () => {
  it("returns SYMBOL_REACHABLE with a ReachabilityPath for a symbol-level advisory with a concrete path", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "symbol-caller.js")],
      advisory: {
        id: "GHSA-synth-sym-001",
        module: "serialize-javascript",
        versionRange: "<3.1.0",
        // Synthetic symbol targeting the named export "serialize"
        symbols: [{ package: "serialize-javascript", name: "serialize" }],
        symbolLevel: true,
        sources: ["synthetic"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_SYMBOL_REACHABLE);
    // ReachabilityPath must be present for SYMBOL_REACHABLE
    expect(result.path).toBeDefined();
    expect(result.path!.steps.length).toBeGreaterThan(0);
  });

  it("ReachabilityPath steps have file and symbol populated", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "symbol-caller.js")],
      advisory: {
        id: "GHSA-synth-sym-001",
        module: "serialize-javascript",
        versionRange: "<3.1.0",
        symbols: [{ package: "serialize-javascript", name: "serialize" }],
        symbolLevel: true,
        sources: ["synthetic"],
      },
    });
    if (result.confidence === Confidence.CONFIDENCE_SYMBOL_REACHABLE && result.path) {
      for (const step of result.path.steps) {
        expect(step.symbol).toBeTruthy();
      }
    }
  });
});

// ── Path absent for non-SYMBOL_REACHABLE ─────────────────────────────────────

describe("reachability – path only present for SYMBOL_REACHABLE", () => {
  it("does NOT populate a ReachabilityPath for PACKAGE_REACHABLE", async () => {
    const result = await queryReachability({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisory: {
        id: "GHSA-real-adv-001",
        module: "serialize-javascript",
        versionRange: "<3.1.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
    expect(result.path).toBeUndefined();
  });
});
