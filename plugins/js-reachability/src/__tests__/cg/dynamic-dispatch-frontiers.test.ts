/**
 * Tests for M1: non-import dynamic dispatch constructs must emit UNKNOWN
 * frontiers so reachability yields CONFIDENCE_UNKNOWN rather than
 * CONFIDENCE_NOT_REACHABLE.
 *
 * Covered constructs:
 *   - eval(code) in a reachable first-party file
 *   - Computed member call obj[method]() in a reachable first-party file
 *   - Aliased require: const req = require; req(name)
 *
 * All tests run through the SHIPPED analyze() path.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../../engine/analyze.js";
import { buildCallGraph } from "../../cg/build.js";
import { Confidence } from "../../gen/anst/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const gate = path.resolve(__dirname, "../../../testdata/projects/gate-g1");

const serializeAdvisory = {
  id: "GHSA-h9rv-jmmf-4pgx",
  module: "serialize-javascript",
  versionRange: "<3.1.0",
  symbols: [] as Array<{ package: string; name: string }>,
  symbolLevel: false,
  sources: ["osv"],
};

// ── eval() + computed member call → UNKNOWN frontiers ────────────────────────

describe("M1 – eval() in reachable file emits UNKNOWN frontier", () => {
  it("buildCallGraph emits at least one UNKNOWN frontier for a file containing eval()", async () => {
    const cg = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "eval-dispatch.js")],
    });
    const hasEvalFrontier = cg.unknownFrontiers.some(
      (u) =>
        u.fromFile === path.join(gate, "src", "eval-dispatch.js") &&
        (u.reason === "dynamic-dispatch" || u.detail?.includes("eval"))
    );
    expect(hasEvalFrontier).toBe(true);
  });

  it("analyze() returns CONFIDENCE_UNKNOWN for serialize-javascript when entrypoint contains eval()", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "eval-dispatch.js")],
      advisories: [{ ...serializeAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(f!.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Aliased require → UNKNOWN frontier ───────────────────────────────────────

describe("M1 – aliased require in reachable file emits UNKNOWN frontier", () => {
  it("buildCallGraph emits at least one UNKNOWN frontier for a file using aliased require", async () => {
    const cg = await buildCallGraph({
      projectRoot: gate,
      entrypoints: [path.join(gate, "src", "aliased-require.js")],
    });
    const hasAliasedFrontier = cg.unknownFrontiers.some(
      (u) =>
        u.fromFile === path.join(gate, "src", "aliased-require.js")
    );
    expect(hasAliasedFrontier).toBe(true);
  });

  it("analyze() returns CONFIDENCE_UNKNOWN for serialize-javascript when entrypoint uses aliased require", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "aliased-require.js")],
      advisories: [{ ...serializeAdvisory }],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(f!.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});
