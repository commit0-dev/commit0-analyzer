/**
 * Gate G1-JS: standalone shim test.
 *
 * Proves that the engine yields PACKAGE_REACHABLE for a real npm advisory
 * (serialize-javascript, GHSA-h9rv-jmmf-4pgx) via the analyze() engine
 * function (same code path as --analyze shim, no gRPC, no host).
 *
 * Also proves determinism: two runs produce byte-identical Finding JSON.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../../engine/analyze.js";
import { Confidence } from "../../gen/commit0/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const gate = path.resolve(__dirname, "../../../testdata/projects/gate-g1");

const gateRequest = {
  moduleRoot: gate,
  entrypoints: [] as string[],
  advisories: [
    {
      id: "GHSA-h9rv-jmmf-4pgx",
      module: "serialize-javascript",
      versionRange: "<3.1.0",
      symbols: [],
      symbolLevel: false,
      sources: ["osv"],
    },
  ],
};

// ── Gate G1-JS: PACKAGE_REACHABLE for real advisory ──────────────────────────

describe("Gate G1-JS – real npm advisory yields PACKAGE_REACHABLE via shim", () => {
  it("produces a PACKAGE_REACHABLE Finding for serialize-javascript (GHSA-h9rv-jmmf-4pgx)", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });

  it("stamps algorithm=conservative-flow on the Finding", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(f!.properties["algorithm"]).toBe("conservative-flow");
  });

  it("stamps language=js on the Finding", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    expect(["js", "ts"]).toContain(f!.language);
  });

  it("sets advisory.id correctly", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f!.advisory?.id).toBe("GHSA-h9rv-jmmf-4pgx");
  });

  it("does NOT populate a path for PACKAGE_REACHABLE", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f!.path).toBeUndefined();
  });
});

// ── Determinism: two runs produce byte-identical Finding JSON ─────────────────

describe("Gate G1-JS – determinism", () => {
  it("produces byte-identical Finding JSON across two consecutive runs", async () => {
    const findings1 = await analyze(gateRequest);
    const findings2 = await analyze(gateRequest);
    const json1 = JSON.stringify(findings1);
    const json2 = JSON.stringify(findings2);
    expect(json1).toBe(json2);
  });
});

// ── Tier (b): installed-not-imported advisory → NOT_REACHABLE ─────────────────

describe("Gate G1-JS – installed-not-imported package yields NOT_REACHABLE", () => {
  it("returns NOT_REACHABLE for lodash which is installed but never imported", async () => {
    const findings = await analyze({
      ...gateRequest,
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
    // Either NOT_REACHABLE (declared but not imported) or no finding at all
    if (f) {
      expect(f.confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
    }
    // No finding is also acceptable — means the engine skipped it (not imported)
  });
});

// ── Metric V1-JS: import-graph-only verdict exposed ──────────────────────────

describe("Gate G1-JS – Metric V1-JS import-graph verdict exposed", () => {
  it("exposes an import_graph_verdict property on the Finding for P6 comparison", async () => {
    const findings = await analyze(gateRequest);
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    // The property must be one of the known confidence labels
    const v = f!.properties["import_graph_verdict"];
    expect(v).toBeDefined();
    expect([
      "CONFIDENCE_PACKAGE_REACHABLE",
      "CONFIDENCE_NOT_REACHABLE",
      "CONFIDENCE_UNKNOWN",
      "CONFIDENCE_SYMBOL_REACHABLE",
    ]).toContain(v);
  });
});
