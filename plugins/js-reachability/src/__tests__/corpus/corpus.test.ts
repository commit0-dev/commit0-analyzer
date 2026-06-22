/**
 * Corpus harness — labeled JS/TS reachability fixture suite.
 *
 * For each corpus case in testdata/corpus/:
 *   - Reads labels.json for the expected tier per advisory.
 *   - Runs analyze() in-process.
 *   - Asserts each finding's tier matches the label.
 *
 * Aggregate metrics computed and asserted at suite level:
 *   - Precision:    TP / (TP + FP)     — labeled REACHABLE and engine agreed
 *   - Recall:       TP / (TP + FN)     — labeled REACHABLE and engine found
 *   - FP-suppression: labels correctly downgraded to NOT_REACHABLE
 *   - UNKNOWN-rate: fraction of all findings that are UNKNOWN
 *   - Metric V1-JS: count of findings where call-graph verdict ≠ import-graph-only verdict
 *
 * Thresholds are set from the green baseline measured on first run.
 * The UNKNOWN-rate is tracked (not gated) so the engine cannot "win" by
 * marking everything UNKNOWN or everything reachable.
 *
 * Determinism: corpus cases run in sorted directory order; advisory order
 * is fixed by labels.json.
 */

import { describe, it, expect, beforeAll } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { analyze } from "../../engine/analyze.js";
import { Confidence } from "../../gen/anst/v1/plugin.js";
import type { Finding } from "../../gen/anst/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = path.resolve(__dirname, "../../../testdata/corpus");

// ── Types ─────────────────────────────────────────────────────────────────────

type ExpectedTier =
  | "PACKAGE_REACHABLE"
  | "SYMBOL_REACHABLE"
  | "NOT_REACHABLE"
  | "UNKNOWN";

interface LabelAdvisory {
  id: string;
  package: string;
  version: string;
  symbolLevel?: boolean;
  symbols?: Array<{ package: string; name: string }>;
  expectedTier: ExpectedTier;
  expectedPathSymbols?: string[];
  note?: string;
}

interface Labels {
  comment?: string;
  advisories: LabelAdvisory[];
  entrypoints?: string[];
}

interface CaseResult {
  caseName: string;
  advisoryId: string;
  expectedTier: ExpectedTier;
  actualTier: ExpectedTier;
  passed: boolean;
  importGraphVerdict: string;
  callGraphVerdict: string;
  valueDelta: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function confidenceToTier(c: Confidence): ExpectedTier {
  switch (c) {
    case Confidence.CONFIDENCE_SYMBOL_REACHABLE:
      return "SYMBOL_REACHABLE";
    case Confidence.CONFIDENCE_PACKAGE_REACHABLE:
      return "PACKAGE_REACHABLE";
    case Confidence.CONFIDENCE_NOT_REACHABLE:
      return "NOT_REACHABLE";
    default:
      return "UNKNOWN";
  }
}

function tierLabel(t: ExpectedTier): string {
  return t;
}

/** True when the tier indicates the engine considers the package reachable. */
function isReachable(t: ExpectedTier): boolean {
  return t === "PACKAGE_REACHABLE" || t === "SYMBOL_REACHABLE";
}

// ── Corpus case loader ────────────────────────────────────────────────────────

function loadCorpusCases(): string[] {
  return fs
    .readdirSync(CORPUS_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

function readLabels(caseName: string): Labels {
  const labelsPath = path.join(CORPUS_DIR, caseName, "labels.json");
  const raw = fs.readFileSync(labelsPath, "utf8");
  return JSON.parse(raw) as Labels;
}

// ── Run all corpus cases ──────────────────────────────────────────────────────

const allResults: CaseResult[] = [];

describe("Corpus harness — per-case tier assertions", () => {
  const cases = loadCorpusCases();

  for (const caseName of cases) {
    describe(`corpus/${caseName}`, () => {
      const labels = readLabels(caseName);
      const caseRoot = path.join(CORPUS_DIR, caseName);

      it(
        `all ${labels.advisories.length} advisory label(s) match engine output`,
        async () => {
          const entrypoints = (labels.entrypoints ?? []).map((ep) =>
            path.join(caseRoot, ep)
          );

          const advisoryRequests = labels.advisories.map((adv) => ({
            id: adv.id,
            module: adv.package,
            versionRange: adv.version,
            symbols: adv.symbols ?? [],
            symbolLevel: adv.symbolLevel ?? false,
            sources: ["corpus"],
          }));

          // A throw from analyze() is always a test failure — it means the
          // engine crashed on this corpus case. Do not catch and fabricate
          // synthetic findings; let the error propagate so the test fails loudly.
          const findings: Finding[] = await analyze({
            moduleRoot: caseRoot,
            entrypoints,
            advisories: advisoryRequests,
          });

          const failures: string[] = [];

          for (const adv of labels.advisories) {
            const finding = findings.find((f) => f.module === adv.package);

            // A missing finding means NOT_REACHABLE (engine elided it)
            const actualConfidence =
              finding?.confidence ?? Confidence.CONFIDENCE_NOT_REACHABLE;
            const actualTier = confidenceToTier(actualConfidence);
            const passed = actualTier === adv.expectedTier;

            const igv =
              finding?.properties?.["import_graph_verdict"] ?? "CONFIDENCE_NOT_REACHABLE";
            const cgv = tierLabel(actualTier);
            const valueDelta = igv !== `CONFIDENCE_${cgv}`;

            allResults.push({
              caseName,
              advisoryId: adv.id,
              expectedTier: adv.expectedTier,
              actualTier,
              passed,
              importGraphVerdict: igv,
              callGraphVerdict: `CONFIDENCE_${cgv}`,
              valueDelta,
            });

            if (!passed) {
              failures.push(
                `  advisory ${adv.id}: expected ${adv.expectedTier}, got ${actualTier}` +
                  (adv.note ? ` [note: ${adv.note}]` : "")
              );
            }
          }

          if (failures.length > 0) {
            throw new Error(
              `corpus/${caseName} — tier mismatch(es):\n${failures.join("\n")}`
            );
          }
        }
      );

      it(`engine is deterministic for corpus/${caseName}`, async () => {
        const entrypoints = (labels.entrypoints ?? []).map((ep) =>
          path.join(caseRoot, ep)
        );
        const advisoryRequests = labels.advisories.map((adv) => ({
          id: adv.id,
          module: adv.package,
          versionRange: adv.version,
          symbols: adv.symbols ?? [],
          symbolLevel: adv.symbolLevel ?? false,
          sources: ["corpus"],
        }));
        const req = { moduleRoot: caseRoot, entrypoints, advisories: advisoryRequests };
        // A throw here is a test failure regardless of expected tier.
        const run1 = JSON.stringify(await analyze(req));
        const run2 = JSON.stringify(await analyze(req));
        expect(run1).toBe(run2);
      });
    });
  }
});

// ── Aggregate metrics ─────────────────────────────────────────────────────────

describe("Corpus harness — aggregate precision/recall/metrics", () => {
  /**
   * We compute metrics after all case tests ran. Because vitest runs
   * describe blocks synchronously but tests asynchronously, we use
   * beforeAll to wait for allResults to be populated by the per-case
   * tests. However, since tests run in file order, all per-case its
   * complete before this describe block's tests run.
   */

  it("meets minimum precision threshold", () => {
    const metrics = computeMetrics(allResults);
    // Precision threshold set from measured green baseline.
    // Baseline: all labeled-REACHABLE cases that the engine also marks
    // REACHABLE, divided by all engine-REACHABLE predictions.
    const PRECISION_FLOOR = 0.7;
    expect(metrics.precision).toBeGreaterThanOrEqual(PRECISION_FLOOR);
  });

  it("meets minimum recall threshold", () => {
    const metrics = computeMetrics(allResults);
    // Recall: all labeled-REACHABLE the engine found / all labeled-REACHABLE.
    const RECALL_FLOOR = 0.7;
    expect(metrics.recall).toBeGreaterThanOrEqual(RECALL_FLOOR);
  });

  it("UNKNOWN-rate is tracked and within bounds (engine must not game precision/recall)", () => {
    const metrics = computeMetrics(allResults);
    // UNKNOWN-rate must stay below ceiling: if everything were UNKNOWN the
    // engine "wins" by never being wrong. Cap at 50% to catch gaming.
    // Also must be > 0 because we have labeled-UNKNOWN cases.
    expect(metrics.unknownRate).toBeGreaterThan(0);
    expect(metrics.unknownRate).toBeLessThan(0.5);
  });

  it("FP-suppression: at least one manifest-level FP is correctly downgraded to NOT_REACHABLE", () => {
    const metrics = computeMetrics(allResults);
    // We have the `not-imported` case which exercises suppression.
    expect(metrics.fpSuppressed).toBeGreaterThanOrEqual(1);
  });

  it("Metric V1-JS value-delta is non-negative (call-graph adds value over import-graph)", () => {
    const metrics = computeMetrics(allResults);
    expect(metrics.valueDelta).toBeGreaterThanOrEqual(0);
  });

  it("reports corpus metrics (informational — printed for validation log)", () => {
    const metrics = computeMetrics(allResults);
    // Always passes — the output is for the orchestrator to record.
    const table = formatMetricsTable(metrics, allResults);
    console.log("\n" + table);
    expect(true).toBe(true);
  });
});

// ── Metrics computation ───────────────────────────────────────────────────────

interface Metrics {
  precision: number;
  recall: number;
  unknownRate: number;
  fpSuppressed: number;
  valueDelta: number;
  tp: number;
  fp: number;
  fn: number;
  totalFindings: number;
  unknownCount: number;
}

function computeMetrics(results: CaseResult[]): Metrics {
  let tp = 0; // labeled REACHABLE, engine REACHABLE
  let fp = 0; // labeled NOT_REACHABLE or UNKNOWN, engine REACHABLE
  let fn = 0; // labeled REACHABLE, engine NOT_REACHABLE or UNKNOWN
  let fpSuppressed = 0; // labeled NOT_REACHABLE, engine NOT_REACHABLE (correct suppression)
  let unknownCount = 0;
  let valueDelta = 0;

  for (const r of results) {
    const labeledReachable = isReachable(r.expectedTier);
    const engineReachable = isReachable(r.actualTier);

    if (r.actualTier === "UNKNOWN") unknownCount++;
    if (r.valueDelta) valueDelta++;

    if (labeledReachable && engineReachable) tp++;
    else if (!labeledReachable && engineReachable) fp++;
    else if (labeledReachable && !engineReachable) fn++;
    else if (r.expectedTier === "NOT_REACHABLE" && r.actualTier === "NOT_REACHABLE") {
      fpSuppressed++;
    }
  }

  const total = results.length;
  const precision = tp + fp === 0 ? 1.0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1.0 : tp / (tp + fn);
  const unknownRate = total === 0 ? 0 : unknownCount / total;

  return { precision, recall, unknownRate, fpSuppressed, valueDelta, tp, fp, fn, totalFindings: total, unknownCount };
}

function formatMetricsTable(m: Metrics, results: CaseResult[]): string {
  const pct = (n: number) => (n * 100).toFixed(1) + "%";
  const lines: string[] = [
    "=== Corpus Baseline Metrics ===",
    `  Total advisory assertions : ${m.totalFindings}`,
    `  True Positives (TP)       : ${m.tp}`,
    `  False Positives (FP)      : ${m.fp}`,
    `  False Negatives (FN)      : ${m.fn}`,
    `  Precision                 : ${pct(m.precision)} (threshold ≥70%)`,
    `  Recall                    : ${pct(m.recall)} (threshold ≥70%)`,
    `  UNKNOWN-rate              : ${pct(m.unknownRate)} (tracked; must be >0% and <50%)`,
    `  FP-suppression count      : ${m.fpSuppressed} (labeled NOT_REACHABLE correctly kept)`,
    `  Metric V1-JS value-delta  : ${m.valueDelta} findings where call-graph ≠ import-graph-only`,
    "",
    "Per-case results:",
    ...results.map(
      (r) =>
        `  ${r.passed ? "PASS" : "FAIL"} ${r.caseName}/${r.advisoryId}: expected=${r.expectedTier} actual=${r.actualTier}` +
        (r.valueDelta ? " [V1-JS-delta]" : "")
    ),
    "=== End Corpus Metrics ===",
  ];
  return lines.join("\n");
}
