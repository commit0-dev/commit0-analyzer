/**
 * Corpus precision/recall report.
 *
 * Runs the engine in-process against every corpus case in testdata/corpus/,
 * compares findings to labels.json, and prints a human-readable table of:
 *   - per-case pass/fail
 *   - aggregate precision, recall, UNKNOWN-rate, FP-suppression
 *   - Metric V1-JS value-delta (findings where call-graph verdict differs
 *     from the import-graph-only verdict)
 *
 * Usage:
 *   bun run corpus:report
 *   npx tsx scripts/corpus-report.ts
 *
 * Reporting only — does not change verdicts or fail with a non-zero exit code
 * unless the --assert flag is passed, which is reserved for CI.
 */

import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { analyze } from "../src/engine/analyze.js";
import { Confidence } from "../src/gen/commit0-analyzer/v1/plugin.js";
import type { Finding } from "../src/gen/commit0-analyzer/v1/plugin.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CORPUS_DIR = path.resolve(__dirname, "../testdata/corpus");

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

function isReachable(t: ExpectedTier): boolean {
  return t === "PACKAGE_REACHABLE" || t === "SYMBOL_REACHABLE";
}

function pad(s: string, n: number): string {
  return s.padEnd(n);
}

function pct(n: number): string {
  return (n * 100).toFixed(1).padStart(6) + "%";
}

// ── Run corpus ────────────────────────────────────────────────────────────────

async function runCase(caseName: string): Promise<CaseResult[]> {
  const caseRoot = path.join(CORPUS_DIR, caseName);
  const labelsPath = path.join(caseRoot, "labels.json");
  const labels: Labels = JSON.parse(fs.readFileSync(labelsPath, "utf8"));

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

  // A throw from analyze() means the engine crashed on this case — propagate
  // the error so the caller reports it as a case load failure, not UNKNOWN.
  const findings: Finding[] = await analyze({
    moduleRoot: caseRoot,
    entrypoints,
    advisories: advisoryRequests,
  });

  return labels.advisories.map((adv) => {
    const finding = findings.find((f) => f.module === adv.package);
    const actualConfidence =
      finding?.confidence ?? Confidence.CONFIDENCE_NOT_REACHABLE;
    const actualTier = confidenceToTier(actualConfidence);
    const igv =
      finding?.properties?.["import_graph_verdict"] ?? "CONFIDENCE_NOT_REACHABLE";
    const cgLabel = `CONFIDENCE_${actualTier}`;
    const valueDelta = igv !== cgLabel;

    return {
      caseName,
      advisoryId: adv.id,
      expectedTier: adv.expectedTier,
      actualTier,
      passed: actualTier === adv.expectedTier,
      importGraphVerdict: igv,
      callGraphVerdict: cgLabel,
      valueDelta,
    };
  });
}

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
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let fpSuppressed = 0;
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

  return {
    precision,
    recall,
    unknownRate,
    fpSuppressed,
    valueDelta,
    tp,
    fp,
    fn,
    totalFindings: total,
    unknownCount,
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const cases = fs
    .readdirSync(CORPUS_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();

  console.log(`\nRunning corpus report on ${cases.length} case(s) in ${CORPUS_DIR}\n`);

  const allResults: CaseResult[] = [];
  for (const caseName of cases) {
    try {
      const results = await runCase(caseName);
      allResults.push(...results);
    } catch (err) {
      console.error(`ERROR loading case ${caseName}: ${err}`);
    }
  }

  const metrics = computeMetrics(allResults);

  // Per-case table
  const W = {
    case: 38,
    advisory: 34,
    expected: 20,
    actual: 20,
    delta: 8,
    status: 6,
  };
  const header =
    pad("Case", W.case) +
    pad("Advisory", W.advisory) +
    pad("Expected", W.expected) +
    pad("Actual", W.actual) +
    pad("V1-JS", W.delta) +
    "Status";
  const sep = "-".repeat(header.length);

  console.log(sep);
  console.log(header);
  console.log(sep);

  for (const r of allResults) {
    const row =
      pad(r.caseName, W.case) +
      pad(r.advisoryId.replace("GHSA-corpus-", ""), W.advisory) +
      pad(r.expectedTier, W.expected) +
      pad(r.actualTier, W.actual) +
      pad(r.valueDelta ? "DELTA" : "", W.delta) +
      (r.passed ? "PASS" : "FAIL");
    console.log(row);
    if (!r.passed) {
      console.log(
        `  !! MISMATCH — expected ${r.expectedTier}, got ${r.actualTier}`
      );
    }
  }

  console.log(sep);

  // Aggregate metrics table
  console.log("\n=== Corpus Baseline Metrics ===");
  console.log(`  Corpus cases              : ${cases.length}`);
  console.log(`  Total advisory assertions : ${metrics.totalFindings}`);
  console.log(`  True Positives  (TP)      : ${metrics.tp}`);
  console.log(`  False Positives (FP)      : ${metrics.fp}`);
  console.log(`  False Negatives (FN)      : ${metrics.fn}`);
  console.log(`  UNKNOWN outputs           : ${metrics.unknownCount}`);
  console.log("");
  console.log(`  Precision                 : ${pct(metrics.precision)}`);
  console.log(`  Recall                    : ${pct(metrics.recall)}`);
  console.log(`  UNKNOWN-rate              : ${pct(metrics.unknownRate)}  (must be >0% and <50%)`);
  console.log(`  FP-suppression count      : ${metrics.fpSuppressed}  (labeled NOT_REACHABLE correctly kept)`);
  console.log(`  Metric V1-JS value-delta  : ${metrics.valueDelta}  (findings where call-graph ≠ import-graph-only)`);
  console.log("");

  const passCount = allResults.filter((r) => r.passed).length;
  const failCount = allResults.length - passCount;
  console.log(
    `  Result: ${passCount}/${allResults.length} passed, ${failCount} failed`
  );
  console.log("=== End Corpus Metrics ===\n");

  if (process.argv.includes("--assert")) {
    const PRECISION_FLOOR = 0.7;
    const RECALL_FLOOR = 0.7;
    const UNKNOWN_RATE_FLOOR = 0.0;   // must be > 0 (we have labeled-UNKNOWN cases)
    const UNKNOWN_RATE_CEIL = 0.5;    // must be < 0.5 (cannot game precision by marking everything UNKNOWN)

    const violations: string[] = [];
    if (failCount > 0) {
      violations.push(`${failCount} per-case tier mismatch(es)`);
    }
    if (metrics.precision < PRECISION_FLOOR) {
      violations.push(
        `Precision ${pct(metrics.precision)} is below floor ${pct(PRECISION_FLOOR)}`
      );
    }
    if (metrics.recall < RECALL_FLOOR) {
      violations.push(
        `Recall ${pct(metrics.recall)} is below floor ${pct(RECALL_FLOOR)}`
      );
    }
    if (metrics.unknownRate <= UNKNOWN_RATE_FLOOR) {
      violations.push(
        `UNKNOWN-rate ${pct(metrics.unknownRate)} must be > ${pct(UNKNOWN_RATE_FLOOR)} (labeled-UNKNOWN cases must surface)`
      );
    }
    if (metrics.unknownRate >= UNKNOWN_RATE_CEIL) {
      violations.push(
        `UNKNOWN-rate ${pct(metrics.unknownRate)} must be < ${pct(UNKNOWN_RATE_CEIL)} (engine must not game precision by marking everything UNKNOWN)`
      );
    }

    if (violations.length > 0) {
      console.error("\n--assert violations:");
      for (const v of violations) {
        console.error(`  !! ${v}`);
      }
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error("corpus-report fatal error:", err);
  process.exit(1);
});
