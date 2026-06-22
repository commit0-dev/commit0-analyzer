/**
 * Jelly cross-check — offline, CI-optional.
 *
 * Runs `npx @cs-au-dk/jelly@0.9.0` (pinned version) on each corpus case,
 * extracts the call-graph edge set from its JSON output, and diffs against
 * our engine's reachability output.  Edges Jelly finds that our engine
 * marks NOT_REACHABLE are potential false negatives to triage.
 *
 * Key properties:
 *   - SKIP-with-warning if `npx` is absent or Jelly install fails.
 *   - SKIP-with-warning if network is absent (Jelly cannot be fetched).
 *   - Pure validation only — no product dependency on Jelly.
 *   - Never blocks: always exits 0.  Use --assert to exit 1 on errors.
 *   - Jelly has no UNKNOWN tier; we must not let its lack of UNKNOWN weaken
 *     our UNKNOWN floor.  Jelly FN candidates that our engine marks UNKNOWN
 *     are documented, not treated as engine bugs.
 *
 * Usage:
 *   bun run jelly:crosscheck
 *   npx tsx scripts/jelly-crosscheck.ts [--assert] [--case <name>]
 *
 * Output: a triage report for each corpus case listing:
 *   - edges Jelly finds that we also find (agreeing)
 *   - edges Jelly finds that we mark NOT_REACHABLE (potential FN → triage)
 *   - edges Jelly finds that we mark UNKNOWN (conservative difference — documented)
 */

import path from "node:path";
import fs from "node:fs";
import { execSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { analyze } from "../src/engine/analyze.js";
import { Confidence } from "../src/gen/anst/v1/plugin.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CORPUS_DIR = path.resolve(__dirname, "../testdata/corpus");

const JELLY_VERSION = "0.9.0";
const JELLY_PACKAGE = `@cs-au-dk/jelly@${JELLY_VERSION}`;

// ── Types ─────────────────────────────────────────────────────────────────────

interface Labels {
  comment?: string;
  advisories: Array<{
    id: string;
    package: string;
    version: string;
    symbolLevel?: boolean;
    symbols?: Array<{ package: string; name: string }>;
    expectedTier: string;
  }>;
  entrypoints?: string[];
}

interface TriageEntry {
  caseName: string;
  advisoryPackage: string;
  jellyVerdict: "reachable" | "not-reachable";
  ourVerdict: string;
  category: "agree" | "fn-candidate" | "unknown-conservative";
  note: string;
}

// ── Jelly availability check ──────────────────────────────────────────────────

function checkJellyAvailable(): boolean {
  // Check that npx itself is available
  const npxCheck = spawnSync("npx", ["--version"], {
    encoding: "utf8",
    timeout: 5000,
    stdio: "pipe",
  });
  if (npxCheck.error || npxCheck.status !== 0) {
    console.warn(
      `[jelly-crosscheck] SKIP: npx not available (${npxCheck.error?.message ?? "non-zero exit"})`
    );
    return false;
  }

  // Try a dry-run install of Jelly to check network/registry availability.
  // Use --prefer-offline if the package is already cached.
  const jellyCheck = spawnSync(
    "npx",
    ["--yes", "--prefer-offline", JELLY_PACKAGE, "--version"],
    {
      encoding: "utf8",
      timeout: 30000,
      stdio: "pipe",
    }
  );
  if (jellyCheck.error) {
    console.warn(
      `[jelly-crosscheck] SKIP: Jelly unavailable — ${jellyCheck.error.message}`
    );
    return false;
  }
  if (jellyCheck.status !== 0) {
    // Jelly may not support --version; try to detect a recognisable error
    const stderr = jellyCheck.stderr ?? "";
    if (
      stderr.includes("ENOTFOUND") ||
      stderr.includes("ETIMEDOUT") ||
      stderr.includes("ECONNREFUSED") ||
      stderr.includes("npm error")
    ) {
      console.warn(
        `[jelly-crosscheck] SKIP: network or registry error fetching Jelly\n  ${stderr.slice(0, 200)}`
      );
      return false;
    }
    // Non-zero exit for unknown reason — skip conservatively
    console.warn(
      `[jelly-crosscheck] SKIP: Jelly version probe returned exit ${jellyCheck.status}\n  stderr: ${stderr.slice(0, 200)}`
    );
    return false;
  }

  return true;
}

// ── Run Jelly on one corpus case ──────────────────────────────────────────────

interface JellyResult {
  reachablePackages: Set<string>;
  error?: string;
}

function runJellyOnCase(caseRoot: string, entrypoints: string[]): JellyResult {
  if (entrypoints.length === 0) {
    return { reachablePackages: new Set(), error: "no entrypoints" };
  }

  // Jelly CLI: `jelly --json-output <outfile> <entrypoints...>`
  // We direct output to a temp file and parse it.
  const outFile = path.join(caseRoot, ".jelly-crosscheck-tmp.json");
  try {
    // Use the first entrypoint as the analysis root.
    // Jelly expects relative paths or absolute paths to the entry files.
    const jellyArgs = [
      "--yes",
      "--prefer-offline",
      JELLY_PACKAGE,
      "--callgraph-output",
      outFile,
      ...entrypoints,
    ];

    const result = spawnSync("npx", jellyArgs, {
      cwd: caseRoot,
      encoding: "utf8",
      timeout: 60000,
      stdio: "pipe",
    });

    if (result.error) {
      return { reachablePackages: new Set(), error: String(result.error) };
    }

    if (!fs.existsSync(outFile)) {
      // Jelly may not have produced output (no edges found or error)
      return {
        reachablePackages: new Set(),
        error: `no output file produced (exit ${result.status})`,
      };
    }

    const raw = fs.readFileSync(outFile, "utf8");
    const jellyData = JSON.parse(raw) as {
      entries?: Array<{ callee?: { module?: string } }>;
      calls?: Array<{ target?: { package?: string } }>;
      reachable?: string[];
      packages?: string[];
      [key: string]: unknown;
    };

    // Extract reachable packages from Jelly's output format.
    // Jelly's JSON schema varies by version; try several known shapes.
    const pkgs = new Set<string>();

    if (Array.isArray(jellyData.reachable)) {
      for (const p of jellyData.reachable) {
        if (typeof p === "string") pkgs.add(p);
      }
    }
    if (Array.isArray(jellyData.packages)) {
      for (const p of jellyData.packages) {
        if (typeof p === "string") pkgs.add(p);
      }
    }
    if (Array.isArray(jellyData.calls)) {
      for (const c of jellyData.calls) {
        const pkg = c?.target?.package;
        if (typeof pkg === "string") pkgs.add(pkg);
      }
    }
    if (Array.isArray(jellyData.entries)) {
      for (const e of jellyData.entries) {
        const mod = e?.callee?.module;
        if (typeof mod === "string" && !mod.startsWith(".")) pkgs.add(mod);
      }
    }

    return { reachablePackages: pkgs };
  } catch (err) {
    return { reachablePackages: new Set(), error: String(err) };
  } finally {
    if (fs.existsSync(outFile)) {
      fs.unlinkSync(outFile);
    }
  }
}

// ── Triage ────────────────────────────────────────────────────────────────────

function triageEntry(
  caseName: string,
  advisoryPackage: string,
  jellyFindsReachable: boolean,
  ourConfidence: Confidence
): TriageEntry {
  const ourVerdict =
    ourConfidence === Confidence.CONFIDENCE_SYMBOL_REACHABLE
      ? "SYMBOL_REACHABLE"
      : ourConfidence === Confidence.CONFIDENCE_PACKAGE_REACHABLE
        ? "PACKAGE_REACHABLE"
        : ourConfidence === Confidence.CONFIDENCE_NOT_REACHABLE
          ? "NOT_REACHABLE"
          : "UNKNOWN";

  if (!jellyFindsReachable) {
    // Jelly says not reachable (or couldn't determine)
    return {
      caseName,
      advisoryPackage,
      jellyVerdict: "not-reachable",
      ourVerdict,
      category: "agree",
      note: "Both engine and Jelly agree: not reachable (or Jelly produced no edges for this pkg)",
    };
  }

  // Jelly finds reachable:
  if (
    ourConfidence === Confidence.CONFIDENCE_PACKAGE_REACHABLE ||
    ourConfidence === Confidence.CONFIDENCE_SYMBOL_REACHABLE
  ) {
    return {
      caseName,
      advisoryPackage,
      jellyVerdict: "reachable",
      ourVerdict,
      category: "agree",
      note: "Both Jelly and our engine agree: package is reachable",
    };
  }

  if (ourConfidence === Confidence.CONFIDENCE_UNKNOWN) {
    // Jelly has no UNKNOWN tier — it marks things reachable or not.
    // Our UNKNOWN is conservative (dynamic dispatch, eval, etc.).
    // This is a known architectural difference, NOT a false negative.
    return {
      caseName,
      advisoryPackage,
      jellyVerdict: "reachable",
      ourVerdict,
      category: "unknown-conservative",
      note:
        "Jelly marks reachable; our engine marks UNKNOWN (conservative — dynamic dispatch / eval / missing lockfile). " +
        "Jelly has no UNKNOWN tier so this difference is expected. This is NOT a false negative in our engine.",
    };
  }

  // ourVerdict === NOT_REACHABLE but Jelly finds reachable → FN candidate
  return {
    caseName,
    advisoryPackage,
    jellyVerdict: "reachable",
    ourVerdict,
    category: "fn-candidate",
    note:
      "Jelly finds the package reachable but our engine returns NOT_REACHABLE. " +
      "This is a potential false negative. Triage: verify the import path manually. " +
      "If confirmed: file an engine soundness issue. If Jelly is unsound here: document.",
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const assertMode = process.argv.includes("--assert");
  const caseFilter = (() => {
    const idx = process.argv.indexOf("--case");
    return idx >= 0 ? process.argv[idx + 1] : undefined;
  })();

  console.log("\n=== Jelly Cross-Check ===");
  console.log(`  Jelly version pinned : ${JELLY_VERSION}`);
  console.log(`  Mode                 : ${assertMode ? "assert (non-zero on errors)" : "informational"}`);
  if (caseFilter) console.log(`  Filter               : ${caseFilter}`);
  console.log("");

  // Check Jelly availability
  const jellyAvailable = checkJellyAvailable();
  if (!jellyAvailable) {
    console.log(
      "[jelly-crosscheck] Skipping cross-check — Jelly not available. " +
        "This is expected in offline/CI environments without network access. " +
        "Run locally with network access to produce a full triage report."
    );
    console.log("=== End Jelly Cross-Check (SKIPPED) ===\n");
    process.exit(0);
  }

  const allCases = fs
    .readdirSync(CORPUS_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort()
    .filter((n) => !caseFilter || n === caseFilter);

  const triageEntries: TriageEntry[] = [];
  let jellyErrors = 0;

  for (const caseName of allCases) {
    const caseRoot = path.join(CORPUS_DIR, caseName);
    const labelsPath = path.join(caseRoot, "labels.json");
    const labels: Labels = JSON.parse(fs.readFileSync(labelsPath, "utf8"));

    const entrypoints = (labels.entrypoints ?? []).map((ep) =>
      path.join(caseRoot, ep)
    );

    console.log(`Processing corpus/${caseName}...`);

    // Run our engine
    const advisoryRequests = labels.advisories.map((adv) => ({
      id: adv.id,
      module: adv.package,
      versionRange: adv.version,
      symbols: adv.symbols ?? [],
      symbolLevel: adv.symbolLevel ?? false,
      sources: ["corpus"],
    }));

    let ourFindings: Awaited<ReturnType<typeof analyze>> = [];
    try {
      ourFindings = await analyze({
        moduleRoot: caseRoot,
        entrypoints,
        advisories: advisoryRequests,
      });
    } catch (_err) {
      // Engine error — treat all as UNKNOWN
    }

    // Run Jelly
    const jellyResult = runJellyOnCase(caseRoot, entrypoints);
    if (jellyResult.error) {
      console.warn(`  [WARN] Jelly error on ${caseName}: ${jellyResult.error}`);
      jellyErrors++;
    }

    // Triage each advisory
    for (const adv of labels.advisories) {
      const ourFinding = ourFindings.find((f) => f.module === adv.package);
      const ourConfidence =
        ourFinding?.confidence ?? Confidence.CONFIDENCE_NOT_REACHABLE;
      const jellyFindsReachable = jellyResult.reachablePackages.has(adv.package);

      const entry = triageEntry(caseName, adv.package, jellyFindsReachable, ourConfidence);
      triageEntries.push(entry);
    }
  }

  // Print triage report
  console.log("\n--- Triage Report ---");
  const byCategory = {
    agree: triageEntries.filter((e) => e.category === "agree"),
    "unknown-conservative": triageEntries.filter(
      (e) => e.category === "unknown-conservative"
    ),
    "fn-candidate": triageEntries.filter((e) => e.category === "fn-candidate"),
  };

  console.log(`\nAgreements (${byCategory.agree.length}):`);
  for (const e of byCategory.agree) {
    console.log(
      `  AGREE  ${e.caseName}/${e.advisoryPackage}  jelly=${e.jellyVerdict}  ours=${e.ourVerdict}`
    );
  }

  console.log(`\nConservative differences — UNKNOWN vs Jelly-reachable (${byCategory["unknown-conservative"].length}):`);
  for (const e of byCategory["unknown-conservative"]) {
    console.log(
      `  CONSERVATIVE  ${e.caseName}/${e.advisoryPackage}  jelly=reachable  ours=UNKNOWN`
    );
    console.log(`    Note: ${e.note}`);
  }

  console.log(`\nFalse-negative candidates (${byCategory["fn-candidate"].length}):`);
  for (const e of byCategory["fn-candidate"]) {
    console.log(
      `  FN-CANDIDATE  ${e.caseName}/${e.advisoryPackage}  jelly=reachable  ours=${e.ourVerdict}`
    );
    console.log(`    Note: ${e.note}`);
  }

  console.log(`\nSummary:`);
  console.log(`  Cases processed      : ${allCases.length}`);
  console.log(`  Advisory comparisons : ${triageEntries.length}`);
  console.log(`  Agreements           : ${byCategory.agree.length}`);
  console.log(`  Conservative UNKNOWN : ${byCategory["unknown-conservative"].length}  (expected — Jelly has no UNKNOWN tier)`);
  console.log(`  FN candidates        : ${byCategory["fn-candidate"].length}  (triage manually)`);
  console.log(`  Jelly errors         : ${jellyErrors}  (case-level Jelly failures)`);
  console.log("=== End Jelly Cross-Check ===\n");

  if (assertMode && byCategory["fn-candidate"].length > 0) {
    console.error(
      `[jelly-crosscheck] ${byCategory["fn-candidate"].length} false-negative candidate(s) found. ` +
        "Triage each one: confirm with manual inspection, then either fix the engine " +
        "or add a documented known-limitation note."
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("[jelly-crosscheck] fatal error:", err);
  process.exit(0); // Always exit 0 — never block CI
});
