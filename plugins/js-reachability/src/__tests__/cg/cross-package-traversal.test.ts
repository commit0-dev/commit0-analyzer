/**
 * Tests for cross-package call graph traversal (Phase 4).
 *
 * When a first-party file imports a third-party package whose entry has
 * source fidelity, the call graph traverses INTO that dep file and follows
 * ITS imports recursively (transitive deps). Packages with reduced/none
 * fidelity are UNKNOWN frontiers, never NOT_REACHABLE through them.
 *
 * Fixture: transitive-cross-pkg
 *   index.js → dep-a (source) → dep-b (source, "vulnerable")
 *   dep-a: static imports only (no dynamic require)
 *   dep-c: installed but never imported from any reachable file → NOT_REACHABLE
 *   dep-e: reduced fidelity (minified) → dep-f is UNKNOWN (one level)
 *   dep-f declares deep-vuln → deep-vuln is UNKNOWN (transitive closure, C3)
 *
 * Fixture: hoisted-dynamic-pkg
 *   index.js → dep-zero (source, no declared deps, require(var)) → C1
 *   index.js → dep-withdep (source, declares dep-b only, require(var)) → C2
 *   hoisted-vuln: installed at root, not declared by dep-zero or dep-withdep
 *   C1: dep-zero require(var) is a global frontier → hoisted-vuln = UNKNOWN
 *   C2: dep-withdep require(var) is a global frontier → hoisted-vuln = UNKNOWN
 */

import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCallGraph } from "../../cg/build.js";
import { queryReachability } from "../../reach/query.js";
import { Confidence } from "../../gen/anst/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(__dirname, "../../../testdata/projects");
const fixture = path.join(fixtures, "transitive-cross-pkg");
const hoistedFixture = path.join(fixtures, "hoisted-dynamic-pkg");

// ── Transitive reachability: dep-b reached THROUGH dep-a ─────────────────────

describe("cross-package traversal – transitive dep reachable through source dep", () => {
  it("dep-b is PACKAGE_REACHABLE when reached through dep-a from first-party code", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-b-001",
        module: "dep-b",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });

  it("dep-a itself is PACKAGE_REACHABLE (directly imported)", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-a-001",
        module: "dep-a",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});

// ── Not-imported dep: dep-c is installed but no reachable import site ─────────

describe("cross-package traversal – not-imported dep is NOT_REACHABLE", () => {
  it("dep-c is NOT_REACHABLE when installed but never imported from reachable code", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-c-001",
        module: "dep-c",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
    expect(result.confidence).not.toBe(Confidence.CONFIDENCE_UNKNOWN);
  });
});

// ── dep-d: installed but dep-a has no dynamic require → NOT_REACHABLE ────────
// dep-a in this fixture uses only STATIC imports (require("dep-b")).
// dep-d is installed (dep-a declares it) but is never imported from any
// reachable code. No dynamic frontier covers dep-d → NOT_REACHABLE.
// dep-c also stays NOT_REACHABLE for the same reason.

describe("cross-package traversal – dep-d not reachable (no dynamic dispatch in dep-a)", () => {
  it("dep-d is NOT_REACHABLE because dep-a has no dynamic require in this fixture", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-d-001",
        module: "dep-d",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // dep-a has only static imports; dep-d has no static import path and no
    // dynamic frontier covers it. dep-e's reduced closure only includes dep-f
    // and deep-vuln. dep-d is genuinely NOT_REACHABLE.
    expect(result.confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Reduced-fidelity dep boundary: dep-e itself is PACKAGE_REACHABLE ─────────
// dep-e is minified (reduced fidelity). It is directly imported by index.js
// so dep-e's advisory gets PACKAGE_REACHABLE.
// dep-f (a declared dep of dep-e, behind the reduced boundary) must be UNKNOWN:
// we cannot prove dep-e doesn't reach dep-f because we cannot analyze dep-e's
// minified code. unknown ≠ safe.

describe("cross-package traversal – reduced-fidelity dep", () => {
  it("dep-e is PACKAGE_REACHABLE (directly imported by first-party, reduced fidelity)", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-e-001",
        module: "dep-e",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });

  it("dep-f is UNKNOWN (behind the reduced-fidelity dep-e boundary, cannot prove unreachable)", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-f-001",
        module: "dep-f",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // dep-e is reachable but its code is unanalyzable (reduced fidelity).
    // dep-f is a declared dependency of dep-e, so dep-e could use it at runtime.
    // Cannot prove unreachable → UNKNOWN (not NOT_REACHABLE).
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
  });
});

// ── C3: Transitive reduced-fidelity closure must be UNKNOWN ──────────────────
// dep-e (reduced/minified) is reachable. dep-e declares dep-f. dep-f declares
// deep-vuln. The sound bound for "what dep-e could load at runtime" is the
// FULL TRANSITIVE closure of dep-e's declared deps (dep-f AND its deps).
// We cannot analyze dep-e's code, so dep-f AND deep-vuln must be UNKNOWN.
// unknown ≠ safe: the previous engine only looked one level deep (dep-e's
// direct declared deps = [dep-f]) and missed deep-vuln → false NOT_REACHABLE.

describe("cross-package traversal – C3: deep-vuln in transitive reduced-fidelity closure", () => {
  it("deep-vuln is UNKNOWN (two levels behind the reduced dep-e boundary, transitive closure)", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-deepvuln-001",
        module: "deep-vuln",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // dep-e is reachable but unanalyzable (reduced fidelity).
    // dep-f is declared by dep-e; deep-vuln is declared by dep-f.
    // Both are in the transitive closure of dep-e → both must be UNKNOWN.
    // The previous engine only checked dep-e's one-level declared deps (dep-f)
    // and returned NOT_REACHABLE for deep-vuln. This is the C3 false negative.
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
  });

  it("dep-f is still UNKNOWN (one level behind reduced dep-e, confirms existing behavior)", async () => {
    const result = await queryReachability({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
      advisory: {
        id: "GHSA-cross-pkg-f-002",
        module: "dep-f",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
  });
});

// ── C1: Dynamic dispatch in dep with ZERO declared deps → global frontier ─────
// dep-zero declares nothing and does require(var). With the scoped model
// (OLD engine), couldReach is empty → makeUnknownMarker drops it → frontier
// is ignored → hoisted-vuln = NOT_REACHABLE (false negative, C1).
// With the GLOBAL model (NEW engine), dep-zero's dynamic require is a global
// frontier → hoisted-vuln = UNKNOWN.
//
// Fixture: hoisted-dynamic-pkg
//   index.js → dep-zero (source, no deps, require(var))
//   index.js → dep-withdep (source, declares dep-b, require(var))
//   hoisted-vuln: installed at root, not declared by either dep

describe("cross-package traversal – C1: dep with zero declared deps + require(var) → global frontier", () => {
  it("hoisted-vuln is UNKNOWN when dep-zero (declares nothing) does require(var) [C1]", async () => {
    const result = await queryReachability({
      projectRoot: hoistedFixture,
      entrypoints: [path.join(hoistedFixture, "index.js")],
      advisory: {
        id: "GHSA-hoisted-vuln-c1",
        module: "hoisted-vuln",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // dep-zero is reachable (source fidelity, traversed by the call graph).
    // dep-zero has require(var) with zero declared deps.
    // OLD engine: couldReach=[] → frontier dropped → hoisted-vuln = NOT_REACHABLE (WRONG).
    // NEW engine: dep dynamic dispatch = global frontier → hoisted-vuln = UNKNOWN (CORRECT).
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(result.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });

  it("dep-zero is PACKAGE_REACHABLE (directly imported by first-party)", async () => {
    const result = await queryReachability({
      projectRoot: hoistedFixture,
      entrypoints: [path.join(hoistedFixture, "index.js")],
      advisory: {
        id: "GHSA-dep-zero-001",
        module: "dep-zero",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});

// ── C2: Dynamic dispatch in dep with declared dep-b, hoisted-vuln not declared ─
// dep-withdep declares dep-b and does require(var).
// With the scoped model (OLD engine), couldReach = ["dep-b"] → hoisted-vuln
// is NOT in couldReach → hoisted-vuln = NOT_REACHABLE (false negative, C2).
// With the GLOBAL model (NEW engine), dep-withdep's dynamic require is a
// global frontier → hoisted-vuln = UNKNOWN.

describe("cross-package traversal – C2: dep declares dep-b only, require(var) → global frontier covers hoisted-vuln", () => {
  it("hoisted-vuln is UNKNOWN when dep-withdep declares dep-b only but does require(var) [C2]", async () => {
    const result = await queryReachability({
      projectRoot: hoistedFixture,
      entrypoints: [path.join(hoistedFixture, "index.js")],
      advisory: {
        id: "GHSA-hoisted-vuln-c2",
        module: "hoisted-vuln",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    // dep-withdep declares dep-b only but uses require(var).
    // Node.js hoisting means the dynamic specifier can resolve to hoisted-vuln
    // at runtime even though dep-withdep doesn't declare it.
    // OLD engine: couldReach=["dep-b"] → hoisted-vuln NOT in couldReach → NOT_REACHABLE (WRONG).
    // NEW engine: global frontier → hoisted-vuln = UNKNOWN (CORRECT).
    expect(result.confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
    expect(result.confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });

  it("dep-withdep is PACKAGE_REACHABLE (directly imported)", async () => {
    const result = await queryReachability({
      projectRoot: hoistedFixture,
      entrypoints: [path.join(hoistedFixture, "index.js")],
      advisory: {
        id: "GHSA-dep-withdep-001",
        module: "dep-withdep",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });

  it("dep-b is PACKAGE_REACHABLE (statically imported by dep-withdep)", async () => {
    const result = await queryReachability({
      projectRoot: hoistedFixture,
      entrypoints: [path.join(hoistedFixture, "index.js")],
      advisory: {
        id: "GHSA-dep-b-001",
        module: "dep-b",
        versionRange: ">=0.0.0",
        symbols: [],
        symbolLevel: false,
        sources: ["osv"],
      },
    });
    expect(result.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});

// ── Call graph level: import sites recorded for transitive deps ───────────────

describe("cross-package traversal – call graph import sites", () => {
  it("dep-b has an import site (from dep-a's source file)", async () => {
    const cg = await buildCallGraph({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
    });
    const sites = cg.importSites.get("dep-b");
    expect(sites).toBeDefined();
    expect(sites!.length).toBeGreaterThan(0);
  });

  it("dep-a import site fromFile is the first-party index.js", async () => {
    const cg = await buildCallGraph({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
    });
    const sites = cg.importSites.get("dep-a");
    expect(sites).toBeDefined();
    expect(sites!.some((s) => s.fromFile.endsWith("index.js"))).toBe(true);
  });

  it("dep-c has no reachable import site", async () => {
    const cg = await buildCallGraph({
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
    });
    const sites = cg.importSites.get("dep-c") ?? [];
    const reachableSites = sites.filter((s) => cg.reachableFiles.has(s.fromFile));
    expect(reachableSites).toHaveLength(0);
  });
});

// ── Determinism: two runs produce identical results ───────────────────────────

describe("cross-package traversal – determinism", () => {
  it("two calls to buildCallGraph produce byte-identical importSites", async () => {
    const opts = {
      projectRoot: fixture,
      entrypoints: [path.join(fixture, "index.js")],
    };
    const r1 = await buildCallGraph(opts);
    const r2 = await buildCallGraph(opts);

    const serialize = (cg: typeof r1) =>
      JSON.stringify({
        reachableFiles: [...cg.reachableFiles].sort(),
        importSites: [...cg.importSites.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => [k, v]),
        unknownFrontiers: cg.unknownFrontiers.map((u) => ({
          reason: u.reason,
          fromFile: u.fromFile,
        })),
      });

    expect(serialize(r1)).toBe(serialize(r2));
  });
});
