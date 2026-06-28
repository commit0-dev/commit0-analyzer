/**
 * Tests for the confidence decision tree (src/confidence.ts).
 *
 * Mirrors the Go AssignConfidence invariants exactly.
 * All inputs are pure value types — no file I/O, no graph builds.
 */
import { describe, it, expect } from "vitest";
import { assignConfidence } from "../../confidence.js";
import { Confidence } from "../../gen/commit0/v1/plugin.js";

// ── parse/type/resolve error → UNKNOWN ───────────────────────────────────────

describe("assignConfidence – parse/resolve error → UNKNOWN", () => {
  it("returns UNKNOWN when there is a parse error in scope", () => {
    const { confidence } = assignConfidence({
      parseError: true,
      packageImported: false,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
  });
});

// ── package not imported → NOT_REACHABLE ─────────────────────────────────────

describe("assignConfidence – package not imported → NOT_REACHABLE", () => {
  it("returns NOT_REACHABLE when the package is not imported anywhere", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: false,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── symbol_level + resolved + path → SYMBOL_REACHABLE ────────────────────────

describe("assignConfidence – symbol_level + resolved + BFS path → SYMBOL_REACHABLE", () => {
  it("returns SYMBOL_REACHABLE when symbol is resolved and BFS found a path", () => {
    const { confidence, path } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: true,
      symbolResolved: true,
      bfsReachable: true,
      unknownFrontierOnOnlyPath: false,
      bfsPath: [{ symbol: "serialize", location: { file: "src/index.js", line: 1, column: 0 } }],
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_SYMBOL_REACHABLE);
    expect(path).toBeDefined();
    expect(path!.steps.length).toBeGreaterThan(0);
  });

  it("returns the exact BFS path steps for SYMBOL_REACHABLE", () => {
    const step = { symbol: "serialize", location: { file: "src/foo.js", line: 5, column: 3 } };
    const { path } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: true,
      symbolResolved: true,
      bfsReachable: true,
      unknownFrontierOnOnlyPath: false,
      bfsPath: [step],
    });
    expect(path!.steps[0].symbol).toBe("serialize");
    expect(path!.steps[0].location?.file).toBe("src/foo.js");
  });
});

// ── reachable package (non-symbol) → PACKAGE_REACHABLE ───────────────────────

describe("assignConfidence – package reachable, not symbol-level → PACKAGE_REACHABLE", () => {
  it("returns PACKAGE_REACHABLE when the package is imported and reachable from entrypoints", () => {
    const { confidence, path } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: true,
      unknownFrontierOnOnlyPath: false,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
    // Path must be absent for non-SYMBOL_REACHABLE
    expect(path).toBeUndefined();
  });
});

// ── UNKNOWN frontier on only path → UNKNOWN ───────────────────────────────────

describe("assignConfidence – UNKNOWN frontier on only path → UNKNOWN (not NOT_REACHABLE)", () => {
  it("returns UNKNOWN when the only candidate path is blocked by an UNKNOWN frontier", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: true,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_UNKNOWN);
  });

  it("never returns NOT_REACHABLE when UNKNOWN frontier blocks the only path", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: true,
    });
    expect(confidence).not.toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Clean graph, no path → NOT_REACHABLE ─────────────────────────────────────

describe("assignConfidence – clean graph, no path → NOT_REACHABLE", () => {
  it("returns NOT_REACHABLE when package is imported but no path exists and graph is clean", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });
});

// ── Symbol level but symbol not resolved and package not reachable → NOT_REACHABLE ──
// When a symbol-level advisory cannot resolve the symbol AND the package is
// not BFS-reachable and there is no UNKNOWN frontier on the path, the correct
// verdict is NOT_REACHABLE — the package is imported somewhere but not reached
// from any entrypoint, and the unverifiable symbol does not add uncertainty.
// (If the package were BFS-reachable, the verdict would be PACKAGE_REACHABLE.)

describe("assignConfidence – symbol_level, symbol not resolved, package not reachable → NOT_REACHABLE", () => {
  it("returns NOT_REACHABLE when symbol_level is true but symbol could not be resolved and package is not BFS-reachable", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: true,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(confidence).toBe(Confidence.CONFIDENCE_NOT_REACHABLE);
  });

  it("returns PACKAGE_REACHABLE when symbol_level is true but symbol could not be resolved and package IS BFS-reachable", () => {
    const { confidence } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: true,
      symbolResolved: false,
      bfsReachable: true,
      unknownFrontierOnOnlyPath: false,
    });
    // Symbol can't be confirmed but the package is definitely reachable
    expect(confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
  });
});

// ── Path absent for non-SYMBOL_REACHABLE ─────────────────────────────────────

describe("assignConfidence – path invariant", () => {
  it("returns undefined path for UNKNOWN", () => {
    const { path } = assignConfidence({
      parseError: true,
      packageImported: false,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(path).toBeUndefined();
  });

  it("returns undefined path for NOT_REACHABLE", () => {
    const { path } = assignConfidence({
      parseError: false,
      packageImported: false,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: false,
      unknownFrontierOnOnlyPath: false,
    });
    expect(path).toBeUndefined();
  });

  it("returns undefined path for PACKAGE_REACHABLE", () => {
    const { path } = assignConfidence({
      parseError: false,
      packageImported: true,
      symbolLevel: false,
      symbolResolved: false,
      bfsReachable: true,
      unknownFrontierOnOnlyPath: false,
    });
    expect(path).toBeUndefined();
  });
});
