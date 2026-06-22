/**
 * Tests for symbol resolution correctness (H1 fix).
 *
 * A symbol-level advisory must only yield SYMBOL_REACHABLE when the named
 * export is genuinely resolvable at the import site. A non-existent or
 * unverifiable symbol must fall back to PACKAGE_REACHABLE (not fabricate
 * a SYMBOL_REACHABLE verdict with a fake path step).
 *
 * These tests run through the SHIPPED analyze() path.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../../engine/analyze.js";
import { Confidence } from "../../gen/anst/v1/plugin.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const gate = path.resolve(__dirname, "../../../testdata/projects/gate-g1");

// ── Bogus symbol on a symbol-level advisory → PACKAGE_REACHABLE ──────────────
// Before the H1 fix, analyze() unconditionally sets symbolResolved=true when
// any reachable import site exists, regardless of whether the named symbol
// exists in the package. This produces a fabricated SYMBOL_REACHABLE verdict.
// After the fix, an unresolvable symbol must yield PACKAGE_REACHABLE.

describe("symbol resolution – bogus symbol falls back to PACKAGE_REACHABLE", () => {
  it("returns PACKAGE_REACHABLE (not SYMBOL_REACHABLE) when the symbol name does not match any import binding", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "index.js")],
      advisories: [
        {
          id: "GHSA-bogus-sym-001",
          module: "serialize-javascript",
          versionRange: "<3.1.0",
          // "thisSymbolDoesNotExist" is not imported or exported anywhere
          symbols: [{ package: "serialize-javascript", name: "thisSymbolDoesNotExist" }],
          symbolLevel: true,
          sources: ["synthetic"],
        },
      ],
    });
    const f = findings.find((f) => f.module === "serialize-javascript");
    expect(f).toBeDefined();
    // Must NOT be SYMBOL_REACHABLE — the symbol was never imported
    expect(f!.confidence).not.toBe(Confidence.CONFIDENCE_SYMBOL_REACHABLE);
    // Must be PACKAGE_REACHABLE because the package itself is reachable
    expect(f!.confidence).toBe(Confidence.CONFIDENCE_PACKAGE_REACHABLE);
    // No path should be present
    expect(f!.path).toBeUndefined();
  });

  it("returns SYMBOL_REACHABLE for a symbol that IS genuinely imported (control case)", async () => {
    const findings = await analyze({
      moduleRoot: gate,
      entrypoints: [path.join(gate, "src", "symbol-caller.js")],
      advisories: [
        {
          id: "GHSA-synth-sym-control",
          module: "serialize-javascript",
          versionRange: "<3.1.0",
          // "serialize" is the real destructured binding in symbol-caller.js
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
  });
});
