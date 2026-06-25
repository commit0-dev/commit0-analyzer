/**
 * Tests for the parser seam (parseModule).
 *
 * Verifies the normalized ParsedModule output across CJS/ESM/TS/JSX file types,
 * import/export/require extraction, dynamic import detection, and parse-error
 * handling.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseModule } from "../../parse/index.js";
import type { ParsedModuleOk, ParsedModuleUnknown } from "../../parse/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(__dirname, "../../../testdata/projects/resolve-fixtures");

// ── ESM imports ───────────────────────────────────────────────────────────────

describe("parseModule – ESM static imports", () => {
  it("extracts static import specifiers from an ESM file", async () => {
    const file = path.join(fixtures, "src", "app.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const specifiers = ok.imports.map((i) => i.specifier);
    expect(specifiers).toContain("./index.js");
    expect(specifiers).toContain("lodash");
  });

  it("marks static imports as not dynamic", async () => {
    const file = path.join(fixtures, "src", "app.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const staticImports = ok.imports.filter((i) => !i.isDynamic);
    expect(staticImports.length).toBeGreaterThan(0);
  });
});

// ── Dynamic imports ───────────────────────────────────────────────────────────

describe("parseModule – dynamic imports", () => {
  it("extracts literal dynamic import() specifier", async () => {
    const file = path.join(fixtures, "src", "dyn-import.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const dynImports = ok.imports.filter((i) => i.isDynamic);
    expect(dynImports.some((i) => i.specifier === "./lazy")).toBe(true);
  });

  it("records dynamic import with non-literal source as isDynamic + specifier=null", async () => {
    const file = path.join(fixtures, "src", "dyn-var.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const dynImports = ok.imports.filter((i) => i.isDynamic && i.specifier === null);
    expect(dynImports.length).toBeGreaterThan(0);
  });
});

// ── CJS require() ─────────────────────────────────────────────────────────────

describe("parseModule – CJS require()", () => {
  it("extracts require() specifier from a CommonJS file", async () => {
    const file = path.join(fixtures, "src", "cjs-module.cjs");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const specifiers = ok.imports.map((i) => i.specifier);
    expect(specifiers).toContain("path");
    expect(specifiers).toContain("./helper");
  });

  it("records dynamic require(var) as isDynamic + specifier=null", async () => {
    const file = path.join(fixtures, "src", "cjs-dynamic.cjs");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const dynReqs = ok.imports.filter((i) => i.isDynamic && i.specifier === null);
    expect(dynReqs.length).toBeGreaterThan(0);
  });
});

// ── TypeScript ────────────────────────────────────────────────────────────────

describe("parseModule – TypeScript", () => {
  it("parses a .ts file and extracts its imports", async () => {
    const file = path.join(fixtures, "src", "typed.ts");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const specifiers = ok.imports.map((i) => i.specifier);
    expect(specifiers).toContain("./index.js");
  });

  it("parses a .tsx file without error", async () => {
    const file = path.join(fixtures, "src", "component.tsx");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
  });
});

// ── Parse error → UNKNOWN ─────────────────────────────────────────────────────

describe("parseModule – parse error handling", () => {
  it("returns an UNKNOWN marker (not a throw) for a file with a syntax error", async () => {
    const file = path.join(fixtures, "src", "syntax-error.js");
    const result = await parseModule(file);
    // Must NOT throw. Must return unknown marker.
    expect(result.kind).toBe("unknown");
    const unk = result as ParsedModuleUnknown;
    expect(unk.reason).toBeTruthy();
  });

  it("returns an UNKNOWN marker for a missing file", async () => {
    const result = await parseModule("/absolutely/does/not/exist.js");
    expect(result.kind).toBe("unknown");
    const unk = result as ParsedModuleUnknown;
    expect(unk.reason).toBeTruthy();
  });
});

// ── Exports ───────────────────────────────────────────────────────────────────

describe("parseModule – exports", () => {
  it("extracts named exports from an ESM file", async () => {
    const file = path.join(fixtures, "src", "index.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    expect(ok.exports.length).toBeGreaterThan(0);
  });
});

// ── Location info ─────────────────────────────────────────────────────────────

describe("parseModule – location info", () => {
  it("attaches line/column to each import", async () => {
    const file = path.join(fixtures, "src", "app.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    for (const imp of ok.imports) {
      expect(typeof imp.line).toBe("number");
      expect(imp.line).toBeGreaterThan(0);
    }
  });
});

// ── Re-export edges (#1) ──────────────────────────────────────────────────────

describe("parseModule – re-export import edges", () => {
  it("emits an ImportRecord with importKind reexport for export * from", async () => {
    const file = path.join(fixtures, "src", "reexport-star.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const reexport = ok.imports.find(
      (i) => i.importKind === "reexport" && i.specifier === "./utils.js"
    );
    expect(reexport).toBeDefined();
    expect(reexport?.isDynamic).toBe(false);
  });

  it("emits an ImportRecord with importKind reexport for export { x } from", async () => {
    const file = path.join(fixtures, "src", "reexport-named.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const reexport = ok.imports.find(
      (i) => i.importKind === "reexport" && i.specifier === "./helpers.js"
    );
    expect(reexport).toBeDefined();
    expect(reexport?.isDynamic).toBe(false);
  });

  it("emits an ImportRecord with importKind reexport for export { x as y } from", async () => {
    const file = path.join(fixtures, "src", "reexport-renamed.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const reexport = ok.imports.find(
      (i) => i.importKind === "reexport" && i.specifier === "./base.js"
    );
    expect(reexport).toBeDefined();
    expect(reexport?.isDynamic).toBe(false);
  });

  it("populates ExportRecord.fromSpecifier for export * from", async () => {
    const file = path.join(fixtures, "src", "reexport-star.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const exp = ok.exports.find((e) => e.isReexport && e.fromSpecifier === "./utils.js");
    expect(exp).toBeDefined();
  });

  it("populates ExportRecord.fromSpecifier for export { x } from", async () => {
    const file = path.join(fixtures, "src", "reexport-named.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    const exp = ok.exports.find((e) => e.isReexport && e.fromSpecifier === "./helpers.js");
    expect(exp).toBeDefined();
  });
});

// ── CJS sourceType inference (#4) ─────────────────────────────────────────────

describe("parseModule – CJS sourceType inference for .js with require()", () => {
  it("infers sourceType commonjs for a .js file that uses only require() and no ESM syntax", async () => {
    const file = path.join(fixtures, "src", "cjs-plain.js");
    const result = await parseModule(file);
    expect(result.kind).toBe("parsed");
    const ok = result as ParsedModuleOk;
    expect(ok.sourceType).toBe("commonjs");
  });
});
