import { describe, it, expect } from "vitest";
import { extractVulnerableSymbols } from "../../symbols/extract-from-patch.js";
import type { ChangedFile, VulnerableSymbol } from "../../symbols/types.js";

// ── helpers ───────────────────────────────────────────────────────────────────

function file(path: string, newContent: string, changedLines: number[]): ChangedFile {
  return { path, newContent, changedLines };
}

// ── exported function fix ─────────────────────────────────────────────────────

describe("extractVulnerableSymbols – fix inside export function", () => {
  const src = [
    "export function validate(input: string): boolean {",  // line 1
    "  if (!input) return false;",                         // line 2
    "  return input.length > 0;",                          // line 3
    "}",                                                    // line 4
    "",                                                     // line 5
    "export function unrelated() {",                        // line 6
    "  return 42;",                                         // line 7
    "}",                                                    // line 8
  ].join("\n");

  it("identifies the exported function whose body contains the changed line", () => {
    const changed = [file("src/validate.ts", src, [3])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/validate.ts",
      exportName: "validate",
      kind: "function",
    });
  });

  it("does not include an unrelated exported function", () => {
    const changed = [file("src/validate.ts", src, [3])];
    const result = extractVulnerableSymbols(changed);
    expect(result.find((s) => s.exportName === "unrelated")).toBeUndefined();
  });

  it("when the changed line is in the second export function, identifies that one", () => {
    const changed = [file("src/validate.ts", src, [7])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0].exportName).toBe("unrelated");
  });
});

// ── export const arrow function ───────────────────────────────────────────────

describe("extractVulnerableSymbols – fix inside export const arrow function", () => {
  const src = [
    "export const sanitize = (s: string): string => {",  // line 1
    "  return s.trim().toLowerCase();",                   // line 2
    "};",                                                  // line 3
  ].join("\n");

  it("identifies the exported const arrow function", () => {
    const changed = [file("src/sanitize.ts", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/sanitize.ts",
      exportName: "sanitize",
      kind: "function",
    });
  });
});

// ── export class method fix ───────────────────────────────────────────────────

describe("extractVulnerableSymbols – fix inside export class method", () => {
  const src = [
    "export class Parser {",           // line 1
    "  parse(input: string) {",        // line 2
    "    return JSON.parse(input);",   // line 3
    "  }",                             // line 4
    "",                                // line 5
    "  stringify(data: unknown) {",    // line 6
    "    return JSON.stringify(data);",// line 7
    "  }",                             // line 8
    "}",                               // line 9
  ].join("\n");

  it("returns Class.method format with kind=method for a change inside a method", () => {
    const changed = [file("src/parser.ts", src, [3])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/parser.ts",
      exportName: "Parser.parse",
      kind: "method",
    });
  });

  it("identifies the correct method when the change is in the second method", () => {
    const changed = [file("src/parser.ts", src, [7])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/parser.ts",
      exportName: "Parser.stringify",
      kind: "method",
    });
  });
});

// ── non-exported helper attribution ──────────────────────────────────────────

describe("extractVulnerableSymbols – fix in non-exported helper", () => {
  const src = [
    "function helperA(x: number): number {",  // line 1
    "  return x * 2;",                         // line 2
    "}",                                        // line 3
    "",                                         // line 4
    "export function process(v: number) {",    // line 5
    "  return helperA(v) + 1;",                // line 6
    "}",                                        // line 7
  ].join("\n");

  it("when a changed line is inside a non-exported function, returns module-level marker", () => {
    // The helper is at lines 1-3; no exported ancestor wraps it
    const changed = [file("src/process.ts", src, [2])];
    const result = extractVulnerableSymbols(changed);
    // Must not be empty (unknown ≠ safe)
    expect(result.length).toBeGreaterThan(0);
    // Must not attribute to 'process' (helper is not inside process)
    expect(result.find((s) => s.exportName === "process")).toBeUndefined();
    // The marker should have exportName "module-level"
    expect(result[0].exportName).toBe("module-level");
  });

  it("when change is inside the exported function body, attributes to it", () => {
    const changed = [file("src/process.ts", src, [6])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0].exportName).toBe("process");
  });
});

// ── export default ────────────────────────────────────────────────────────────

describe("extractVulnerableSymbols – export default function", () => {
  const src = [
    "export default function handler(req: Request) {",  // line 1
    "  return fetch(req.url);",                          // line 2
    "}",                                                  // line 3
  ].join("\n");

  it("returns exportName=default with kind=function", () => {
    const changed = [file("src/handler.ts", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/handler.ts",
      exportName: "default",
      kind: "function",
    });
  });
});

// ── CJS exports.foo ───────────────────────────────────────────────────────────

describe("extractVulnerableSymbols – CJS exports.foo", () => {
  const src = [
    "exports.escape = function escape(str) {",  // line 1
    "  return str.replace(/</g, '&lt;');",       // line 2
    "};",                                         // line 3
  ].join("\n");

  it("identifies a CJS exports.name assignment as an exported symbol", () => {
    const changed = [file("src/escape.cjs", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/escape.cjs",
      exportName: "escape",
      kind: "function",
    });
  });
});

// ── CJS module.exports.foo ────────────────────────────────────────────────────

describe("extractVulnerableSymbols – CJS module.exports.foo", () => {
  const src = [
    "module.exports.serialize = function(obj) {",  // line 1
    "  return JSON.stringify(obj, null, 2);",        // line 2
    "};",                                             // line 3
  ].join("\n");

  it("identifies a module.exports.name assignment", () => {
    const changed = [file("src/serial.js", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/serial.js",
      exportName: "serialize",
      kind: "function",
    });
  });
});

// ── multi-file patch ──────────────────────────────────────────────────────────

describe("extractVulnerableSymbols – multi-file patch", () => {
  const srcA = [
    "export function alpha() {",  // line 1
    "  return 1;",                 // line 2
    "}",                           // line 3
  ].join("\n");

  const srcB = [
    "export function beta() {",   // line 1
    "  return 2;",                 // line 2
    "}",                           // line 3
  ].join("\n");

  it("returns symbols from all changed files", () => {
    const changed = [
      file("src/a.ts", srcA, [2]),
      file("src/b.ts", srcB, [2]),
    ];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(2);
    const names = result.map((s) => s.exportName);
    expect(names).toContain("alpha");
    expect(names).toContain("beta");
  });

  it("results are sorted by file then exportName", () => {
    const changed = [
      file("src/b.ts", srcB, [2]),
      file("src/a.ts", srcA, [2]),
    ];
    const result = extractVulnerableSymbols(changed);
    expect(result[0].file).toBe("src/a.ts");
    expect(result[1].file).toBe("src/b.ts");
  });
});

// ── change touching only a comment / import ───────────────────────────────────

describe("extractVulnerableSymbols – change inside a comment or import only", () => {
  const src = [
    "// This is a comment that was changed",  // line 1
    "import { foo } from './foo.js';",         // line 2
    "",                                         // line 3
    "export function doSomething() {",          // line 4
    "  return foo();",                          // line 5
    "}",                                        // line 6
  ].join("\n");

  it("returns module-level marker when changed line is a top-level comment", () => {
    // Line 1 is a comment at the top level, not inside any exported declaration
    const changed = [file("src/thing.ts", src, [1])];
    const result = extractVulnerableSymbols(changed);
    // Not empty (unknown ≠ safe), and exportName is module-level
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].exportName).toBe("module-level");
  });

  it("returns module-level marker when only an import statement was changed", () => {
    // Line 2 is an import statement
    const changed = [file("src/thing.ts", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].exportName).toBe("module-level");
  });
});

// ── deduplication ─────────────────────────────────────────────────────────────

describe("extractVulnerableSymbols – deduplication", () => {
  const src = [
    "export function transform(x: number) {",  // line 1
    "  const a = x * 2;",                       // line 2
    "  const b = a + 1;",                       // line 3
    "  return b;",                               // line 4
    "}",                                         // line 5
  ].join("\n");

  it("deduplicates when multiple changed lines are in the same exported symbol", () => {
    const changed = [file("src/t.ts", src, [2, 3, 4])];
    const result = extractVulnerableSymbols(changed);
    // Should only emit transform once, not three times
    expect(result).toHaveLength(1);
    expect(result[0].exportName).toBe("transform");
  });
});

// ── export class (class-level change) ────────────────────────────────────────

describe("extractVulnerableSymbols – change in class body outside any method", () => {
  const src = [
    "export class Config {",                     // line 1
    "  static DEFAULT_TIMEOUT = 5000;",          // line 2
    "",                                           // line 3
    "  constructor(public timeout: number) {}",  // line 4
    "}",                                          // line 5
  ].join("\n");

  it("attributes a change in a class field to the class", () => {
    const changed = [file("src/config.ts", src, [2])];
    const result = extractVulnerableSymbols(changed);
    expect(result.length).toBeGreaterThan(0);
    // Should attribute to Config class
    const cls = result.find((s) => s.exportName === "Config");
    expect(cls).toBeDefined();
    expect(cls?.kind).toBe("class");
  });
});

// ── malformed / empty content ─────────────────────────────────────────────────

describe("extractVulnerableSymbols – malformed content", () => {
  it("returns empty array and does not throw for unparseable JS", () => {
    const broken = "export function ??? {{{{{";
    const changed = [file("src/broken.ts", broken, [1])];
    expect(() => extractVulnerableSymbols(changed)).not.toThrow();
  });

  it("returns empty array for empty content", () => {
    const changed = [file("src/empty.ts", "", [1])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toEqual([]);
  });

  it("returns empty array when changedLines is empty", () => {
    const src = "export function foo() { return 1; }";
    const changed = [file("src/f.ts", src, [])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toEqual([]);
  });
});

// ── multi-declarator mis-attribution ─────────────────────────────────────────

describe("extractVulnerableSymbols – multi-declarator: change on second declarator returns correct name", () => {
  // export const f = () => {...}, g = () => {...}
  // A change on g's line must attribute to g, not f.
  const src = [
    "export const f = () => {",   // line 1
    "  return 1;",                 // line 2
    "}, g = () => {",             // line 3
    "  return 2;",                 // line 4
    "};",                          // line 5
  ].join("\n");

  it("attributes a change on the second declarator line to g, not f", () => {
    const changed = [file("src/multi.ts", src, [4])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0].exportName).toBe("g");
  });
});

// ── exported enum attribution ─────────────────────────────────────────────────

describe("extractVulnerableSymbols – exported enum", () => {
  const src = [
    "export enum Color {",  // line 1
    "  Red,",               // line 2
    "  Green,",             // line 3
    "  Blue,",              // line 4
    "}",                    // line 5
  ].join("\n");

  it("attributes a change inside an exported enum to the enum name", () => {
    const changed = [file("src/color.ts", src, [3])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/color.ts",
      exportName: "Color",
      kind: "variable",
    });
  });
});

// ── exported namespace attribution ────────────────────────────────────────────

describe("extractVulnerableSymbols – exported namespace", () => {
  const src = [
    "export namespace Utils {",               // line 1
    "  export function helper(x: number) {", // line 2
    "    return x * 2;",                      // line 3
    "  }",                                    // line 4
    "}",                                      // line 5
  ].join("\n");

  it("attributes a change inside an exported namespace to the namespace name", () => {
    const changed = [file("src/utils.ts", src, [3])];
    const result = extractVulnerableSymbols(changed);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<VulnerableSymbol>({
      file: "src/utils.ts",
      exportName: "Utils",
      kind: "class",
    });
  });
});
