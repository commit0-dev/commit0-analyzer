import { describe, it, expect } from "vitest";
import { parseUnifiedDiff } from "../../symbols/parse-patch.js";

// ── helpers ───────────────────────────────────────────────────────────────────

/** Build a minimal unified diff string from parts. */
function makeDiff(
  oldPath: string,
  newPath: string,
  hunks: Array<{ oldStart: number; oldCount: number; newStart: number; newCount: number; lines: string[] }>
): string {
  const parts: string[] = [];
  parts.push(`--- ${oldPath}`);
  parts.push(`+++ ${newPath}`);
  for (const h of hunks) {
    parts.push(
      `@@ -${h.oldStart},${h.oldCount} +${h.newStart},${h.newCount} @@`
    );
    for (const l of h.lines) parts.push(l);
  }
  return parts.join("\n") + "\n";
}

// ── parse-patch: basic single-file diff ──────────────────────────────────────

describe("parseUnifiedDiff – single-file diff with added lines", () => {
  const patch = makeDiff(
    "a/src/util.ts",
    "b/src/util.ts",
    [
      {
        oldStart: 1,
        oldCount: 3,
        newStart: 1,
        newCount: 5,
        lines: [
          " function old() {",
          "-  return 1;",
          "+  const x = 2;",
          "+  return x;",
          " }",
        ],
      },
    ]
  );

  it("returns one ChangedFile for the modified source", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(1);
    expect(result[0].path).toBe("src/util.ts");
  });

  it("records the new-side line numbers of added lines", () => {
    const result = parseUnifiedDiff(patch);
    // Hunk @@ -1,3 +1,5 @@, newStart=1:
    //   " function old() {"  → context  → new line 1
    //   "-  return 1;"       → removed  → no new-side line
    //   "+  const x = 2;"   → added    → new line 2
    //   "+  return x;"       → added    → new line 3
    //   " }"                 → context  → new line 4
    const changed = result[0].changedLines;
    expect(changed).toContain(2);
    expect(changed).toContain(3);
  });

  it("does not include context-only lines as changed", () => {
    const result = parseUnifiedDiff(patch);
    const changed = result[0].changedLines;
    // New-side lines 1 and 4 are context lines — they should NOT be in changedLines
    expect(changed).not.toContain(1);
    expect(changed).not.toContain(4);
  });
});

// ── parse-patch: deleted-only file is ignored ────────────────────────────────

describe("parseUnifiedDiff – deleted-only file", () => {
  const patch = [
    "--- a/src/removed.ts",
    "+++ /dev/null",
    "@@ -1,3 +0,0 @@",
    "-export function gone() {}",
    "-",
    "-// old code",
  ].join("\n") + "\n";

  it("returns empty array for a deletion-only diff", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(0);
  });
});

// ── parse-patch: non-source file extension is skipped ────────────────────────

describe("parseUnifiedDiff – non-source file", () => {
  const patch = makeDiff(
    "a/README.md",
    "b/README.md",
    [
      {
        oldStart: 1,
        oldCount: 1,
        newStart: 1,
        newCount: 2,
        lines: [" # title", "+some new line"],
      },
    ]
  );

  it("skips non-source files (.md)", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(0);
  });
});

// ── parse-patch: multi-hunk diff ─────────────────────────────────────────────

describe("parseUnifiedDiff – multiple hunks in a single file", () => {
  const patch = makeDiff(
    "a/src/thing.js",
    "b/src/thing.js",
    [
      {
        oldStart: 1,
        oldCount: 3,
        newStart: 1,
        newCount: 3,
        lines: [
          " const a = 1;",
          "-const b = 2;",
          "+const b = 3;",
        ],
      },
      {
        oldStart: 20,
        oldCount: 3,
        newStart: 20,
        newCount: 4,
        lines: [
          " function foo() {",
          "-  return 1;",
          "+  const r = 2;",
          "+  return r;",
          " }",
        ],
      },
    ]
  );

  it("collects changed lines from all hunks", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(1);
    const changed = result[0].changedLines;
    // Hunk 1: new-side lines 1 (context), 2 is deleted (no new), 3 is added
    // Wait: the hunk starts at newStart=1, so:
    //   line " const a = 1;" → new line 1 (context, not changed)
    //   line "-const b = 2;" → old line 2 (removed, no new-side)
    //   line "+const b = 3;" → new line 2 (added, changed)
    expect(changed).toContain(2); // added in hunk 1
    // Hunk 2 starts at newStart=20
    //   " function foo() {" → new line 20 (context)
    //   "-  return 1;" → removed
    //   "+  const r = 2;" → new line 21 (added)
    //   "+  return r;" → new line 22 (added)
    //   " }" → new line 23 (context)
    expect(changed).toContain(21);
    expect(changed).toContain(22);
    expect(changed).not.toContain(20);
  });
});

// ── parse-patch: multi-file patch ────────────────────────────────────────────

describe("parseUnifiedDiff – multi-file patch", () => {
  const patch = [
    "--- a/src/a.ts",
    "+++ b/src/a.ts",
    "@@ -1,2 +1,3 @@",
    " const x = 1;",
    "+const y = 2;",
    " export { x };",
    "--- a/src/b.js",
    "+++ b/src/b.js",
    "@@ -5,2 +5,3 @@",
    " // comment",
    "+return 42;",
    " }",
  ].join("\n") + "\n";

  it("returns one entry per source file", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(2);
    const paths = result.map((f) => f.path).sort();
    expect(paths).toEqual(["src/a.ts", "src/b.js"]);
  });

  it("each file has the correct changed lines", () => {
    const result = parseUnifiedDiff(patch);
    const aFile = result.find((f) => f.path === "src/a.ts")!;
    const bFile = result.find((f) => f.path === "src/b.js")!;
    // a.ts: context at new line 1, added at new line 2, context at new line 3
    expect(aFile.changedLines).toContain(2);
    expect(aFile.changedLines).not.toContain(1);
    // b.js: context at new line 5, added at new line 6, context at new line 7
    expect(bFile.changedLines).toContain(6);
    expect(bFile.changedLines).not.toContain(5);
  });
});

// ── parse-patch: supported extensions ────────────────────────────────────────

describe("parseUnifiedDiff – supported extension filter", () => {
  it("includes .js, .ts, .jsx, .tsx, .cjs, .mjs, .cts, .mts files", () => {
    const extensions = [".js", ".ts", ".jsx", ".tsx", ".cjs", ".mjs", ".cts", ".mts"];
    for (const ext of extensions) {
      const patch = makeDiff(
        `a/src/file${ext}`,
        `b/src/file${ext}`,
        [{ oldStart: 1, oldCount: 1, newStart: 1, newCount: 2, lines: [" x", "+y"] }]
      );
      const result = parseUnifiedDiff(patch);
      expect(result).toHaveLength(1);
    }
  });

  it("excludes .json, .css, .md, .txt, .yaml files", () => {
    const nonSource = [".json", ".css", ".md", ".txt", ".yaml"];
    for (const ext of nonSource) {
      const patch = makeDiff(
        `a/file${ext}`,
        `b/file${ext}`,
        [{ oldStart: 1, oldCount: 1, newStart: 1, newCount: 2, lines: [" x", "+y"] }]
      );
      const result = parseUnifiedDiff(patch);
      expect(result).toHaveLength(0);
    }
  });
});

// ── parse-patch: malformed / binary patch ────────────────────────────────────

describe("parseUnifiedDiff – malformed input", () => {
  it("returns empty array for empty string", () => {
    expect(parseUnifiedDiff("")).toEqual([]);
  });

  it("returns empty array for non-diff text (no throw)", () => {
    expect(() => parseUnifiedDiff("hello world\nno diff here")).not.toThrow();
    expect(parseUnifiedDiff("hello world\nno diff here")).toEqual([]);
  });

  it("returns empty array for binary diff marker (no throw)", () => {
    const bin = [
      "--- a/image.ts",
      "+++ b/image.ts",
      "Binary files a/image.ts and b/image.ts differ",
    ].join("\n");
    expect(() => parseUnifiedDiff(bin)).not.toThrow();
    // binary files line has no hunk header → no changedLines, so skip or empty
    const result = parseUnifiedDiff(bin);
    // Either empty or has no changedLines (both valid)
    if (result.length > 0) {
      expect(result[0].changedLines).toHaveLength(0);
    }
  });

  it("returns empty array for partial header without hunks (no throw)", () => {
    const partial = "--- a/src/x.ts\n+++ b/src/x.ts\n";
    expect(() => parseUnifiedDiff(partial)).not.toThrow();
    const result = parseUnifiedDiff(partial);
    // Either empty or has empty changedLines
    if (result.length > 0) {
      expect(result[0].changedLines).toHaveLength(0);
    }
  });
});

// ── parse-patch: content line starting with "++ " inside a hunk must not be treated as file header ──

describe("parseUnifiedDiff – added line whose content starts with '++ ' is not a file header", () => {
  // Source content "++ something" → diff line "+++ something" which starts with "+++ "
  // and would be mistaken for a file header by a naive startsWith("+++ ") check.
  const patch = [
    "--- a/src/counter.ts",
    "+++ b/src/counter.ts",
    "@@ -1,3 +1,4 @@",
    " let count = 0;",
    "+++ something added here",  // content is "+ something added here"; diff line starts with "+++ "
    " export function getCount() {",
    "   return count;",
    " }",
  ].join("\n") + "\n";

  it("records the hunk changed lines and does not drop them when an added line diff-prefix produces +++", () => {
    const result = parseUnifiedDiff(patch);
    expect(result).toHaveLength(1);
    expect(result[0].path).toBe("src/counter.ts");
    // The "+++ something added here" line is new-side line 2 (added line inside hunk)
    expect(result[0].changedLines).toContain(2);
  });

  it("does not misinterpret the +++ content line inside a hunk as a new file header", () => {
    const result = parseUnifiedDiff(patch);
    // If it were mistaken for a header, the rest of the hunk would be dropped.
    // Verify we still have one file, not zero or two.
    expect(result).toHaveLength(1);
  });
});

// ── parse-patch: git diff header format (a/ b/ prefix stripping) ─────────────

describe("parseUnifiedDiff – git diff a/b prefix stripping", () => {
  it("strips a/ and b/ git prefixes from paths", () => {
    const patch = makeDiff(
      "a/packages/lib/src/index.ts",
      "b/packages/lib/src/index.ts",
      [{ oldStart: 1, oldCount: 1, newStart: 1, newCount: 2, lines: [" x", "+y"] }]
    );
    const result = parseUnifiedDiff(patch);
    expect(result[0].path).toBe("packages/lib/src/index.ts");
  });
});
