/**
 * Tests for the --extract-symbols subcommand plumbing (symbols-cmd.ts).
 *
 * We test the extractSymbols() function directly rather than forking a child
 * process, so these are fast and deterministic.  The fixture patch and file
 * content are real — the extractor is not mocked.
 */

import { describe, it, expect } from "vitest";
import { extractSymbols } from "../symbols-cmd.js";

// ── fixture ───────────────────────────────────────────────────────────────────

/**
 * A minimal unified diff touching the `sanitize` export function.
 * The diff adds a line inside the function body.
 */
const FIXTURE_PATCH = `\
diff --git a/src/utils.ts b/src/utils.ts
index 0000000..1111111 100644
--- a/src/utils.ts
+++ b/src/utils.ts
@@ -1,7 +1,8 @@
 export function sanitize(input: string): string {
-  return input.trim();
+  // strip control characters before trimming
+  return input.replace(/[\\x00-\\x1f]/g, "").trim();
 }

 export function noop(): void {
   // intentional no-op
 }
`;

/**
 * The full post-fix content of src/utils.ts.
 * Must match what the patch produces so the extractor can attribute lines.
 */
const FIXTURE_FILE_CONTENT = `\
export function sanitize(input: string): string {
  // strip control characters before trimming
  return input.replace(/[\\x00-\\x1f]/g, "").trim();
}

export function noop(): void {
  // intentional no-op
}
`;

// ── tests ─────────────────────────────────────────────────────────────────────

describe("extractSymbols – happy path", () => {
  it("returns the exported symbol touched by the patch", async () => {
    const result = await extractSymbols({
      patch: FIXTURE_PATCH,
      files: [{ path: "src/utils.ts", content: FIXTURE_FILE_CONTENT }],
    });

    expect(result).toHaveLength(1);
    expect(result[0].file).toBe("src/utils.ts");
    expect(result[0].exportName).toBe("sanitize");
    expect(result[0].kind).toBe("function");
  });

  it("does not return symbols from unchanged files", async () => {
    const result = await extractSymbols({
      patch: FIXTURE_PATCH,
      files: [{ path: "src/utils.ts", content: FIXTURE_FILE_CONTENT }],
    });
    // noop was not touched by the patch
    const names = result.map((s) => s.exportName);
    expect(names).not.toContain("noop");
  });
});

describe("extractSymbols – content hydration", () => {
  it("drops changed files whose path has no matching supplied content", async () => {
    // No files entry for src/utils.ts → extractor receives empty newContent and
    // must silently drop it (returning [] not throwing).
    const result = await extractSymbols({
      patch: FIXTURE_PATCH,
      files: [], // no content supplied
    });
    expect(result).toEqual([]);
  });

  it("ignores extra files not mentioned in the patch", async () => {
    const result = await extractSymbols({
      patch: FIXTURE_PATCH,
      files: [
        { path: "src/utils.ts", content: FIXTURE_FILE_CONTENT },
        { path: "src/other.ts", content: "export const x = 1;\n" },
      ],
    });
    // Only src/utils.ts is in the patch; other.ts must not appear in output
    const files = result.map((s) => s.file);
    expect(files).not.toContain("src/other.ts");
  });
});

describe("extractSymbols – malformed / empty input", () => {
  it("returns [] for an empty patch string", async () => {
    const result = await extractSymbols({ patch: "", files: [] });
    expect(result).toEqual([]);
  });

  it("returns [] for a non-diff garbage string", async () => {
    const result = await extractSymbols({ patch: "not a diff", files: [] });
    expect(result).toEqual([]);
  });

  it("returns [] when files is missing", async () => {
    // Cast to Partial to simulate a caller that omits the files field.
    const result = await extractSymbols({ patch: FIXTURE_PATCH } as Parameters<typeof extractSymbols>[0]);
    expect(result).toEqual([]);
  });
});

describe("extractSymbols – dropped-file diagnostic", () => {
  it("writes a stderr diagnostic when a changed file has no supplied content, and stdout still yields symbols for matched files", async () => {
    // Patch touches both src/a.ts and src/b.ts; content is only supplied for src/a.ts.
    const patchTwoFiles = `\
diff --git a/src/a.ts b/src/a.ts
index 0000000..1111111 100644
--- a/src/a.ts
+++ b/src/a.ts
@@ -1,4 +1,5 @@
 export function alpha(input: string): string {
-  return input.trim();
+  // strip before trimming
+  return input.replace(/[\\x00-\\x1f]/g, "").trim();
 }
diff --git a/src/b.ts b/src/b.ts
index 0000000..2222222 100644
--- a/src/b.ts
+++ b/src/b.ts
@@ -1,3 +1,4 @@
 export function beta(): void {
+  // changed
 }
`;
    const aContent = `\
export function alpha(input: string): string {
  // strip before trimming
  return input.replace(/[\\x00-\\x1f]/g, "").trim();
}
`;

    const stderrLines: string[] = [];
    const captureStderr = (msg: string): void => { stderrLines.push(msg); };

    const result = await extractSymbols(
      {
        patch: patchTwoFiles,
        files: [{ path: "src/a.ts", content: aContent }],
      },
      captureStderr
    );

    // stdout side: src/a.ts symbol must be present
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result.some((s) => s.file === "src/a.ts")).toBe(true);

    // stderr side: diagnostic must mention the unmatched file
    const stderrOut = stderrLines.join("");
    expect(stderrOut).toMatch(/src\/b\.ts/);
    expect(stderrOut).toMatch(/extract-symbols/);
  });
});

describe("extractSymbols – stdin entry point (runFromStdin)", () => {
  it("parses a valid JSON payload and returns symbols", async () => {
    const { runFromStdin } = await import("../symbols-cmd.js");

    const payload = JSON.stringify({
      patch: FIXTURE_PATCH,
      files: [{ path: "src/utils.ts", content: FIXTURE_FILE_CONTENT }],
    });

    const result = await runFromStdin(payload);
    const parsed: unknown = JSON.parse(result);
    expect(Array.isArray(parsed)).toBe(true);
    expect((parsed as unknown[]).length).toBe(1);
  });

  it("returns [] JSON for malformed stdin", async () => {
    const { runFromStdin } = await import("../symbols-cmd.js");
    const result = await runFromStdin("not json at all");
    expect(result.trim()).toBe("[]");
  });

  it("returns [] JSON for empty string stdin", async () => {
    const { runFromStdin } = await import("../symbols-cmd.js");
    const result = await runFromStdin("");
    expect(result.trim()).toBe("[]");
  });
});
