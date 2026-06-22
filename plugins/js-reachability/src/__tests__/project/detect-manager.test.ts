import { describe, it, expect } from "vitest";
import path from "node:path";
import { detectManager } from "../../project/detect-manager.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("detectManager", () => {
  it("detects npm from package-lock.json", async () => {
    const result = await detectManager(path.join(fixtures, "single-pkg"));
    expect(result.manager).toBe("npm");
    expect(result.incomplete).toHaveLength(0);
  });

  it("detects npm for workspace with package-lock.json", async () => {
    const result = await detectManager(path.join(fixtures, "npm-ws"));
    expect(result.manager).toBe("npm");
    expect(result.incomplete).toHaveLength(0);
  });

  it("detects yarn from yarn.lock", async () => {
    const result = await detectManager(path.join(fixtures, "yarn-ws"));
    expect(result.manager).toBe("yarn");
    expect(result.incomplete).toHaveLength(0);
  });

  it("detects pnpm from pnpm-lock.yaml", async () => {
    const result = await detectManager(path.join(fixtures, "pnpm-ws"));
    expect(result.manager).toBe("pnpm");
    expect(result.incomplete).toHaveLength(0);
  });

  it("returns unknown when no lockfile is present", async () => {
    const result = await detectManager(path.join(fixtures, "missing-lock"));
    expect(result.manager).toBe("unknown");
    expect(result.incomplete).toHaveLength(1);
    expect(result.incomplete[0].scope).toContain("missing-lock");
  });

  it("detects npm from corrupt lockfile (file exists = npm)", async () => {
    const result = await detectManager(path.join(fixtures, "corrupt-lock"));
    expect(result.manager).toBe("npm");
    expect(result.incomplete).toHaveLength(0);
  });
});
