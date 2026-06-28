/**
 * Tests: platform-excluded optional dependencies must not produce dep-unresolved
 * incomplete entries for pnpm and npm projects.
 *
 * All platform/arch values are explicit so results are deterministic on any host.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { buildProjectModel } from "../../project/build-project-model.js";
import { parsePnpmLockfile } from "../../lockfile/pnpm.js";
import { isPlatformExcluded } from "../../lockfile/platform-filter.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

// Explicit host descriptors used throughout — never read from process.platform/arch.
const LINUX_X64 = { platform: "linux", arch: "x64" };
const DARWIN_ARM64 = { platform: "darwin", arch: "arm64" };

// ── platform-filter unit tests ────────────────────────────────────────────────

describe("isPlatformExcluded – unit", () => {
  it("empty constraints → not excluded", () => {
    expect(isPlatformExcluded([], [], "darwin", "arm64")).toBe(false);
  });

  it("undefined constraints → not excluded", () => {
    expect(isPlatformExcluded(undefined, undefined, "darwin", "arm64")).toBe(false);
  });

  it("os: [linux] on darwin → excluded", () => {
    expect(isPlatformExcluded(["linux"], undefined, "darwin", "arm64")).toBe(true);
  });

  it("os: [darwin] on darwin → not excluded", () => {
    expect(isPlatformExcluded(["darwin"], undefined, "darwin", "arm64")).toBe(false);
  });

  it("cpu: [x64] on arm64 → excluded", () => {
    expect(isPlatformExcluded(undefined, ["x64"], "darwin", "arm64")).toBe(true);
  });

  it("cpu: [arm64] on arm64 → not excluded", () => {
    expect(isPlatformExcluded(undefined, ["arm64"], "darwin", "arm64")).toBe(false);
  });

  it("os: [!win32] on darwin → not excluded (negation denylist)", () => {
    expect(isPlatformExcluded(["!win32"], undefined, "darwin", "arm64")).toBe(false);
  });

  it("os: [!darwin] on darwin → excluded (negation denylist)", () => {
    expect(isPlatformExcluded(["!darwin"], undefined, "darwin", "arm64")).toBe(true);
  });

  it("os: [linux, darwin] on darwin → not excluded (multi-value allowlist)", () => {
    expect(isPlatformExcluded(["linux", "darwin"], undefined, "darwin", "arm64")).toBe(false);
  });

  it("os: [linux, win32] on darwin → excluded (allowlist misses host)", () => {
    expect(isPlatformExcluded(["linux", "win32"], undefined, "darwin", "arm64")).toBe(true);
  });

  it("os excluded AND cpu excluded → excluded", () => {
    expect(isPlatformExcluded(["linux"], ["x64"], "darwin", "arm64")).toBe(true);
  });

  it("os excluded, cpu ok → excluded", () => {
    expect(isPlatformExcluded(["linux"], ["arm64"], "darwin", "arm64")).toBe(true);
  });

  it("os ok, cpu excluded → excluded", () => {
    expect(isPlatformExcluded(["darwin"], ["x64"], "darwin", "arm64")).toBe(true);
  });
});

// ── pnpm: platform-excluded optional store miss ────────────────────────────────

describe("pnpm optional dep excluded by os constraint emits no dep-unresolved", () => {
  it("parsePnpmLockfile does not emit dep-unresolved for absent platform-excluded optional", async () => {
    // platform-only-linux has os:[linux]; on darwin/arm64 it is excluded → no dep-unresolved.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-only-linux")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("buildProjectModel has no dep-unresolved for absent platform-excluded optional", async () => {
    // platform-only-linux has os:[linux]; on darwin/arm64 it is excluded → no dep-unresolved.
    const model = await buildProjectModel(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-only-linux")
    );
    expect(unresolved).toHaveLength(0);
  });
});

describe("pnpm optional dep excluded by cpu constraint emits no dep-unresolved", () => {
  it("no dep-unresolved for cpu-excluded optional (x64-only dep on arm64)", async () => {
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-only-x64")
    );
    expect(unresolved).toHaveLength(0);
  });
});

describe("pnpm optional dep whose store is absent emits no dep-unresolved", () => {
  it("optional dep whose constraints match host but store is absent is NOT incomplete", async () => {
    // platform-absent-match declares os: [darwin] cpu: [arm64] and optional: true.
    // Its store path is missing. Because it is optional, pnpm chose not to install it;
    // it cannot contribute import paths at runtime on this host → not a coverage gap.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-absent-match")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("does NOT emit dep-unresolved for same dep when host platform is excluded", async () => {
    // On linux/x64 platform-absent-match (os: [darwin]) is excluded → no dep-unresolved.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      LINUX_X64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-absent-match")
    );
    expect(unresolved).toHaveLength(0);
  });
});

describe("pnpm required dep absent from store always emits dep-unresolved", () => {
  it("required dep with os constraint but absent from store → still dep-unresolved", async () => {
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    // required-absent is NOT optional; missing from store → must emit dep-unresolved
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("required-absent")
    );
    expect(unresolved).toHaveLength(1);
  });
});

describe("pnpm graph does not contain fabricated dirs for platform-excluded optional packages", () => {
  it("platform-excluded optional package is absent from the lockfile graph", async () => {
    // On linux/x64, platform-only-linux (os: [linux]) is excluded on darwin/arm64.
    // On darwin/arm64, platform-only-linux is excluded — it must not appear in graph.
    const { graph } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      DARWIN_ARM64
    );
    const linuxPkg = [...graph.values()].find((p) => p.name === "platform-only-linux");
    expect(linuxPkg).toBeUndefined();
  });

  it("optional package with missing store is absent from graph even on a matching platform", async () => {
    // platform-only-linux is optional: true with os: [linux]. On linux/x64 its os
    // constraint matches the host, but the store path is missing and it is optional →
    // pnpm did not install it → absent from the runtime → absent from graph.
    const { graph } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform"),
      LINUX_X64
    );
    const linuxPkg = [...graph.values()].find((p) => p.name === "platform-only-linux");
    expect(linuxPkg).toBeUndefined();
  });
});

// ── npm: platform-excluded optional from lockfile entry ───────────────────────

describe("npm optional dep with os constraint excluding host emits no dep-unresolved", () => {
  it("buildProjectModel has no dep-unresolved for lockfile-optional platform-excluded dep", async () => {
    // platform-only-linux has os: [linux]; on darwin/arm64 it is excluded.
    const model = await buildProjectModel(
      path.join(fixtures, "npm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-only-linux")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("the normal resolved dep (lodash) is still resolved correctly", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-optional-platform"),
      DARWIN_ARM64
    );
    const ws = model.workspaces[0];
    expect(ws.deps.get("lodash")?.version).toBe("4.17.21");
  });
});

describe("npm optional dep absent from lockfile packages map entirely emits dep-unresolved", () => {
  it("optional npm dep with no lockfile entry is flagged as dep-unresolved on any host", async () => {
    // platform-absent-match-npm is in package.json optionalDependencies but has NO entry
    // in the lockfile packages map. With no constraint info, unknown ≠ safe: dep-unresolved
    // must fire regardless of host (we cannot know whether the package is platform-excluded).
    const model = await buildProjectModel(
      path.join(fixtures, "npm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-absent-match-npm")
    );
    expect(unresolved).toHaveLength(1);
  });

  it("same dep also emits dep-unresolved on a different host (no constraint info available)", async () => {
    // Same scenario on linux/x64 — since there are no lockfile constraints to suppress on,
    // the dep-unresolved must fire on this host too.
    const model = await buildProjectModel(
      path.join(fixtures, "npm-optional-platform"),
      LINUX_X64
    );
    const unresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("platform-absent-match-npm")
    );
    expect(unresolved).toHaveLength(1);
  });
});

describe("npm required dep absent from lockfile always emits dep-unresolved", () => {
  it("required dep missing from lockfile still emits dep-unresolved", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-optional-platform"),
      DARWIN_ARM64
    );
    const unresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("required-absent")
    );
    expect(unresolved).toHaveLength(1);
  });
});
