/**
 * Tests for the Node.js module resolver.
 *
 * Covers: relative specifiers, bare specifiers (lockfile-pinned + phantom),
 * exports/imports map with conditions and subpath patterns, workspace symlinks,
 * scoped packages, and dynamic/unresolved → UNKNOWN markers.
 */
import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveSpecifier } from "../../resolve/index.js";
import type {
  ResolveContext,
  ResolveResultFirstParty,
  ResolveResultThirdParty,
  ResolveResultUnknown,
} from "../../resolve/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(__dirname, "../../../testdata/projects");

// resolve-fixtures project built by build-fixtures.mjs globalSetup
const resolveFixtures = path.join(fixtures, "resolve-fixtures");

// ── 1. Relative specifiers ────────────────────────────────────────────────────

describe("resolveSpecifier – relative specifiers", () => {
  const dir = resolveFixtures;

  it("resolves ./index.js to the file itself", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(dir, "src", "app.js"),
      workspaceDir: dir,
      deps: new Map(),
    };
    const result = resolveSpecifier("./index.js", ctx);
    expect(result.kind).toBe("first-party");
    const fp = result as ResolveResultFirstParty;
    expect(fp.resolvedPath).toBe(path.join(dir, "src", "index.js"));
  });

  it("resolves ../lib/util.js relative to the fromFile directory", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(dir, "src", "app.js"),
      workspaceDir: dir,
      deps: new Map(),
    };
    const result = resolveSpecifier("../lib/util.js", ctx);
    expect(result.kind).toBe("first-party");
    const fp = result as ResolveResultFirstParty;
    expect(fp.resolvedPath).toBe(path.join(dir, "lib", "util.js"));
  });

  it("resolves extension-less specifier by trying .ts before .js", () => {
    // resolve-fixtures/src/typed.ts exists (no .js counterpart)
    const ctx: ResolveContext = {
      fromFile: path.join(dir, "src", "app.js"),
      workspaceDir: dir,
      deps: new Map(),
    };
    const result = resolveSpecifier("./typed", ctx);
    expect(result.kind).toBe("first-party");
    const fp = result as ResolveResultFirstParty;
    expect(fp.resolvedPath).toMatch(/typed\.(ts|tsx|js|jsx)$/);
  });

  it("resolves directory specifier to index file", () => {
    // resolve-fixtures/src/components/index.js exists
    const ctx: ResolveContext = {
      fromFile: path.join(dir, "src", "app.js"),
      workspaceDir: dir,
      deps: new Map(),
    };
    const result = resolveSpecifier("./components", ctx);
    expect(result.kind).toBe("first-party");
    const fp = result as ResolveResultFirstParty;
    expect(fp.resolvedPath).toMatch(/components[/\\]index\.(js|ts)$/);
  });

  it("returns UNKNOWN for a relative path that does not exist", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(dir, "src", "app.js"),
      workspaceDir: dir,
      deps: new Map(),
    };
    const result = resolveSpecifier("./nonexistent-file", ctx);
    expect(result.kind).toBe("unknown");
    const unk = result as ResolveResultUnknown;
    expect(unk.reason).toMatch(/not found|does not exist/i);
  });
});

// ── 2. Bare specifiers → lockfile-pinned ─────────────────────────────────────

describe("resolveSpecifier – bare specifiers (lockfile-pinned)", () => {
  it("resolves a bare specifier to the lockfile-pinned dir", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "lodash");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["lodash", { name: "lodash", version: "4.17.21", dir: pkgDir }]]),
    };
    const result = resolveSpecifier("lodash", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.packageName).toBe("lodash");
    expect(tp.version).toBe("4.17.21");
    expect(tp.resolvedPath).toContain("lodash");
    expect(tp.phantom).toBeFalsy();
  });

  it("resolves scoped package @scope/helper to its lockfile-pinned dir", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "@scope", "helper");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["@scope/helper", { name: "@scope/helper", version: "1.0.0", dir: pkgDir }]]),
    };
    const result = resolveSpecifier("@scope/helper", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.packageName).toBe("@scope/helper");
    expect(tp.version).toBe("1.0.0");
    expect(tp.phantom).toBeFalsy();
  });

  it("falls back to flat node_modules for phantom (hoisted but undeclared) dep", () => {
    // phantom-pkg is NOT in deps map but IS in node_modules
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map(), // empty: dep is not declared
    };
    const result = resolveSpecifier("phantom-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.phantom).toBe(true);
    expect(tp.packageName).toBe("phantom-pkg");
  });

  it("returns UNKNOWN for a bare specifier not in deps and not in node_modules", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map(),
    };
    const result = resolveSpecifier("totally-missing-package", ctx);
    expect(result.kind).toBe("unknown");
  });
});

// ── 3. exports map + conditions ───────────────────────────────────────────────

describe("resolveSpecifier – exports map + conditions", () => {
  it("resolves a package with exports map (import condition)", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["import", "default"],
    };
    const result = resolveSpecifier("exports-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.resolvedPath).toContain("exports-pkg");
  });

  it("resolves exports subpath exports-pkg/utils to the mapped file", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["import", "default"],
    };
    const result = resolveSpecifier("exports-pkg/utils", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.resolvedPath).toContain("utils");
  });

  it("honors require condition when present", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["require", "default"],
    };
    const result = resolveSpecifier("exports-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.resolvedPath).toMatch(/cjs|require/);
  });

  it("falls back to default condition when specific condition not matched", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["browser", "default"], // 'browser' not in exports map → falls back to default
    };
    const result = resolveSpecifier("exports-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.resolvedPath).toContain("exports-pkg");
  });

  it("returns UNKNOWN for a subpath not covered by exports map", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["import", "default"],
    };
    const result = resolveSpecifier("exports-pkg/nonexistent-subpath", ctx);
    expect(result.kind).toBe("unknown");
    const unk = result as ResolveResultUnknown;
    expect(unk.reason).toMatch(/not found in exports/i);
  });

  it("resolves subpath pattern exports-pkg/features/auth to the mapped pattern", () => {
    const pkgDir = path.join(resolveFixtures, "node_modules", "exports-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["exports-pkg", { name: "exports-pkg", version: "1.0.0", dir: pkgDir }]]),
      conditions: ["import", "default"],
    };
    const result = resolveSpecifier("exports-pkg/features/auth", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.resolvedPath).toContain("auth");
  });
});

// ── 4. Workspace symlinks ─────────────────────────────────────────────────────

describe("resolveSpecifier – workspace sibling (source-traversed)", () => {
  it("resolves a workspace sibling to its source directory (first-party)", () => {
    const appDir = path.join(resolveFixtures, "packages", "app");
    const utilsDir = path.join(resolveFixtures, "packages", "utils");
    const ctx: ResolveContext = {
      fromFile: path.join(appDir, "src", "index.js"),
      workspaceDir: appDir,
      deps: new Map([
        ["@ws/utils", { name: "@ws/utils", version: "1.0.0", dir: utilsDir }],
      ]),
      workspaceDirs: new Map([["@ws/utils", utilsDir]]),
    };
    const result = resolveSpecifier("@ws/utils", ctx);
    expect(result.kind).toBe("first-party");
    const fp = result as ResolveResultFirstParty;
    expect(fp.resolvedPath).toContain("utils");
    expect(fp.workspaceSibling).toBe(true);
  });
});

// ── 5. Dynamic / unresolved → UNKNOWN ────────────────────────────────────────

describe("resolveSpecifier – dynamic and unresolved specifiers", () => {
  it("null specifier (dynamic) returns UNKNOWN with dynamic reason", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map(),
    };
    const result = resolveSpecifier(null, ctx);
    expect(result.kind).toBe("unknown");
    const unk = result as ResolveResultUnknown;
    expect(unk.reason).toMatch(/dynamic/i);
  });

  it("null specifier always returns UNKNOWN regardless of deps map", () => {
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([["lodash", { name: "lodash", version: "4.17.21", dir: "/some/path" }]]),
    };
    const result = resolveSpecifier(null, ctx);
    expect(result.kind).toBe("unknown");
  });
});

// ── 6. Unresolvable exports root (#2) ────────────────────────────────────────

describe("resolveSpecifier – unresolvable exports root entry yields UNKNOWN (#2)", () => {
  it("returns UNKNOWN when exports field exists but has no matching condition for root entry", () => {
    // unknown-cond-pkg has exports with only an unknown condition (no default)
    const pkgDir = path.join(resolveFixtures, "node_modules", "unknown-cond-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map([
        ["unknown-cond-pkg", { name: "unknown-cond-pkg", version: "1.0.0", dir: pkgDir }],
      ]),
      conditions: ["import", "default"],
    };
    const result = resolveSpecifier("unknown-cond-pkg", ctx);
    expect(result.kind).toBe("unknown");
    const unk = result as ResolveResultUnknown;
    expect(unk.specifier).toBe("unknown-cond-pkg");
  });
});

// ── 7. Phantom flag only for truly undeclared deps (#3) ──────────────────────

describe("resolveSpecifier – phantom flag only for undeclared deps (#3)", () => {
  it("sets phantom:true for a dep found via flat walk that is NOT in declaredDeps", () => {
    // phantom-pkg is in node_modules but not in package.json deps
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map(), // not lockfile-pinned
      declaredDeps: new Set(), // not declared in manifest
    };
    const result = resolveSpecifier("phantom-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.phantom).toBe(true);
  });

  it("sets phantom:false for a dep found via flat walk that IS in declaredDeps but not lockfile-pinned", () => {
    // declared-flat-pkg is declared in manifest but absent from lockfile
    const pkgDir = path.join(resolveFixtures, "node_modules", "declared-flat-pkg");
    const ctx: ResolveContext = {
      fromFile: path.join(resolveFixtures, "src", "app.js"),
      workspaceDir: resolveFixtures,
      deps: new Map(), // not lockfile-pinned (simulates missing from lockfile)
      declaredDeps: new Set(["declared-flat-pkg"]), // declared in manifest
    };
    const result = resolveSpecifier("declared-flat-pkg", ctx);
    expect(result.kind).toBe("third-party");
    const tp = result as ResolveResultThirdParty;
    expect(tp.phantom).toBe(false);
  });
});
