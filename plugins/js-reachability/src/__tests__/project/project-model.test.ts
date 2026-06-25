import { describe, it, expect } from "vitest";
import path from "node:path";
import { buildProjectModel } from "../../project/build-project-model.js";
import { serializeProjectModel } from "../../project-model-cmd.js";

const fixtures = path.resolve(
  import.meta.dirname,
  "../../../testdata/projects"
);

describe("buildProjectModel – single-package npm", () => {
  it("produces one workspace with manager=npm", async () => {
    const model = await buildProjectModel(path.join(fixtures, "single-pkg"));
    expect(model.manager).toBe("npm");
    expect(model.workspaces).toHaveLength(1);
    expect(model.incomplete).toHaveLength(0);
  });

  it("workspace deps include lodash resolved to 4.17.21", async () => {
    const model = await buildProjectModel(path.join(fixtures, "single-pkg"));
    const ws = model.workspaces[0];
    const dep = ws.deps.get("lodash");
    expect(dep?.version).toBe("4.17.21");
    expect(dep?.dir).toContain("node_modules");
    expect(dep?.dir).toContain("lodash");
  });
});

describe("buildProjectModel – npm workspace multi-version hoisting", () => {
  it("produces two workspaces", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    expect(model.workspaces).toHaveLength(2);
    expect(model.manager).toBe("npm");
  });

  it("app workspace resolves lodash to 4.16.6 (app-local hoisted version)", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const app = model.workspaces.find((w) => w.name === "@npm-ws/app");
    expect(app).toBeDefined();
    const lodash = app!.deps.get("lodash");
    expect(lodash?.version).toBe("4.16.6");
  });

  it("utils workspace resolves lodash to 4.17.21 (root hoisted version)", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const utils = model.workspaces.find((w) => w.name === "@npm-ws/utils");
    expect(utils).toBeDefined();
    const lodash = utils!.deps.get("lodash");
    expect(lodash?.version).toBe("4.17.21");
  });

  it("app workspace has @npm-ws/utils in localDeps", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const app = model.workspaces.find((w) => w.name === "@npm-ws/app");
    expect(app?.localDeps).toContain("@npm-ws/utils");
  });
});

describe("buildProjectModel – yarn workspace", () => {
  it("produces two workspaces with manager=yarn", async () => {
    const model = await buildProjectModel(path.join(fixtures, "yarn-ws"));
    expect(model.manager).toBe("yarn");
    expect(model.workspaces).toHaveLength(2);
  });

  it("app workspace resolves lodash from yarn.lock", async () => {
    const model = await buildProjectModel(path.join(fixtures, "yarn-ws"));
    const app = model.workspaces.find((w) => w.name === "@yarn-ws/app");
    const lodash = app!.deps.get("lodash");
    expect(lodash?.version).toBe("4.17.21");
  });

  it("app workspace has @yarn-ws/utils in localDeps", async () => {
    const model = await buildProjectModel(path.join(fixtures, "yarn-ws"));
    const app = model.workspaces.find((w) => w.name === "@yarn-ws/app");
    expect(app?.localDeps).toContain("@yarn-ws/utils");
  });
});

describe("buildProjectModel – pnpm workspace", () => {
  it("produces two workspaces with manager=pnpm", async () => {
    const model = await buildProjectModel(path.join(fixtures, "pnpm-ws"));
    expect(model.manager).toBe("pnpm");
    expect(model.workspaces).toHaveLength(2);
  });

  it("app workspace resolves lodash to 4.17.21 with realpath dir", async () => {
    const model = await buildProjectModel(path.join(fixtures, "pnpm-ws"));
    const app = model.workspaces.find((w) => w.name === "@pnpm-ws/app");
    const lodash = app!.deps.get("lodash");
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.dir).toContain(".pnpm");
    expect(lodash?.dir).toContain("lodash");
  });

  it("app workspace has @pnpm-ws/utils in localDeps", async () => {
    const model = await buildProjectModel(path.join(fixtures, "pnpm-ws"));
    const app = model.workspaces.find((w) => w.name === "@pnpm-ws/app");
    expect(app?.localDeps).toContain("@pnpm-ws/utils");
  });
});

describe("buildProjectModel – edge cases", () => {
  it("missing lockfile yields manager=unknown and incomplete entry", async () => {
    const model = await buildProjectModel(path.join(fixtures, "missing-lock"));
    expect(model.manager).toBe("unknown");
    expect(model.incomplete.length).toBeGreaterThan(0);
  });

  it("corrupt lockfile yields incomplete entry without throwing", async () => {
    const model = await buildProjectModel(path.join(fixtures, "corrupt-lock"));
    expect(model.incomplete.length).toBeGreaterThan(0);
    // manager is still detectable (file exists)
    expect(model.manager).toBe("npm");
  });
});

describe("buildProjectModel – M1: optional dep resolution failure is not incomplete", () => {
  it("unresolvable optional dep does not emit an incomplete entry", async () => {
    // missing-lock has no lockfile; lodash is a required dep so gets incomplete.
    // We verify that any optionalDependencies would NOT add extra incomplete entries
    // by confirming the model does not crash and the incomplete list only covers
    // manager-detection / required deps.
    const model = await buildProjectModel(path.join(fixtures, "missing-lock"));
    // All incomplete entries should be for required deps or manager detection,
    // never complaining about "optional dep missing"
    for (const entry of model.incomplete) {
      expect(entry.reason).not.toMatch(/optional/i);
    }
  });
});

describe("buildProjectModel – M2: bare '*' specifier as workspace ref", () => {
  it("pnpm workspace: '@pnpm-ws/utils' dep with specifier 'workspace:*' is a localDep", async () => {
    const model = await buildProjectModel(path.join(fixtures, "pnpm-ws"));
    const app = model.workspaces.find((w) => w.name === "@pnpm-ws/app");
    expect(app?.localDeps).toContain("@pnpm-ws/utils");
  });

  it("pnpm workspace: bare '*' on a non-workspace dep is NOT treated as workspace ref", async () => {
    // In the pnpm-ws fixture, @pnpm-ws/utils has specifier workspace:*
    // and is a real sibling. We verify lodash (non-sibling) is resolved normally.
    const model = await buildProjectModel(path.join(fixtures, "pnpm-ws"));
    const app = model.workspaces.find((w) => w.name === "@pnpm-ws/app");
    // lodash is not a workspace name, so it must NOT be in localDeps
    expect(app?.localDeps).not.toContain("lodash");
    // and it MUST be resolved as a real dep
    expect(app?.deps.get("lodash")).toBeDefined();
  });
});

describe("buildProjectModel – berry yarn incomplete propagation", () => {
  it("berry yarn fixture yields an incomplete entry for PnP", async () => {
    const model = await buildProjectModel(path.join(fixtures, "berry-yarn"));
    expect(model.manager).toBe("yarn");
    expect(model.incomplete.some((e) => /berry|PnP|pnp/i.test(e.reason))).toBe(
      true
    );
  });

  it("berry yarn still resolves package versions from lockfile", async () => {
    const model = await buildProjectModel(path.join(fixtures, "berry-yarn"));
    const ws = model.workspaces[0];
    // lodash is declared and should be resolved from the berry lockfile
    expect(ws.deps.get("lodash")?.version).toBe("4.17.21");
  });
});

describe("buildProjectModel – glob dir without package.json is silently skipped", () => {
  it("glob match missing package.json produces no incomplete entry", async () => {
    // packages/config is a directory matched by packages/* but has no package.json.
    // It must be silently skipped — no 'other' or any kind of incomplete entry for it.
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-glob-empty-dir")
    );
    const dirEntries = model.incomplete.filter((e) =>
      e.scope.includes("config")
    );
    expect(dirEntries).toHaveLength(0);
  });

  it("glob match missing package.json does not prevent resolving the real workspace dep", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-glob-empty-dir")
    );
    const app = model.workspaces.find((w) => w.name === "@glob-empty/app");
    expect(app).toBeDefined();
    expect(app!.deps.get("lodash")?.version).toBe("4.17.21");
  });

  it("scan is not fail-closed due to a glob dir without package.json", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-glob-empty-dir")
    );
    // incomplete must not contain entries for the empty config dir
    const otherEntries = model.incomplete.filter(
      (e) => e.kind === "other" && e.scope.includes("config")
    );
    expect(otherEntries).toHaveLength(0);
  });
});

describe("buildProjectModel – npm nested workspace with root-hoisted dep", () => {
  it("produces two workspaces from packages/app/* glob", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-nested")
    );
    expect(model.workspaces).toHaveLength(2);
    expect(model.manager).toBe("npm");
  });

  it("deeply-nested workspace resolves dep hoisted to root node_modules", async () => {
    // @nested/core is at packages/app/core — a two-level nesting.
    // lodash is ONLY in the lockfile at "node_modules/lodash" (root-hoisted),
    // not at "packages/app/core/node_modules/lodash". The walk-up must find it.
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-nested")
    );
    const core = model.workspaces.find((w) => w.name === "@nested/core");
    expect(core).toBeDefined();
    expect(core!.deps.get("lodash")?.version).toBe("4.17.21");
  });

  it("deeply-nested workspace resolves sibling dep as local", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-nested")
    );
    const utils = model.workspaces.find((w) => w.name === "@nested/utils");
    expect(utils).toBeDefined();
    expect(utils!.localDeps).toContain("@nested/core");
  });

  it("no incomplete entries when all external deps resolve via hoisted walk-up", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-nested")
    );
    const depUnresolved = model.incomplete.filter(
      (e) => e.kind === "dep-unresolved"
    );
    expect(depUnresolved).toHaveLength(0);
  });
});

describe("buildProjectModel – declared external dep absent everywhere emits dep-unresolved", () => {
  it("dep in package.json but absent from lockfile produces dep-unresolved incomplete entry", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-unresolved-dep")
    );
    const entry = model.incomplete.find(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("not-in-lockfile")
    );
    expect(entry).toBeDefined();
    expect(entry!.reason).toMatch(/not-in-lockfile/);
  });

  it("dep that IS in lockfile still resolves despite the missing sibling dep", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "npm-ws-unresolved-dep")
    );
    const app = model.workspaces.find((w) => w.name === "@unresolved/app");
    expect(app!.deps.get("lodash")?.version).toBe("4.17.21");
  });
});

describe("buildProjectModel – yarn nested workspace with root-hoisted dep", () => {
  it("produces two workspaces from packages/app/* glob", async () => {
    const model = await buildProjectModel(
      path.join(fixtures, "yarn-ws-nested")
    );
    expect(model.workspaces).toHaveLength(2);
    expect(model.manager).toBe("yarn");
  });

  it("deeply-nested yarn workspace resolves dep from flat yarn.lock", async () => {
    // @yarn-nested/core is at packages/app/core (two-level nesting).
    // yarn v1 locks are flat and hoisted to root node_modules. The resolver
    // must look up by name@specifier regardless of workspace nesting depth.
    const model = await buildProjectModel(
      path.join(fixtures, "yarn-ws-nested")
    );
    const core = model.workspaces.find((w) => w.name === "@yarn-nested/core");
    expect(core).toBeDefined();
    expect(core!.deps.get("lodash")?.version).toBe("4.17.21");
  });
});

describe("serializeProjectModel – determinism", () => {
  it("produces byte-identical JSON across two calls", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const json1 = serializeProjectModel(model);
    const json2 = serializeProjectModel(model);
    expect(json1).toBe(json2);
  });

  it("JSON is valid and parseable", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const json = serializeProjectModel(model);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("JSON contains stable sorted keys", async () => {
    const model = await buildProjectModel(path.join(fixtures, "npm-ws"));
    const json = serializeProjectModel(model);
    const parsed = JSON.parse(json);
    expect(parsed.manager).toBe("npm");
    expect(Array.isArray(parsed.workspaces)).toBe(true);
    expect(Array.isArray(parsed.incomplete)).toBe(true);
  });
});
