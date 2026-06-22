/**
 * Vitest globalSetup: builds all gitignored fixture install layouts and
 * lockfiles so the test suite passes on a fresh checkout where node_modules
 * and lockfiles under testdata/ are absent.
 *
 * Run order: this runs once before any test file is loaded.
 * Idempotent: clears and rebuilds each generated directory on every run.
 *
 * What is built here (all gitignored by the root .gitignore):
 *   - package-lock.json files        (rule: package-lock.json)
 *   - pnpm-lock.yaml files           (rule: pnpm-lock.yaml)
 *   - yarn.lock files                (rule: yarn.lock)
 *   - node_modules install layouts   (rule: node_modules)
 *
 * What is NOT built here (static, committed to git):
 *   - package.json files
 *   - pnpm-workspace.yaml files
 *
 * Determinism: no timestamps, no random names, directories sorted where
 * iteration order matters.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projects = path.join(__dirname, "projects");

// ── helpers ──────────────────────────────────────────────────────────────────

function mkdir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/** Write a file, creating parent directories as needed. */
function write(filePath, content) {
  mkdir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, "utf8");
}

/** Write a minimal package.json with name and version. */
function writePkg(dir, name, version) {
  write(
    path.join(dir, "package.json"),
    JSON.stringify({ name, version }, null, 2) + "\n"
  );
}

/** Remove a directory tree if it exists. */
function rmdir(dir) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ── single-pkg ───────────────────────────────────────────────────────────────
// npm single-package project.
// lockfile: package-lock.json  node_modules: node_modules/lodash

function buildSinglePkg() {
  const root = path.join(projects, "single-pkg");

  // package-lock.json (gitignored)
  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "single-pkg",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "single-pkg",
            version: "1.0.0",
            dependencies: { lodash: "^4.17.21" },
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-abc123",
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  // node_modules/lodash (gitignored)
  const nmLodash = path.join(root, "node_modules", "lodash");
  rmdir(path.join(root, "node_modules"));
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
}

// ── npm-ws ───────────────────────────────────────────────────────────────────
// npm workspace: root + packages/app (lodash 4.16.6 local) + packages/utils
// hoisted: node_modules/lodash@4.17.21, node_modules/semver@7.6.0
// app-local: packages/app/node_modules/lodash@4.16.6

function buildNpmWs() {
  const root = path.join(projects, "npm-ws");

  // package-lock.json (gitignored)
  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "npm-ws-root",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "npm-ws-root",
            version: "1.0.0",
            workspaces: ["packages/*"],
            dependencies: { semver: "^7.6.0" },
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved:
              "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-abc",
          },
          "node_modules/semver": {
            version: "7.6.0",
            resolved:
              "https://registry.npmjs.org/semver/-/semver-7.6.0.tgz",
            integrity: "sha512-def",
          },
          "packages/app": {
            name: "@npm-ws/app",
            version: "1.0.0",
            dependencies: { lodash: "^4.17.21", "@npm-ws/utils": "*" },
          },
          "packages/app/node_modules/lodash": {
            version: "4.16.6",
            resolved:
              "https://registry.npmjs.org/lodash/-/lodash-4.16.6.tgz",
            integrity: "sha512-ghi",
          },
          "packages/utils": {
            name: "@npm-ws/utils",
            version: "1.0.0",
            dependencies: { lodash: "^4.16.0" },
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  // node_modules install layout (gitignored)
  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  const nmSemver = path.join(root, "node_modules", "semver");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
  mkdir(nmSemver);
  writePkg(nmSemver, "semver", "7.6.0");

  rmdir(path.join(root, "packages", "app", "node_modules"));
  const appNmLodash = path.join(
    root,
    "packages",
    "app",
    "node_modules",
    "lodash"
  );
  mkdir(appNmLodash);
  writePkg(appNmLodash, "lodash", "4.16.6");

  // packages/utils has no separate node_modules in this fixture
  rmdir(path.join(root, "packages", "utils", "node_modules"));
}

// ── yarn-ws ───────────────────────────────────────────────────────────────────
// yarn v1 workspace: root + packages/app + packages/utils
// node_modules: lodash@4.17.21, semver@7.6.0

function buildYarnWs() {
  const root = path.join(projects, "yarn-ws");

  // yarn.lock (gitignored)
  write(
    path.join(root, "yarn.lock"),
    [
      "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
      "# yarn lockfile v1",
      "",
      "",
      "lodash@^4.17.21:",
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"',
      "  integrity sha512-abc",
      "",
      "semver@^7.6.0:",
      '  version "7.6.0"',
      '  resolved "https://registry.yarnpkg.com/semver/-/semver-7.6.0.tgz#def"',
      "  integrity sha512-def",
      "",
    ].join("\n")
  );

  // node_modules install layout (gitignored)
  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  const nmSemver = path.join(root, "node_modules", "semver");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
  mkdir(nmSemver);
  writePkg(nmSemver, "semver", "7.6.0");
}

// ── pnpm-ws ───────────────────────────────────────────────────────────────────
// pnpm workspace: root + packages/app (lodash 4.17.21) + packages/utils (semver 7.6.0)
// .pnpm store: node_modules/.pnpm/lodash@4.17.21 + semver@7.6.0

function buildPnpmWs() {
  const root = path.join(projects, "pnpm-ws");

  // pnpm-lock.yaml (gitignored)
  write(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'",
      "",
      "settings:",
      "  autoInstallPeers: true",
      "  excludeLinksFromLockfile: false",
      "",
      "importers:",
      "",
      "  .:",
      "    specifiers: {}",
      "",
      "  packages/app:",
      "    dependencies:",
      "      lodash:",
      "        specifier: ^4.17.21",
      "        version: 4.17.21",
      "      '@pnpm-ws/utils':",
      "        specifier: 'workspace:*'",
      "        version: link:../utils",
      "    specifiers:",
      "      lodash: ^4.17.21",
      "      '@pnpm-ws/utils': 'workspace:*'",
      "",
      "  packages/utils:",
      "    dependencies:",
      "      semver:",
      "        specifier: ^7.6.0",
      "        version: 7.6.0",
      "    specifiers:",
      "      semver: ^7.6.0",
      "",
      "packages:",
      "",
      "  /lodash@4.17.21:",
      "    resolution: {integrity: sha512-abc}",
      "    dev: false",
      "",
      "  /semver@7.6.0:",
      "    resolution: {integrity: sha512-def}",
      "    dev: false",
      "",
    ].join("\n")
  );

  // .pnpm store layout (gitignored)
  // Real directories — realpath resolves to themselves
  rmdir(path.join(root, "node_modules"));

  const storeLodash = path.join(
    root,
    "node_modules",
    ".pnpm",
    "lodash@4.17.21",
    "node_modules",
    "lodash"
  );
  const storeSemver = path.join(
    root,
    "node_modules",
    ".pnpm",
    "semver@7.6.0",
    "node_modules",
    "semver"
  );
  mkdir(storeLodash);
  writePkg(storeLodash, "lodash", "4.17.21");
  mkdir(storeSemver);
  writePkg(storeSemver, "semver", "7.6.0");
}

// ── pnpm-multi-version ────────────────────────────────────────────────────────
// pnpm workspace: packages/app (lodash 4.16.6) + packages/lib (lodash 4.17.21)
// .pnpm store: both versions

function buildPnpmMultiVersion() {
  const root = path.join(projects, "pnpm-multi-version");

  // pnpm-lock.yaml (gitignored)
  write(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'",
      "",
      "settings:",
      "  autoInstallPeers: true",
      "  excludeLinksFromLockfile: false",
      "",
      "importers:",
      "",
      "  .:",
      "    specifiers: {}",
      "",
      "  packages/app:",
      "    dependencies:",
      "      lodash:",
      "        specifier: ^4.16.6",
      "        version: 4.16.6",
      "",
      "  packages/lib:",
      "    dependencies:",
      "      lodash:",
      "        specifier: ^4.17.21",
      "        version: 4.17.21",
      "",
      "packages:",
      "",
      "  /lodash@4.16.6:",
      "    resolution: {integrity: sha512-old}",
      "    dev: false",
      "",
      "  /lodash@4.17.21:",
      "    resolution: {integrity: sha512-new}",
      "    dev: false",
      "",
    ].join("\n")
  );

  // .pnpm store layout (gitignored)
  rmdir(path.join(root, "node_modules"));

  for (const version of ["4.16.6", "4.17.21"].sort()) {
    const storeDir = path.join(
      root,
      "node_modules",
      ".pnpm",
      `lodash@${version}`,
      "node_modules",
      "lodash"
    );
    mkdir(storeDir);
    writePkg(storeDir, "lodash", version);
  }
}

// ── corrupt-lock ─────────────────────────────────────────────────────────────
// npm project with an unparseable package-lock.json

function buildCorruptLock() {
  const root = path.join(projects, "corrupt-lock");
  write(
    path.join(root, "package-lock.json"),
    "{ this is not valid json !!!\n"
  );
}

// ── corrupt-lock-dev-only ────────────────────────────────────────────────────
// npm project with an unparseable package-lock.json and only devDependencies
// (zero runtime deps) — exercises that a corrupt lockfile marks the scan
// incomplete even when there is nothing to resolve.

function buildCorruptLockDevOnly() {
  const root = path.join(projects, "corrupt-lock-dev-only");
  write(
    path.join(root, "package-lock.json"),
    "{ this is not valid json !!!\n"
  );
}

// ── corrupt-pnpm ─────────────────────────────────────────────────────────────
// pnpm project with an unparseable pnpm-lock.yaml

function buildCorruptPnpm() {
  const root = path.join(projects, "corrupt-pnpm");
  write(
    path.join(root, "pnpm-lock.yaml"),
    "this: is: not: valid: yaml: [{\n"
  );
}

// ── corrupt-yarn ─────────────────────────────────────────────────────────────
// yarn project with an unparseable yarn.lock

function buildCorruptYarn() {
  const root = path.join(projects, "corrupt-yarn");
  write(
    path.join(root, "yarn.lock"),
    "this is not a valid\nyarn lockfile format !!!\n@@@badly\n"
  );
}

// ── missing-dep-pnpm ─────────────────────────────────────────────────────────
// pnpm project where package.json declares a dep NOT in the lockfile

function buildMissingDepPnpm() {
  const root = path.join(projects, "missing-dep-pnpm");
  write(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      lodash:",
      "        specifier: ^4.17.21",
      "        version: 4.17.21",
      "      not-in-lockfile:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "",
      "packages:",
      "",
      "  /lodash@4.17.21:",
      "    resolution: {integrity: sha512-abc}",
      "    dev: false",
      "",
    ].join("\n")
  );
}

// ── berry-yarn ───────────────────────────────────────────────────────────────
// yarn berry (v2+) project with __metadata block

function buildBerryYarn() {
  const root = path.join(projects, "berry-yarn");
  write(
    path.join(root, "yarn.lock"),
    [
      "__metadata:",
      "  version: 6",
      "  cacheKey: 8",
      "",
      '"lodash@npm:^4.17.21":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "  checksum: abc",
      "  languageName: node",
      "  linkType: hard",
      "",
    ].join("\n")
  );
}

// ── pnpm-peer-suffix ─────────────────────────────────────────────────────────
// pnpm project with peer-suffixed package keys (pnpm v6/v9 format)

function buildPnpmPeerSuffix() {
  const root = path.join(projects, "pnpm-peer-suffix");
  write(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      lodash:",
      "        specifier: ^4.17.21",
      "        version: 4.17.21(react@18.0.0)",
      "      '@scope/helper':",
      "        specifier: ^1.0.0",
      "        version: 1.0.0(peer@2.0.0)",
      "",
      "packages:",
      "",
      "  /lodash@4.17.21(react@18.0.0):",
      "    resolution: {integrity: sha512-abc}",
      "    dev: false",
      "",
      "  /@scope/helper@1.0.0(peer@2.0.0):",
      "    resolution: {integrity: sha512-def}",
      "    dev: false",
      "",
    ].join("\n")
  );
}

// ── resolve-fixtures ─────────────────────────────────────────────────────────
// A synthetic project layout exercising all resolver paths:
//   - relative specifiers (src/app.js → ./index.js, ../lib/util.js)
//   - extension-less resolution (./typed → typed.ts)
//   - directory/index resolution (./components → components/index.js)
//   - bare specifier → pinned dep (lodash in node_modules)
//   - scoped dep (@scope/helper)
//   - phantom dep (phantom-pkg: in node_modules but NOT declared in manifest)
//   - exports map (exports-pkg: with import/require/default conditions + subpaths)
//   - workspace sibling (@ws/utils)
//   - parser fixtures (ESM, CJS, TS, TSX, dynamic import, syntax error)

function buildResolveFixtures() {
  const root = path.join(projects, "resolve-fixtures");

  // ── source files ──────────────────────────────────────────────────────────

  // src/app.js — ESM file with static imports used by resolver + parser tests
  write(
    path.join(root, "src", "app.js"),
    [
      `import _ from "lodash";`,
      `import { helper } from "./index.js";`,
      `export function main() { return _; }`,
      "",
    ].join("\n")
  );

  // src/index.js — re-exports, used as directory/index target and named exports test
  write(
    path.join(root, "src", "index.js"),
    [
      `export function helper() {}`,
      `export function util() {}`,
      "",
    ].join("\n")
  );

  // src/typed.ts — TypeScript file (no .js counterpart) for extension-less resolution
  write(
    path.join(root, "src", "typed.ts"),
    [
      `import { helper } from "./index.js";`,
      `export function greet(name: string): string { return "hello " + name; }`,
      "",
    ].join("\n")
  );

  // src/component.tsx — TSX file
  write(
    path.join(root, "src", "component.tsx"),
    [
      `import React from "react";`,
      `export function Button() { return null; }`,
      "",
    ].join("\n")
  );

  // src/components/index.js — for directory specifier resolution
  write(
    path.join(root, "src", "components", "index.js"),
    `export const Button = () => {};` + "\n"
  );

  // lib/util.js — for ../lib/util.js relative resolution from src/
  write(
    path.join(root, "lib", "util.js"),
    `export function noop() {}` + "\n"
  );

  // src/dyn-import.js — literal dynamic import()
  write(
    path.join(root, "src", "dyn-import.js"),
    [
      `async function load() {`,
      `  const m = await import("./lazy");`,
      `  return m;`,
      `}`,
      "",
    ].join("\n")
  );

  // src/lazy.js — target of the dynamic import above
  write(
    path.join(root, "src", "lazy.js"),
    `export const lazy = true;` + "\n"
  );

  // src/dyn-var.js — dynamic import with a variable (non-literal)
  // Wrapped in an async function so the file is valid in "unambiguous" mode.
  write(
    path.join(root, "src", "dyn-var.js"),
    [
      `export async function loadDynamic() {`,
      `  const name = getModuleName();`,
      `  const m = await import(name);`,
      `  return m;`,
      `}`,
      "",
    ].join("\n")
  );

  // src/cjs-module.cjs — CJS with literal require()
  write(
    path.join(root, "src", "cjs-module.cjs"),
    [
      `const path = require("path");`,
      `const helper = require("./helper");`,
      `module.exports = { path, helper };`,
      "",
    ].join("\n")
  );

  // src/helper.cjs — target of cjs-module.cjs require
  write(
    path.join(root, "src", "helper.cjs"),
    `module.exports = function helper() {};` + "\n"
  );

  // src/cjs-dynamic.cjs — CJS with dynamic require(variable)
  write(
    path.join(root, "src", "cjs-dynamic.cjs"),
    [
      `function load(name) {`,
      `  return require(name);`,
      `}`,
      `module.exports = load;`,
      "",
    ].join("\n")
  );

  // src/syntax-error.js — intentional parse error
  write(
    path.join(root, "src", "syntax-error.js"),
    `export function broken( {` + "\n"
  );

  // src/reexport-star.js — re-export all from another module
  write(
    path.join(root, "src", "reexport-star.js"),
    `export * from "./utils.js";` + "\n"
  );

  // src/reexport-named.js — named re-export from another module
  write(
    path.join(root, "src", "reexport-named.js"),
    `export { helper } from "./helpers.js";` + "\n"
  );

  // src/reexport-renamed.js — renamed re-export from another module
  write(
    path.join(root, "src", "reexport-renamed.js"),
    `export { base as renamed } from "./base.js";` + "\n"
  );

  // src/utils.js, src/helpers.js, src/base.js — targets of re-exports
  write(path.join(root, "src", "utils.js"), `export const utils = true;` + "\n");
  write(path.join(root, "src", "helpers.js"), `export function helper() {}` + "\n");
  write(path.join(root, "src", "base.js"), `export const base = 1;` + "\n");

  // src/cjs-plain.js — plain .js file using only require() (no ESM syntax)
  write(
    path.join(root, "src", "cjs-plain.js"),
    [
      `const fs = require("fs");`,
      `const util = require("./util.js");`,
      `module.exports = { fs, util };`,
      "",
    ].join("\n")
  );

  // packages/app/src/index.js — workspace app entry
  write(
    path.join(root, "packages", "app", "src", "index.js"),
    [
      `import { helper } from "@ws/utils";`,
      `export function app() { return helper(); }`,
      "",
    ].join("\n")
  );

  // packages/app/src/custom-entry.js — for explicit entrypoint override test
  write(
    path.join(root, "packages", "app", "src", "custom-entry.js"),
    `export function custom() {}` + "\n"
  );

  // packages/app/bin/cli.js — bin script
  write(
    path.join(root, "packages", "app", "bin", "cli.js"),
    `#!/usr/bin/env node\nconsole.log("cli");` + "\n"
  );

  // packages/utils/src/index.js — workspace utils entry
  write(
    path.join(root, "packages", "utils", "src", "index.js"),
    `export function helper() { return 42; }` + "\n"
  );

  // ── package.json files (static, not gitignored) ───────────────────────────

  // Root package.json for resolve-fixtures
  write(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "resolve-fixtures",
        version: "1.0.0",
        private: true,
        dependencies: {
          lodash: "^4.17.21",
          "@scope/helper": "^1.0.0",
          "exports-pkg": "^1.0.0",
          // NOTE: phantom-pkg intentionally NOT declared here
        },
      },
      null,
      2
    ) + "\n"
  );

  // packages/app package.json
  write(
    path.join(root, "packages", "app", "package.json"),
    JSON.stringify(
      {
        name: "@ws/app",
        version: "1.0.0",
        private: true,
        bin: { "my-app": "./bin/cli.js" },
        main: "./src/index.js",
        dependencies: {
          "@ws/utils": "workspace:*",
          lodash: "^4.17.21",
        },
      },
      null,
      2
    ) + "\n"
  );

  // packages/utils package.json
  write(
    path.join(root, "packages", "utils", "package.json"),
    JSON.stringify(
      {
        name: "@ws/utils",
        version: "1.0.0",
        main: "./src/index.js",
        exports: { ".": "./src/index.js" },
      },
      null,
      2
    ) + "\n"
  );

  // ── node_modules layout (gitignored) ──────────────────────────────────────
  rmdir(path.join(root, "node_modules"));

  // lodash (lockfile-pinned dep)
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
  write(path.join(nmLodash, "index.js"), `module.exports = {};` + "\n");

  // @scope/helper (scoped dep)
  const nmScopeHelper = path.join(root, "node_modules", "@scope", "helper");
  mkdir(nmScopeHelper);
  write(
    path.join(nmScopeHelper, "package.json"),
    JSON.stringify({ name: "@scope/helper", version: "1.0.0", main: "./index.js" }, null, 2) + "\n"
  );
  write(path.join(nmScopeHelper, "index.js"), `module.exports = {};` + "\n");

  // phantom-pkg (in node_modules but NOT in package.json deps — phantom)
  const nmPhantom = path.join(root, "node_modules", "phantom-pkg");
  mkdir(nmPhantom);
  writePkg(nmPhantom, "phantom-pkg", "2.0.0");
  write(path.join(nmPhantom, "index.js"), `module.exports = {};` + "\n");

  // exports-pkg — package with exports map, conditions, subpaths, and patterns
  const nmExportsPkg = path.join(root, "node_modules", "exports-pkg");
  mkdir(nmExportsPkg);
  write(
    path.join(nmExportsPkg, "package.json"),
    JSON.stringify(
      {
        name: "exports-pkg",
        version: "1.0.0",
        exports: {
          ".": {
            import: "./esm/index.js",
            require: "./cjs/index.js",
            default: "./esm/index.js",
          },
          "./utils": {
            import: "./esm/utils.js",
            default: "./esm/utils.js",
          },
          "./features/*": {
            import: "./esm/features/*.js",
            default: "./esm/features/*.js",
          },
        },
      },
      null,
      2
    ) + "\n"
  );
  // ESM entry
  mkdir(path.join(nmExportsPkg, "esm"));
  write(path.join(nmExportsPkg, "esm", "index.js"), `export const x = 1;` + "\n");
  write(path.join(nmExportsPkg, "esm", "utils.js"), `export const utils = true;` + "\n");
  mkdir(path.join(nmExportsPkg, "esm", "features"));
  write(path.join(nmExportsPkg, "esm", "features", "auth.js"), `export const auth = true;` + "\n");
  // CJS entry (for require condition)
  mkdir(path.join(nmExportsPkg, "cjs"));
  write(path.join(nmExportsPkg, "cjs", "index.js"), `module.exports = {};` + "\n");

  // unknown-cond-pkg — package whose exports has only an unknown condition (no default)
  // Resolving its root entry with standard conditions must yield UNKNOWN, not a directory.
  const nmUnknownCond = path.join(root, "node_modules", "unknown-cond-pkg");
  mkdir(nmUnknownCond);
  write(
    path.join(nmUnknownCond, "package.json"),
    JSON.stringify(
      {
        name: "unknown-cond-pkg",
        version: "1.0.0",
        exports: {
          ".": {
            "electron": "./electron.js",
          },
        },
      },
      null,
      2
    ) + "\n"
  );
  write(path.join(nmUnknownCond, "electron.js"), `module.exports = {};` + "\n");

  // declared-flat-pkg — in node_modules but intentionally absent from lockfile-pinned deps
  // Used to verify phantom:false when the dep IS declared in the manifest.
  const nmDeclaredFlat = path.join(root, "node_modules", "declared-flat-pkg");
  mkdir(nmDeclaredFlat);
  writePkg(nmDeclaredFlat, "declared-flat-pkg", "3.0.0");
  write(path.join(nmDeclaredFlat, "index.js"), `module.exports = {};` + "\n");
}

// ── entry point ──────────────────────────────────────────────────────────────

export default function setup() {
  buildSinglePkg();
  buildNpmWs();
  buildYarnWs();
  buildPnpmWs();
  buildPnpmMultiVersion();
  buildCorruptLock();
  buildCorruptLockDevOnly();
  buildCorruptPnpm();
  buildCorruptYarn();
  buildMissingDepPnpm();
  buildBerryYarn();
  buildPnpmPeerSuffix();
  buildResolveFixtures();
}
