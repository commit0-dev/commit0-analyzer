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

// ── pnpm-scoped-store ─────────────────────────────────────────────────────────
// A pnpm project with a SCOPED dependency and a peer-dep-suffixed scoped
// dependency. pnpm encodes the scope "/" as "+" in the .pnpm store directory
// name and appends "_<encoded-peers>" for peer-resolved packages. Both must
// resolve in the virtual store (regression for scoped-dep resolution).

function buildPnpmScopedStore() {
  const root = path.join(projects, "pnpm-scoped-store");

  write(
    path.join(root, "pnpm-lock.yaml"),
    [
      "lockfileVersion: '6.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      '@scope/pkg':",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "      '@scope/peered':",
      "        specifier: ^1.0.0",
      "        version: 1.0.0(react@18.0.0)",
      "    specifiers:",
      "      '@scope/pkg': ^1.0.0",
      "      '@scope/peered': ^1.0.0",
      "",
      "packages:",
      "",
      "  /@scope/pkg@1.0.0:",
      "    resolution: {integrity: sha512-a}",
      "    dev: false",
      "",
      "  /@scope/peered@1.0.0(react@18.0.0):",
      "    resolution: {integrity: sha512-b}",
      "    dev: false",
      "",
    ].join("\n")
  );

  write(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "pnpm-scoped-store",
        version: "1.0.0",
        dependencies: { "@scope/pkg": "^1.0.0", "@scope/peered": "^1.0.0" },
      },
      null,
      2
    ) + "\n"
  );

  rmdir(path.join(root, "node_modules"));

  // Scoped store dir: @scope+pkg@1.0.0
  const storePkg = path.join(
    root, "node_modules", ".pnpm", "@scope+pkg@1.0.0", "node_modules", "@scope", "pkg"
  );
  mkdir(storePkg);
  writePkg(storePkg, "@scope/pkg", "1.0.0");

  // Peer-suffixed scoped store dir: @scope+peered@1.0.0_react@18.0.0
  const storePeered = path.join(
    root, "node_modules", ".pnpm", "@scope+peered@1.0.0_react@18.0.0", "node_modules", "@scope", "peered"
  );
  mkdir(storePeered);
  writePkg(storePeered, "@scope/peered", "1.0.0");
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

// ── gate-g1 ───────────────────────────────────────────────────────────────────
// Gate G1-JS fixture: a minimal npm project that exercises the four labeled
// confidence tiers required by Phase 5.
//
// Packages installed:
//   serialize-javascript@3.0.0  — real npm advisory GHSA-h9rv-jmmf-4pgx
//   lodash@4.17.21              — installed but NEVER imported (tier b)
//
// Source files:
//   src/index.js        — imports and calls serialize-javascript (tier a)
//   src/dyn-require.js  — dynamic require(variable) path (tier c)
//   src/symbol-caller.js — imports the named export 'serialize' directly (tier d)

function buildGateG1() {
  const root = path.join(projects, "gate-g1");

  // ── package.json (static — must already exist as committed file) ──────────
  write(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "gate-g1",
        version: "1.0.0",
        private: true,
        main: "./src/index.js",
        dependencies: {
          "serialize-javascript": "^3.0.0",
          lodash: "^4.17.21",
        },
      },
      null,
      2
    ) + "\n"
  );

  // ── Source files ──────────────────────────────────────────────────────────

  // tier (a): imports and calls serialize-javascript
  write(
    path.join(root, "src", "index.js"),
    [
      `const serialize = require("serialize-javascript");`,
      ``,
      `function run(data) {`,
      `  return serialize(data);`,
      `}`,
      ``,
      `module.exports = { run };`,
      ``,
    ].join("\n")
  );

  // tier (c): dynamic require — the specifier is a variable, not a literal
  write(
    path.join(root, "src", "dyn-require.js"),
    [
      `function loadPlugin(name) {`,
      `  // non-literal specifier → UNKNOWN frontier`,
      `  return require(name);`,
      `}`,
      ``,
      `module.exports = { loadPlugin };`,
      ``,
    ].join("\n")
  );

  // tier (d): imports the named export 'serialize' via ESM destructure
  // so the engine can trace it as a symbol-level call
  write(
    path.join(root, "src", "symbol-caller.js"),
    [
      `const { serialize } = require("serialize-javascript");`,
      ``,
      `function callIt(data) {`,
      `  return serialize(data);`,
      `}`,
      ``,
      `module.exports = { callIt };`,
      ``,
    ].join("\n")
  );

  // ── package-lock.json (gitignored) ────────────────────────────────────────
  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "gate-g1",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "gate-g1",
            version: "1.0.0",
            dependencies: {
              "serialize-javascript": "^3.0.0",
              lodash: "^4.17.21",
            },
          },
          "node_modules/serialize-javascript": {
            version: "3.0.0",
            resolved:
              "https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-3.0.0.tgz",
            integrity: "sha512-gate-g1-fixture",
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved:
              "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-gate-g1-lodash",
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  // ── node_modules layout (gitignored) ──────────────────────────────────────
  rmdir(path.join(root, "node_modules"));

  // serialize-javascript — the vulnerable package being tested
  const nmSerialize = path.join(root, "node_modules", "serialize-javascript");
  mkdir(nmSerialize);
  write(
    path.join(nmSerialize, "package.json"),
    JSON.stringify(
      { name: "serialize-javascript", version: "3.0.0", main: "./index.js" },
      null,
      2
    ) + "\n"
  );
  // Minimal implementation that exports 'serialize' as the main export AND
  // as a named property so both default and destructured imports resolve.
  write(
    path.join(nmSerialize, "index.js"),
    [
      `function serialize(val) { return JSON.stringify(val); }`,
      `serialize.serialize = serialize;`,
      `module.exports = serialize;`,
      ``,
    ].join("\n")
  );

  // lodash — installed but never imported by any fixture source file (tier b)
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  write(
    path.join(nmLodash, "package.json"),
    JSON.stringify(
      { name: "lodash", version: "4.17.21", main: "./lodash.js" },
      null,
      2
    ) + "\n"
  );
  write(
    path.join(nmLodash, "lodash.js"),
    `module.exports = {};` + "\n"
  );
}

// ── no-entrypoint-ws ──────────────────────────────────────────────────────────
// A private package that declares and imports a vulnerable dependency but has
// no bin, main, or exports — so no entrypoint is resolvable. The engine must
// return UNKNOWN (not NOT_REACHABLE) for its advisories: with no root to
// traverse from, "not reachable" would be a false negative.

function buildNoEntrypointWs() {
  const root = path.join(projects, "no-entrypoint-ws");

  write(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "no-entrypoint-ws",
        version: "1.0.0",
        private: true,
        // intentionally NO main / module / exports / bin
        dependencies: { "serialize-javascript": "^3.0.0" },
      },
      null,
      2
    ) + "\n"
  );

  // The dependency is genuinely imported by source, but that source is not an
  // entrypoint (no main/bin/exports reference it), mirroring a private example
  // app whose dep is used only via test files or unparsed component files.
  write(
    path.join(root, "lib", "uses-dep.js"),
    [
      `const serialize = require("serialize-javascript");`,
      `module.exports = (data) => serialize(data);`,
      ``,
    ].join("\n")
  );

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "no-entrypoint-ws",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "no-entrypoint-ws",
            version: "1.0.0",
            dependencies: { "serialize-javascript": "^3.0.0" },
          },
          "node_modules/serialize-javascript": {
            version: "3.0.0",
            resolved:
              "https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-3.0.0.tgz",
            integrity: "sha512-stub",
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  rmdir(path.join(root, "node_modules"));
  const nm = path.join(root, "node_modules", "serialize-javascript");
  mkdir(nm);
  write(
    path.join(nm, "package.json"),
    JSON.stringify(
      { name: "serialize-javascript", version: "3.0.0", main: "./index.js" },
      null,
      2
    ) + "\n"
  );
  write(path.join(nm, "index.js"), `module.exports = function () {};\n`);
}

// ── default-index-ws ──────────────────────────────────────────────────────────
// A package with NO main/exports but an index.js at the root that imports and
// calls a vulnerable dependency. Node resolves the entry to index.js by default,
// so the engine must detect it and report PACKAGE_REACHABLE (not UNKNOWN).

function buildDefaultIndexWs() {
  const root = path.join(projects, "default-index-ws");

  write(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "default-index-ws",
        version: "1.0.0",
        // NO main / module / exports / bin — Node defaults the entry to index.js
        dependencies: { "serialize-javascript": "^3.0.0" },
      },
      null,
      2
    ) + "\n"
  );

  write(
    path.join(root, "index.js"),
    [
      `const serialize = require("serialize-javascript");`,
      `module.exports = (data) => serialize(data);`,
      ``,
    ].join("\n")
  );

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "default-index-ws",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "default-index-ws",
            version: "1.0.0",
            dependencies: { "serialize-javascript": "^3.0.0" },
          },
          "node_modules/serialize-javascript": {
            version: "3.0.0",
            resolved:
              "https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-3.0.0.tgz",
            integrity: "sha512-stub",
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  rmdir(path.join(root, "node_modules"));
  const nm = path.join(root, "node_modules", "serialize-javascript");
  mkdir(nm);
  write(
    path.join(nm, "package.json"),
    JSON.stringify(
      { name: "serialize-javascript", version: "3.0.0", main: "./index.js" },
      null,
      2
    ) + "\n"
  );
  write(path.join(nm, "index.js"), `module.exports = function () {};\n`);
}

// ── Corpus fixture builders ───────────────────────────────────────────────────
// Each corpus case commits source + labels.json + package.json.
// This section generates the gitignored lockfiles and node_modules layouts.

const corpus = path.join(__dirname, "corpus");

/** Minimal serialize-javascript stub used across corpus cases. */
function installSerializeJavascript(root, version = "3.0.0") {
  const nmSj = path.join(root, "node_modules", "serialize-javascript");
  mkdir(nmSj);
  write(
    path.join(nmSj, "package.json"),
    JSON.stringify({ name: "serialize-javascript", version, main: "./index.js" }, null, 2) + "\n"
  );
  write(
    path.join(nmSj, "index.js"),
    [
      `function serialize(val) { return JSON.stringify(val); }`,
      `serialize.serialize = serialize;`,
      `module.exports = serialize;`,
      ``,
    ].join("\n")
  );
}

/** Minimal npm lockfile entry for serialize-javascript. */
function sjLockEntry(version = "3.0.0") {
  return {
    version,
    resolved: `https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-${version}.tgz`,
    integrity: `sha512-corpus-fixture-${version}`,
  };
}

// ── corpus/cjs-direct ─────────────────────────────────────────────────────────
function buildCorpusCjsDirect() {
  const root = path.join(corpus, "cjs-direct");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-cjs-direct",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-cjs-direct", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/esm-direct ─────────────────────────────────────────────────────────
function buildCorpusEsmDirect() {
  const root = path.join(corpus, "esm-direct");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-esm-direct",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-esm-direct", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/mixed-dual ─────────────────────────────────────────────────────────
function buildCorpusMixedDual() {
  const root = path.join(corpus, "mixed-dual");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-mixed-dual",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-mixed-dual", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/ts-direct ──────────────────────────────────────────────────────────
function buildCorpusTsDirect() {
  const root = path.join(corpus, "ts-direct");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-ts-direct",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-ts-direct", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0", "@types/serialize-javascript": "^5.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
        "node_modules/@types/serialize-javascript": {
          version: "5.0.4",
          resolved: "https://registry.npmjs.org/@types/serialize-javascript/-/serialize-javascript-5.0.4.tgz",
          integrity: "sha512-corpus-types-sj",
          dev: true,
        },
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");

  // minimal @types stub
  const typesDir = path.join(root, "node_modules", "@types", "serialize-javascript");
  mkdir(typesDir);
  write(
    path.join(typesDir, "package.json"),
    JSON.stringify({ name: "@types/serialize-javascript", version: "5.0.4" }, null, 2) + "\n"
  );
  write(
    path.join(typesDir, "index.d.ts"),
    `declare function serialize(val: unknown): string;\nexport = serialize;\n`
  );
}

// ── corpus/transitive-ws ──────────────────────────────────────────────────────
// pnpm workspace: app -> lib -> serialize-javascript
function buildCorpusTransitiveWs() {
  const root = path.join(corpus, "transitive-ws");
  rmdir(path.join(root, "node_modules"));

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
      "      '@corpus-transitive-ws/lib':",
      "        specifier: 'workspace:*'",
      "        version: link:../lib",
      "    specifiers:",
      "      '@corpus-transitive-ws/lib': 'workspace:*'",
      "",
      "  packages/lib:",
      "    dependencies:",
      "      serialize-javascript:",
      "        specifier: ^3.0.0",
      "        version: 3.0.0",
      "    specifiers:",
      "      serialize-javascript: ^3.0.0",
      "",
      "packages:",
      "",
      "  /serialize-javascript@3.0.0:",
      "    resolution: {integrity: sha512-corpus-transitive-ws}",
      "    dev: false",
      "",
    ].join("\n")
  );

  // pnpm strict layout: serialize-javascript lives under lib's local node_modules
  const appNm = path.join(root, "packages", "app", "node_modules");
  const libNm = path.join(root, "packages", "lib", "node_modules");

  // app -> lib symlink (pnpm workspace link)
  mkdir(appNm);
  const appLibLink = path.join(appNm, "@corpus-transitive-ws", "lib");
  mkdir(path.dirname(appLibLink));
  // Use a real directory instead of a symlink for test stability
  if (!fs.existsSync(appLibLink)) {
    fs.symlinkSync(path.join(root, "packages", "lib"), appLibLink, "dir");
  }

  // lib's node_modules contains serialize-javascript
  installSerializeJavascript(path.join(root, "packages", "lib"), "3.0.0");
  // also install at root level for import resolution fallback
  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/not-imported ───────────────────────────────────────────────────────
function buildCorpusNotImported() {
  const root = path.join(corpus, "not-imported");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-not-imported",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-not-imported", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0", "lodash": "^4.17.21" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
        "node_modules/lodash": {
          version: "4.17.21",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
          integrity: "sha512-corpus-not-imported-lodash",
        },
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");

  // lodash is installed but only it is imported by the fixture
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
  write(path.join(nmLodash, "lodash.js"), `module.exports = { identity: (x) => x };\n`);
  write(
    path.join(nmLodash, "package.json"),
    JSON.stringify({ name: "lodash", version: "4.17.21", main: "./lodash.js" }, null, 2) + "\n"
  );
}

// ── corpus/imported-unrelated-export ─────────────────────────────────────────
function buildCorpusImportedUnrelatedExport() {
  const root = path.join(corpus, "imported-unrelated-export");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-imported-unrelated-export",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-imported-unrelated-export", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/dyn-require-var ────────────────────────────────────────────────────
function buildCorpusDynRequireVar() {
  const root = path.join(corpus, "dyn-require-var");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-dyn-require-var",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-dyn-require-var", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/dyn-import-expr ────────────────────────────────────────────────────
function buildCorpusDynImportExpr() {
  const root = path.join(corpus, "dyn-import-expr");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-dyn-import-expr",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-dyn-import-expr", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/eval-reached ───────────────────────────────────────────────────────
function buildCorpusEvalReached() {
  const root = path.join(corpus, "eval-reached");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-eval-reached",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-eval-reached", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/missing-lockfile ───────────────────────────────────────────────────
// Intentionally NO lockfile — the corpus builder generates node_modules but
// leaves no lockfile on disk so the engine's lockfile-missing path fires.
function buildCorpusMissingLockfile() {
  const root = path.join(corpus, "missing-lockfile");
  rmdir(path.join(root, "node_modules"));

  // node_modules exists (installed) but no lockfile — engine detects missing lock
  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/pnpm-strict-ws ─────────────────────────────────────────────────────
function buildCorpusPnpmStrictWs() {
  const root = path.join(corpus, "pnpm-strict-ws");
  rmdir(path.join(root, "node_modules"));

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
      "      serialize-javascript:",
      "        specifier: ^3.0.0",
      "        version: 3.0.0",
      "      '@corpus-pnpm-strict/utils':",
      "        specifier: 'workspace:*'",
      "        version: link:../utils",
      "    specifiers:",
      "      serialize-javascript: ^3.0.0",
      "      '@corpus-pnpm-strict/utils': 'workspace:*'",
      "",
      "  packages/utils:",
      "    specifiers: {}",
      "",
      "packages:",
      "",
      "  /serialize-javascript@3.0.0:",
      "    resolution: {integrity: sha512-corpus-pnpm-strict-ws}",
      "    dev: false",
      "",
    ].join("\n")
  );

  // pnpm .pnpm store layout
  const storeSj = path.join(root, "node_modules", ".pnpm", "serialize-javascript@3.0.0", "node_modules", "serialize-javascript");
  mkdir(storeSj);
  write(
    path.join(storeSj, "package.json"),
    JSON.stringify({ name: "serialize-javascript", version: "3.0.0", main: "./index.js" }, null, 2) + "\n"
  );
  write(
    path.join(storeSj, "index.js"),
    [`function serialize(val) { return JSON.stringify(val); }`, `serialize.serialize = serialize;`, `module.exports = serialize;`, ``].join("\n")
  );

  // app-local symlink to pnpm store
  const appNm = path.join(root, "packages", "app", "node_modules");
  rmdir(appNm);
  mkdir(appNm);
  const appSjLink = path.join(appNm, "serialize-javascript");
  if (!fs.existsSync(appSjLink)) {
    fs.symlinkSync(storeSj, appSjLink, "dir");
  }
}

// ── corpus/npm-hoisted-phantom ────────────────────────────────────────────────
function buildCorpusNpmHoistedPhantom() {
  const root = path.join(corpus, "npm-hoisted-phantom");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-npm-hoisted-phantom-root",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-npm-hoisted-phantom-root", version: "1.0.0", workspaces: ["packages/*"], dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
        // phantom-vuln-dep is in node_modules but NOT in the root or app package.json deps
        "packages/app": { name: "@corpus-npm-hoisted-phantom/app", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "packages/lib": { name: "@corpus-npm-hoisted-phantom/lib", version: "1.0.0" },
      },
    }, null, 2) + "\n"
  );

  // Hoisted: serialize-javascript at root node_modules
  installSerializeJavascript(root, "3.0.0");

  // phantom-vuln-dep: in node_modules but not in any package.json
  const nmPhantom = path.join(root, "node_modules", "phantom-vuln-dep");
  mkdir(nmPhantom);
  write(
    path.join(nmPhantom, "package.json"),
    JSON.stringify({ name: "phantom-vuln-dep", version: "1.0.0", main: "./index.js" }, null, 2) + "\n"
  );
  write(path.join(nmPhantom, "index.js"), `module.exports = { process: (x) => x };\n`);
}

// ── corpus/yarn-ws ────────────────────────────────────────────────────────────
function buildCorpusYarnWs() {
  const root = path.join(corpus, "yarn-ws");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "yarn.lock"),
    [
      "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
      "# yarn lockfile v1",
      "",
      "",
      "serialize-javascript@^3.0.0:",
      '  version "3.0.0"',
      '  resolved "https://registry.yarnpkg.com/serialize-javascript/-/serialize-javascript-3.0.0.tgz#corpus-yarn-ws"',
      "  integrity sha512-corpus-yarn-ws",
      "",
    ].join("\n")
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── corpus/two-version-ws ─────────────────────────────────────────────────────
function buildCorpusTwoVersionWs() {
  const root = path.join(corpus, "two-version-ws");
  rmdir(path.join(root, "node_modules"));

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
      "      serialize-javascript:",
      "        specifier: ^3.0.0",
      "        version: 3.0.0",
      "    specifiers:",
      "      serialize-javascript: ^3.0.0",
      "",
      "  packages/lib:",
      "    dependencies:",
      "      serialize-javascript:",
      "        specifier: ^6.0.0",
      "        version: 6.0.0",
      "    specifiers:",
      "      serialize-javascript: ^6.0.0",
      "",
      "packages:",
      "",
      "  /serialize-javascript@3.0.0:",
      "    resolution: {integrity: sha512-corpus-two-version-v3}",
      "    dev: false",
      "",
      "  /serialize-javascript@6.0.0:",
      "    resolution: {integrity: sha512-corpus-two-version-v6}",
      "    dev: false",
      "",
    ].join("\n")
  );

  // pnpm store: two versions
  for (const version of ["3.0.0", "6.0.0"].sort()) {
    const storeDir = path.join(root, "node_modules", ".pnpm", `serialize-javascript@${version}`, "node_modules", "serialize-javascript");
    mkdir(storeDir);
    write(
      path.join(storeDir, "package.json"),
      JSON.stringify({ name: "serialize-javascript", version, main: "./index.js" }, null, 2) + "\n"
    );
    write(
      path.join(storeDir, "index.js"),
      [`function serialize(val) { return JSON.stringify(val); }`, `serialize.serialize = serialize;`, `module.exports = serialize;`, ``].join("\n")
    );
  }

  // app-local symlink → v3
  const appNm = path.join(root, "packages", "app", "node_modules");
  rmdir(appNm);
  mkdir(appNm);
  const appSjLink = path.join(appNm, "serialize-javascript");
  const storeSjV3 = path.join(root, "node_modules", ".pnpm", "serialize-javascript@3.0.0", "node_modules", "serialize-javascript");
  if (!fs.existsSync(appSjLink)) {
    fs.symlinkSync(storeSjV3, appSjLink, "dir");
  }

  // lib-local symlink → v6
  const libNm = path.join(root, "packages", "lib", "node_modules");
  rmdir(libNm);
  mkdir(libNm);
  const libSjLink = path.join(libNm, "serialize-javascript");
  const storeSjV6 = path.join(root, "node_modules", ".pnpm", "serialize-javascript@6.0.0", "node_modules", "serialize-javascript");
  if (!fs.existsSync(libSjLink)) {
    fs.symlinkSync(storeSjV6, libSjLink, "dir");
  }
}

// ── corpus/dyn-computed-dispatch ──────────────────────────────────────────────
// Entrypoint dispatches via handlers[name]() — computed member call.
// No static import of serialize-javascript appears in reachable first-party code,
// so the engine emits a dynamic-dispatch UNKNOWN frontier. Expected: UNKNOWN.
function buildCorpusDynComputedDispatch() {
  const root = path.join(corpus, "dyn-computed-dispatch");
  rmdir(path.join(root, "node_modules"));

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "corpus-dyn-computed-dispatch",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "corpus-dyn-computed-dispatch", version: "1.0.0", dependencies: { "serialize-javascript": "^3.0.0" } },
        "node_modules/serialize-javascript": sjLockEntry("3.0.0"),
      },
    }, null, 2) + "\n"
  );

  installSerializeJavascript(root, "3.0.0");
}

// ── npm-ws-nested ─────────────────────────────────────────────────────────────
// npm workspace where a deeply-nested workspace (packages/app/core) declares a
// dep that is HOISTED to the repo root node_modules. The workspace-local key
// does not exist in the lockfile — only the root "node_modules/lodash" entry
// does. Verifies that the resolver walks up to find the hoisted entry.

function buildNpmWsNested() {
  const root = path.join(projects, "npm-ws-nested");

  // Static package.json files (already committed, not rebuilt here) must exist
  // as committed files. We only write lockfile + node_modules (gitignored).
  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "npm-ws-nested-root",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "npm-ws-nested-root",
            version: "1.0.0",
            workspaces: ["packages/app/*"],
          },
          // lodash is ONLY at the root-hoisted path, not at the workspace-local path
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-nested-root-lodash",
          },
          "packages/app/core": {
            name: "@nested/core",
            version: "1.0.0",
            dependencies: { lodash: "^4.17.21" },
          },
          "packages/app/utils": {
            name: "@nested/utils",
            version: "1.0.0",
            dependencies: { "@nested/core": "*" },
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  // Root-hoisted node_modules/lodash
  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
}

// ── npm-ws-glob-empty-dir ─────────────────────────────────────────────────────
// npm workspace whose glob pattern (packages/*) matches a directory with NO
// package.json (e.g. a shared config folder). That directory should be silently
// skipped: no workspace added, no incomplete entry emitted, no fail-close.

function buildNpmWsGlobEmptyDir() {
  const root = path.join(projects, "npm-ws-glob-empty-dir");

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "npm-ws-glob-empty-dir-root",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "npm-ws-glob-empty-dir-root",
            version: "1.0.0",
            workspaces: ["packages/*"],
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-glob-empty-lodash",
          },
          "packages/app": {
            name: "@glob-empty/app",
            version: "1.0.0",
            dependencies: { lodash: "^4.17.21" },
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  // packages/app has package.json
  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");

  // packages/config has NO package.json (just a plain dir)
  mkdir(path.join(root, "packages", "config"));
  // Ensure no stale package.json from previous runs
  const configPkg = path.join(root, "packages", "config", "package.json");
  if (fs.existsSync(configPkg)) fs.unlinkSync(configPkg);
}

// ── npm-ws-unresolved-dep ─────────────────────────────────────────────────────
// npm workspace where a required external dep is absent from the lockfile.
// Verifies that a dep-unresolved incomplete entry is emitted (fail-closed honesty).

function buildNpmWsUnresolvedDep() {
  const root = path.join(projects, "npm-ws-unresolved-dep");

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "npm-ws-unresolved-dep-root",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "npm-ws-unresolved-dep-root",
            version: "1.0.0",
            workspaces: ["packages/*"],
          },
          // lodash IS in the lockfile
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-unresolved-lodash",
          },
          "packages/app": {
            name: "@unresolved/app",
            version: "1.0.0",
            dependencies: {
              lodash: "^4.17.21",
              "not-in-lockfile": "^1.0.0",
            },
          },
        },
      },
      null,
      2
    ) + "\n"
  );

  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
}

// ── yarn-ws-nested ────────────────────────────────────────────────────────────
// yarn v1 workspace with a nested workspace (packages/app/core). The dep is
// declared in the workspace and the yarn.lock has a flat entry (hoisted to root
// node_modules). Verifies yarn flat-resolution works for nested workspaces.

function buildYarnWsNested() {
  const root = path.join(projects, "yarn-ws-nested");

  write(
    path.join(root, "yarn.lock"),
    [
      "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
      "# yarn lockfile v1",
      "",
      "",
      "lodash@^4.17.21:",
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#yarn-nested"',
      "  integrity sha512-yarn-nested",
      "",
    ].join("\n")
  );

  // Root node_modules (yarn hoists everything here)
  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
}

// ── pnpm-optional-platform ───────────────────────────────────────────────────
// pnpm project with optional deps that carry os/cpu constraints.
//
// Packages in lockfile (no store dirs except lodash):
//   lodash@4.17.21        – required, store present → resolves clean
//   platform-only-linux@1.0.0 – optional, os:[linux] → excluded on darwin, store ABSENT → no dep-unresolved
//   platform-only-x64@1.0.0   – optional, cpu:[x64]  → excluded on arm64, store ABSENT → no dep-unresolved
//   platform-absent-match@1.0.0 – optional, os:[darwin] cpu:[arm64] → MATCHES host, store ABSENT → dep-unresolved
//   required-absent@1.0.0  – required (not optional), store ABSENT → dep-unresolved

function buildPnpmOptionalPlatform() {
  const root = path.join(projects, "pnpm-optional-platform");

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
      "      required-absent:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "    optionalDependencies:",
      "      platform-only-linux:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "      platform-only-x64:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "      platform-absent-match:",
      "        specifier: ^1.0.0",
      "        version: 1.0.0",
      "",
      "packages:",
      "",
      "  /lodash@4.17.21:",
      "    resolution: {integrity: sha512-abc}",
      "    dev: false",
      "",
      "  /platform-only-linux@1.0.0:",
      "    resolution: {integrity: sha512-linux}",
      "    os:",
      "      - linux",
      "    optional: true",
      "    dev: false",
      "",
      "  /platform-only-x64@1.0.0:",
      "    resolution: {integrity: sha512-x64}",
      "    cpu:",
      "      - x64",
      "    optional: true",
      "    dev: false",
      "",
      "  /platform-absent-match@1.0.0:",
      "    resolution: {integrity: sha512-match}",
      "    os:",
      "      - darwin",
      "    cpu:",
      "      - arm64",
      "    optional: true",
      "    dev: false",
      "",
      "  /required-absent@1.0.0:",
      "    resolution: {integrity: sha512-req}",
      "    dev: false",
      "",
    ].join("\n")
  );

  rmdir(path.join(root, "node_modules"));

  // Only lodge lodash store dir — everything else is intentionally absent
  const storeLodash = path.join(
    root,
    "node_modules",
    ".pnpm",
    "lodash@4.17.21",
    "node_modules",
    "lodash"
  );
  mkdir(storeLodash);
  writePkg(storeLodash, "lodash", "4.17.21");
}

// ── npm-optional-platform ─────────────────────────────────────────────────────
// npm project with optional deps that carry os/cpu constraints in the lockfile.
//
// Packages in lockfile packages map:
//   lodash@4.17.21             – required, installed → resolves clean
//   platform-only-linux@1.0.0  – optional, os:[linux], NOT installed → no dep-unresolved on non-linux hosts
//   platform-absent-match-npm@1.0.0 – optional, os:[darwin] cpu:[arm64], NOT in lockfile packages
//                                       → absent from graph entirely; os/cpu constraints stored separately
//                                       This dep is in package.json optionalDeps but NOT in lockfile
//                                       packages map, so resolveNpmDep returns undefined.
//                                       → dep-unresolved on darwin/arm64 (matches host, but absent)
//                                       → no dep-unresolved on linux/x64 (excluded on that host)
// required-absent is in dependencies but absent from the lockfile packages map → dep-unresolved
//
// The optionalPlatformConstraints map is populated by parseNpmLockfile for
// platform-only-linux (which IS in the lockfile) so buildProjectModel can decide
// whether to suppress dep-unresolved for it.
// For platform-absent-match-npm (NOT in lockfile packages), constraints come from
// a separate "optionalConstraintsHints" section added to the lockfile root "" entry's
// optionalDependencies — but since npm doesn't record constraints there, we use
// a separate mechanism: the lockfile's packages map entry with optional+os+cpu IS the
// authoritative source. When absent from packages map entirely, constraints are unknown.
//
// Implementation note: for the test to exercise platform-absent-match-npm, it must be
// present in package.json optionalDependencies AND in the lockfile root "" entry's
// optionalDependencies, but NOT in the packages map. The optionalPlatformConstraints
// are populated from packages entries, so this dep won't have entries there — but
// we add a special "node_modules/platform-absent-match-npm" entry to the packages map
// with optional+os+cpu so the resolver can find the constraints. The package IS in the
// graph (from the lockfile packages entry), so resolveNpmDep returns it → it resolves.
//
// REVISED SCENARIO: platform-absent-match-npm is in the lockfile packages map but NOT
// installed (no physical dir). The npm graph contains it (resolves from lockfile).
// This means the model sees it as resolved, so no dep-unresolved fires for it regardless.
//
// TRUE HIGH-3 SCENARIO: "missing-from-npm-lockfile" is in package.json optionalDeps
// but completely ABSENT from the lockfile packages map. With no constraint info available,
// this is "unknown" state. Under unknown ≠ safe rule, dep-unresolved must fire.
// We can't use platform constraints to suppress it since there are none recorded.
// HOWEVER: the current code unconditionally suppresses ALL optional npm dep misses.
// The fix: emit dep-unresolved for optional deps absent from lockfile entirely (unknown platform).

function buildNpmOptionalPlatform() {
  const root = path.join(projects, "npm-optional-platform");

  write(
    path.join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: "npm-optional-platform",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "npm-optional-platform",
            version: "1.0.0",
            dependencies: { lodash: "^4.17.21", "required-absent": "^1.0.0" },
            optionalDependencies: {
              "platform-only-linux": "^1.0.0",
              "platform-absent-match-npm": "^1.0.0",
            },
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            integrity: "sha512-abc",
          },
          // platform-only-linux: os:[linux], in lockfile packages + installed on linux,
          // but node_modules dir absent on non-linux hosts. Has constraint info → suppress on linux.
          "node_modules/platform-only-linux": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/platform-only-linux/-/platform-only-linux-1.0.0.tgz",
            integrity: "sha512-linux",
            optional: true,
            os: ["linux"],
          },
          // platform-absent-match-npm: NOT in the lockfile packages map at all.
          // In package.json optionalDependencies but no lockfile entry → resolveNpmDep
          // returns undefined and optionalPlatformConstraints has no entry for it.
          // With no constraint info, unknown ≠ safe: dep-unresolved must fire on any host.
          //
          // required-absent is NOT in the lockfile packages map at all → dep-unresolved
        },
      },
      null,
      2
    ) + "\n"
  );

  rmdir(path.join(root, "node_modules"));
  const nmLodash = path.join(root, "node_modules", "lodash");
  mkdir(nmLodash);
  writePkg(nmLodash, "lodash", "4.17.21");
  // platform-only-linux and platform-absent-match-npm dirs intentionally not created
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
  buildGateG1();
  buildNoEntrypointWs();
  buildDefaultIndexWs();
  buildPnpmScopedStore();
  // Corpus fixtures
  buildCorpusCjsDirect();
  buildCorpusEsmDirect();
  buildCorpusMixedDual();
  buildCorpusTsDirect();
  buildCorpusTransitiveWs();
  buildCorpusNotImported();
  buildCorpusImportedUnrelatedExport();
  buildCorpusDynRequireVar();
  buildCorpusDynImportExpr();
  buildCorpusEvalReached();
  buildCorpusMissingLockfile();
  buildCorpusPnpmStrictWs();
  buildCorpusNpmHoistedPhantom();
  buildCorpusYarnWs();
  buildCorpusTwoVersionWs();
  buildCorpusDynComputedDispatch();
  buildNpmWsNested();
  buildNpmWsGlobEmptyDir();
  buildNpmWsUnresolvedDep();
  buildYarnWsNested();
  buildPnpmOptionalPlatform();
  buildNpmOptionalPlatform();
}
