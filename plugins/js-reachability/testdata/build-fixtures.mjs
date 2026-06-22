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

// ── entry point ──────────────────────────────────────────────────────────────

export default function setup() {
  buildSinglePkg();
  buildNpmWs();
  buildYarnWs();
  buildPnpmWs();
  buildPnpmMultiVersion();
  buildCorruptLock();
  buildCorruptPnpm();
  buildCorruptYarn();
  buildMissingDepPnpm();
  buildBerryYarn();
  buildPnpmPeerSuffix();
}
