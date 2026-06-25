/**
 * Creates fixture node_modules content for pnpm-multi-version test.
 * Run once: node testdata/setup-fixtures.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const base = path.join(__dirname, "projects", "pnpm-multi-version");

const store = [
  { version: "4.16.6" },
  { version: "4.17.21" },
];

for (const { version } of store) {
  const dir = path.join(
    base,
    "node_modules",
    ".pnpm",
    `lodash@${version}`,
    "node_modules",
    "lodash"
  );
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "lodash", version }, null, 2) + "\n"
  );
}

// corrupt-pnpm fixture
const corruptPnpmDir = path.join(__dirname, "projects", "corrupt-pnpm");
fs.mkdirSync(corruptPnpmDir, { recursive: true });
fs.writeFileSync(path.join(corruptPnpmDir, "package.json"), JSON.stringify({ name: "corrupt-pnpm", version: "1.0.0", dependencies: { lodash: "^4.17.21" } }, null, 2) + "\n");
fs.writeFileSync(path.join(corruptPnpmDir, "pnpm-lock.yaml"), "this: is: not: valid: yaml: [{\n");

// corrupt-yarn fixture
const corruptYarnDir = path.join(__dirname, "projects", "corrupt-yarn");
fs.mkdirSync(corruptYarnDir, { recursive: true });
fs.writeFileSync(path.join(corruptYarnDir, "package.json"), JSON.stringify({ name: "corrupt-yarn", version: "1.0.0", dependencies: { lodash: "^4.17.21" } }, null, 2) + "\n");
fs.writeFileSync(path.join(corruptYarnDir, "yarn.lock"), "this is not a valid\nyarn lockfile format !!!\n@@@badly\n");

// missing-dep-pnpm fixture: package.json declares a dep NOT in the lockfile
const missingDepPnpmDir = path.join(__dirname, "projects", "missing-dep-pnpm");
fs.mkdirSync(missingDepPnpmDir, { recursive: true });
fs.writeFileSync(
  path.join(missingDepPnpmDir, "package.json"),
  JSON.stringify({ name: "missing-dep-pnpm", version: "1.0.0", dependencies: { lodash: "^4.17.21", "not-in-lockfile": "^1.0.0" } }, null, 2) + "\n"
);
// pnpm-lock.yaml only has lodash, not not-in-lockfile
const missingDepLock = `lockfileVersion: '6.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n      not-in-lockfile:\n        specifier: ^1.0.0\n        version: 1.0.0\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n    dev: false\n`;
fs.writeFileSync(path.join(missingDepPnpmDir, "pnpm-lock.yaml"), missingDepLock);
fs.writeFileSync(path.join(missingDepPnpmDir, "pnpm-workspace.yaml"), "packages:\n  - '.'\n");

// berry yarn fixture (H1)
const berryYarnDir = path.join(__dirname, "projects", "berry-yarn");
fs.mkdirSync(berryYarnDir, { recursive: true });
fs.writeFileSync(
  path.join(berryYarnDir, "package.json"),
  JSON.stringify({ name: "berry-yarn-root", version: "1.0.0", dependencies: { lodash: "^4.17.21" } }, null, 2) + "\n"
);
const berryLock = `__metadata:\n  version: 6\n  cacheKey: 8\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n  checksum: abc\n  languageName: node\n  linkType: hard\n`;
fs.writeFileSync(path.join(berryYarnDir, "yarn.lock"), berryLock);

// pnpm-peer-suffix fixture (C2)
const peerSuffixDir = path.join(__dirname, "projects", "pnpm-peer-suffix");
fs.mkdirSync(peerSuffixDir, { recursive: true });
fs.writeFileSync(
  path.join(peerSuffixDir, "package.json"),
  JSON.stringify({ name: "pnpm-peer-suffix-root", version: "1.0.0", dependencies: { lodash: "^4.17.21", "@scope/helper": "^1.0.0" } }, null, 2) + "\n"
);
// pnpm-lock.yaml with peer-suffixed keys (pnpm v6/v9 format)
const peerSuffixLock = `lockfileVersion: '6.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21(react@18.0.0)\n      '@scope/helper':\n        specifier: ^1.0.0\n        version: 1.0.0(peer@2.0.0)\n\npackages:\n\n  /lodash@4.17.21(react@18.0.0):\n    resolution: {integrity: sha512-abc}\n    dev: false\n\n  /@scope/helper@1.0.0(peer@2.0.0):\n    resolution: {integrity: sha512-def}\n    dev: false\n`;
fs.writeFileSync(path.join(peerSuffixDir, "pnpm-lock.yaml"), peerSuffixLock);

console.log("fixtures created");
