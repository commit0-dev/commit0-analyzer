/**
 * Tests: pnpm lockfile v9 (lockfileVersion '9.0', emitted by pnpm@11) records the
 * `optional: true` flag in the `snapshots` block, not the `packages` block. A
 * platform-excluded native package (explicit os/cpu constraints that exclude the
 * host), and an optional package with no os/cpu whose store path is absent, must
 * NOT be reported as dep-unresolved — they are not present in the host-platform
 * runtime. A REQUIRED package with a missing store path IS a real coverage gap.
 *
 * The lockfile is written to a fresh temp dir with no `node_modules`, so every
 * store path is deterministically absent on any host/runner — independent of the
 * vitest globalSetup fixture generation under testdata/projects.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parsePnpmLockfile } from "../../lockfile/pnpm.js";

const DARWIN_ARM64 = { platform: "darwin", arch: "arm64" };

const PACKAGE_JSON = JSON.stringify({
  name: "pnpm-optional-platform-v9",
  version: "1.0.0",
  dependencies: { "missing-required": "^1.0.0" },
  optionalDependencies: { "@esbuild/linux-x64": "^0.28.0" },
});

// lockfileVersion 9: os/cpu live in `packages`, `optional` lives in `snapshots`.
const PNPM_LOCK = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      missing-required:
        specifier: ^1.0.0
        version: 1.0.0
    optionalDependencies:
      '@esbuild/linux-x64':
        specifier: ^0.28.0
        version: 0.28.0
      '@emnapi/core':
        specifier: ^1.10.0
        version: 1.10.0
      '@napi-rs/wasm-runtime':
        specifier: ^1.1.5
        version: 1.1.5(@emnapi/core@1.10.0)(@emnapi/runtime@1.10.0)

packages:

  '@esbuild/linux-x64@0.28.0':
    resolution: {integrity: sha512-linuxx64}
    engines: {node: '>=18'}
    cpu: [x64]
    os: [linux]

  '@emnapi/core@1.10.0':
    resolution: {integrity: sha512-emnapi-core}

  '@napi-rs/wasm-runtime@1.1.5':
    resolution: {integrity: sha512-napi-wasm}

  missing-required@1.0.0:
    resolution: {integrity: sha512-req}

snapshots:

  '@esbuild/linux-x64@0.28.0':
    optional: true

  '@emnapi/core@1.10.0':
    optional: true

  '@napi-rs/wasm-runtime@1.1.5(@emnapi/core@1.10.0)(@emnapi/runtime@1.10.0)':
    optional: true

  missing-required@1.0.0: {}
`;

describe("parsePnpmLockfile – lockfile v9 optional flag in snapshots block", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "commit0-analyzer-pnpm-v9-"));
    await writeFile(path.join(dir, "package.json"), PACKAGE_JSON);
    await writeFile(path.join(dir, "pnpm-lock.yaml"), PNPM_LOCK);
    // Deliberately NO node_modules → every store path is missing.
  });

  afterAll(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  async function unresolvedFor(needle: string) {
    const { incomplete } = await parsePnpmLockfile(dir, DARWIN_ARM64);
    return incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes(needle)
    );
  }

  it("platform-excluded native package (os/cpu exclude host, optional in snapshots) is NOT incomplete", async () => {
    // @esbuild/linux-x64 declares cpu:[x64] os:[linux]; on darwin/arm64 it is
    // platform-excluded and absent → expected, not a coverage gap.
    expect(await unresolvedFor("@esbuild/linux-x64")).toHaveLength(0);
  });

  it("optional WASM helper with NO os/cpu constraints (optional:true under peer-less snapshot key) is NOT incomplete", async () => {
    expect(await unresolvedFor("@emnapi/core")).toHaveLength(0);
  });

  it("optional WASM helper whose snapshot key is peer-suffixed is NOT incomplete", async () => {
    // Optional flag lives under `@napi-rs/wasm-runtime@1.1.5(@emnapi/core@...)`;
    // the lookup must strip the peer suffix to find it.
    expect(await unresolvedFor("@napi-rs/wasm-runtime")).toHaveLength(0);
  });

  it("required package with no os/cpu constraints and a missing store path IS still incomplete", async () => {
    // Not optional, no platform constraints → a missing store path is a real
    // coverage gap regardless of host.
    expect(await unresolvedFor("missing-required")).toHaveLength(1);
  });
});
