/**
 * Tests: pnpm lockfile v9 (lockfileVersion '9.0', emitted by pnpm@11) records the
 * `optional: true` flag in the `snapshots` block, not the `packages` block. A
 * platform-excluded native package (explicit os/cpu constraints that exclude the
 * host) must not be reported as dep-unresolved just because its store path is
 * absent — it is definitionally not present in the host-platform runtime.
 *
 * Host platform/arch values are explicit so results are deterministic on any host.
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { parsePnpmLockfile } from "../../lockfile/pnpm.js";

const fixtures = path.resolve(import.meta.dirname, "../../../testdata/projects");

const DARWIN_ARM64 = { platform: "darwin", arch: "arm64" };

describe("parsePnpmLockfile – lockfile v9 optional flag in snapshots block", () => {
  it("platform-excluded native package (os/cpu exclude host, optional in snapshots) is NOT incomplete", async () => {
    // @esbuild/linux-x64 declares cpu:[x64] os:[linux] in `packages` and
    // optional:true in `snapshots`. On darwin/arm64 it is platform-excluded and
    // has no store dir → its absence is expected, not a coverage gap.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform-v9"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) =>
        e.kind === "dep-unresolved" && e.scope.includes("@esbuild/linux-x64")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("optional WASM helper with NO os/cpu constraints (optional:true under peer-less snapshot key) is NOT incomplete", async () => {
    // @emnapi/core@1.10.0 has no os/cpu in `packages` and optional:true under
    // the peer-less key in `snapshots`. pnpm did not install it on this host
    // (no store path); it is an optional runtime helper → absence is expected.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform-v9"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("@emnapi/core")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("optional WASM helper whose snapshot key is peer-suffixed is NOT incomplete", async () => {
    // @napi-rs/wasm-runtime@1.1.5 has no os/cpu in `packages`; its snapshot
    // key is `@napi-rs/wasm-runtime@1.1.5(@emnapi/core@1.10.0)(@emnapi/runtime@1.10.0)`
    // with optional:true. A direct snapshots[rawKey] lookup misses it; the
    // lookup must strip the peer suffix to find the optional flag.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform-v9"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) =>
        e.kind === "dep-unresolved" && e.scope.includes("@napi-rs/wasm-runtime")
    );
    expect(unresolved).toHaveLength(0);
  });

  it("required package with no os/cpu constraints and a missing store path IS still incomplete", async () => {
    // missing-required has no platform constraints and is not optional; a
    // missing store path is a real coverage gap regardless of host.
    const { incomplete } = await parsePnpmLockfile(
      path.join(fixtures, "pnpm-optional-platform-v9"),
      DARWIN_ARM64
    );
    const unresolved = incomplete.filter(
      (e) => e.kind === "dep-unresolved" && e.scope.includes("missing-required")
    );
    expect(unresolved).toHaveLength(1);
  });
});
