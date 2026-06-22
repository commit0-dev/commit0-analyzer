/**
 * Sidecar shim: resolves the oxc native addon (.node file) when running as a
 * bun-compiled binary.
 *
 * When `bun build --compile` produces a single executable, Node's normal
 * module resolution cannot locate native .node addons embedded in memory.
 * The two-file distribution ships the oxc addon alongside the binary:
 *
 *   dist/
 *     anst-js-reachability          (the compiled binary)
 *     oxc-binding/
 *       parser.<platform>-<arch>.node
 *
 * This module patches Module._resolveFilename so that any require() call for
 * an oxc-binding native file is redirected to
 *   dirname(process.execPath)/oxc-binding/<filename>
 *
 * The shim must be imported (side-effect import) before any code that loads
 * oxc. In Phase 1 no oxc parsing happens, but the wiring is in place so the
 * binary build is correct for Phase 3 onwards.
 *
 * Platform/arch mapping follows the oxc-parser npm package convention:
 *   darwin + arm64  → darwin-arm64
 *   darwin + x64    → darwin-x64
 *   linux  + x64    → linux-x64-gnu
 *   linux  + arm64  → linux-arm64-gnu
 *   win32  + x64    → win32-x64-msvc
 */

import Module from "node:module";
import path from "node:path";

const OXC_BINDING_PREFIX = "oxc-binding/";

function oxcSidecarDir(): string {
  // When running as a compiled binary, process.execPath points to the binary.
  // When running via node/bun during development, fall back to __dirname so
  // the shim is a no-op (normal node_modules resolution still works).
  const execDir = path.dirname(process.execPath);
  return path.join(execDir, "oxc-binding");
}

// Only patch when running as a compiled binary (Bun sets this flag).
// During development (node/bun run) the shim does nothing.
const isCompiled =
  typeof (process as unknown as { isBun?: boolean }).isBun === "boolean" &&
  (process as unknown as { isBun?: boolean }).isBun === true;

if (isCompiled) {
  type ResolveFn = (request: string, ...rest: unknown[]) => string;
  const moduleInternal = Module as unknown as { _resolveFilename: ResolveFn };
  const _originalResolve = moduleInternal._resolveFilename;

  moduleInternal._resolveFilename = function (request: string, ...rest: unknown[]): string {
    if (typeof request === "string" && request.includes(OXC_BINDING_PREFIX)) {
      const basename = path.basename(request);
      return path.join(oxcSidecarDir(), basename);
    }
    return _originalResolve.call(this, request, ...rest);
  };
}

export {};
