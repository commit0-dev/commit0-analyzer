/**
 * Crash-safe isolated parser.
 *
 * Runs the oxc parser in a separate child process so a native crash (signal
 * kill from OS memory pressure — uncatchable by JS try/catch) is contained to
 * that process. The main process sees an exit event and resolves the in-flight
 * file as { kind: "unknown", reason: "parser worker crashed" }, then respawns
 * the worker for subsequent files.
 *
 * Soundness guarantee: a crashed, timed-out, or guard-skipped parse always
 * produces kind:"unknown", never kind:"parsed" with empty imports. The caller
 * (build.ts) treats kind:"unknown" the same as a parse error — an unanalyzable
 * boundary that emits an UNKNOWN frontier. unknown ≠ safe is preserved end-to-end.
 *
 * Protocol: newline-delimited JSON over stdio.
 *   stdin  → { id: number, file: string }
 *   stdout ← { id: number, result: ParsedModule }
 *
 * The worker processes one request at a time (sequential) so a crash affects
 * exactly the one in-flight file (since build.ts awaits each parse serially).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import type { ParsedModule } from "./types.js";

/** Per-parse hard timeout (ms). A hang causes kill+respawn+unknown result. */
const PARSE_TIMEOUT_MS = 20_000;

interface PendingRequest {
  resolve: (result: ParsedModule) => void;
  file: string;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Command to spawn the worker. Injectable for tests (tsx loader) vs production
 * (bun binary with --parse-worker self-dispatch).
 */
export interface SpawnCommand {
  /** Executable path. */
  cmd: string;
  /** Arguments to pass. */
  args: string[];
}

/**
 * Detect whether we are running inside a bun-compiled binary.
 * Bun sets process.isBun; we also check process.execPath to distinguish
 * the bun-compiled single binary from `bun run` in dev.
 */
function isCompiledBinary(): boolean {
  const p = process as unknown as { isBun?: boolean };
  return p.isBun === true && !process.execPath.endsWith("bun");
}

/**
 * Build the default spawn command for the worker.
 *
 * Production (bun-compiled binary): the binary self-dispatches via --parse-worker.
 * Dev/test: spawn the worker TypeScript source via `npx tsx` (tsx is available
 * globally via npx even if not installed locally). The worker path is resolved
 * relative to this source file.
 */
function defaultSpawnCommand(): SpawnCommand {
  if (isCompiledBinary()) {
    // The compiled binary re-dispatches when it sees --parse-worker
    return { cmd: process.execPath, args: ["--parse-worker"] };
  }

  // Dev/test: resolve the worker TypeScript source relative to this file.
  // import.meta.url → file:///.../.../src/parse/isolated-parser.ts
  // worker is at the same directory: src/parse/parse-worker.ts
  const workerPath = new URL("./parse-worker.ts", import.meta.url).pathname;

  // Use `npx tsx` to run the TypeScript worker. npx is always available in
  // the same environment that runs vitest (node + npm). The --yes flag is
  // not needed because tsx is already cached from the vitest run.
  return {
    cmd: "npx",
    args: ["tsx", workerPath],
  };
}

export class IsolatedParser {
  private child: ChildProcess | null = null;
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private readonly spawnCmd: SpawnCommand;
  private stopped = false;

  constructor(spawnCmd?: SpawnCommand) {
    this.spawnCmd = spawnCmd ?? defaultSpawnCommand();
  }

  /** Start the worker subprocess. Idempotent if already running. */
  start(): void {
    if (this.child !== null || this.stopped) return;
    this.spawnWorker();
  }

  /**
   * Parse a single file via the isolated worker.
   *
   * Returns kind:"unknown" if:
   *   - the worker crashes (process exit while request is in flight)
   *   - the worker times out (no response within PARSE_TIMEOUT_MS)
   *   - the worker reports kind:"unknown" (parse error, guard skip, etc.)
   *
   * Never throws.
   */
  async parse(file: string): Promise<ParsedModule> {
    if (this.stopped) {
      return { kind: "unknown", file, reason: "isolated parser has been stopped" };
    }

    // Ensure worker is running
    if (this.child === null) {
      this.spawnWorker();
    }

    const id = this.nextId++;

    return new Promise<ParsedModule>((resolve) => {
      const timer = setTimeout(() => {
        // Timeout: kill+respawn, resolve as unknown
        if (this.pending.has(id)) {
          this.pending.delete(id);
          process.stderr.write(
            `[isolated-parser] timeout parsing ${file} — killing worker\n`
          );
          this.killAndRespawn(
            `parser worker timed out after ${PARSE_TIMEOUT_MS}ms`
          );
          resolve({ kind: "unknown", file, reason: "parser worker timed out" });
        }
      }, PARSE_TIMEOUT_MS);

      this.pending.set(id, { resolve, file, timer });

      // Write request to worker stdin
      const req = JSON.stringify({ id, file }) + "\n";
      try {
        this.child!.stdin!.write(req);
      } catch (err) {
        // stdin write failed (worker already dead): the exit handler will resolve
        // this pending request. Clear our timer here so the exit handler wins cleanly.
        clearTimeout(timer);
        this.pending.delete(id);
        resolve({
          kind: "unknown",
          file,
          reason: `worker stdin write failed: ${String(err)}`,
        });
      }
    });
  }

  /** Stop the worker. Idempotent. */
  stop(): void {
    this.stopped = true;
    this.drainPending("isolated parser stopped");
    if (this.child !== null) {
      try {
        this.child.kill();
      } catch {
        // ignore
      }
      this.child = null;
    }
  }

  // ── Private ──────────────────────────────────────────────────────────────────

  private spawnWorker(): void {
    const { cmd, args } = this.spawnCmd;
    // Spawn with a clean NODE_OPTIONS so the parent process's --import loaders
    // (e.g. vitest's tsx loader) do not bleed into the child. The child uses
    // its own runner (npx tsx or the bun binary) to load TypeScript.
    const childEnv = { ...process.env };
    delete childEnv["NODE_OPTIONS"];

    const child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: childEnv,
      // Detached=false: child dies with parent, which is what we want.
    });

    // Forward worker stderr so errors are visible in the parent process
    child.stderr?.on("data", (data: Buffer) => {
      process.stderr.write(`[parse-worker-stderr] ${data.toString()}`);
    });

    child.on("error", (err) => {
      process.stderr.write(`[isolated-parser] worker error: ${err}\n`);
      this.onWorkerDied(`worker process error: ${err.message}`);
    });

    child.on("exit", (code, signal) => {
      if (this.child === child) {
        process.stderr.write(
          `[isolated-parser] worker exited (code=${code} signal=${signal})\n`
        );
        this.onWorkerDied(
          `parser worker crashed (exit code=${code} signal=${signal})`
        );
      }
    });

    // Read newline-delimited JSON responses from worker stdout
    const rl = createInterface({ input: child.stdout!, crlfDelay: Infinity });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let msg: { id: number; result: ParsedModule };
      try {
        msg = JSON.parse(trimmed) as { id: number; result: ParsedModule };
      } catch (err) {
        process.stderr.write(
          `[isolated-parser] invalid JSON from worker: ${err}\n`
        );
        return;
      }
      const pending = this.pending.get(msg.id);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(msg.id);
        pending.resolve(msg.result);
      }
    });

    this.child = child;
  }

  private onWorkerDied(reason: string): void {
    this.child = null;
    this.drainPending(reason);
    // Respawn for subsequent requests (unless stopped)
    if (!this.stopped && this.pending.size === 0) {
      // No pending requests right now; worker will be respawned lazily on next parse()
    }
    // If there are already new pending requests queued (shouldn't happen in
    // sequential use, but guard anyway), respawn immediately.
    if (!this.stopped && this.pending.size > 0) {
      this.spawnWorker();
    }
  }

  private killAndRespawn(reason: string): void {
    if (this.child !== null) {
      const child = this.child;
      this.child = null;
      try {
        child.kill();
      } catch {
        // ignore
      }
      // The exit event will fire but child !== this.child so onWorkerDied won't run
    }
    this.drainPending(reason);
    if (!this.stopped) {
      this.spawnWorker();
    }
  }

  private drainPending(reason: string): void {
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        kind: "unknown",
        file: pending.file,
        reason,
      });
      this.pending.delete(id);
    }
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _singleton: IsolatedParser | null = null;

/** Get (or lazily create) the module-level IsolatedParser singleton. */
export function getIsolatedParser(): IsolatedParser {
  if (_singleton === null) {
    _singleton = new IsolatedParser();
  }
  return _singleton;
}

/** Replace the singleton (for testing). Returns the previous instance. */
export function setIsolatedParser(parser: IsolatedParser | null): IsolatedParser | null {
  const prev = _singleton;
  _singleton = parser;
  return prev;
}
