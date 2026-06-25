/**
 * Bounded pool of isolated parser workers.
 *
 * Manages N crash-safe IsolatedParser instances (one child process each).
 * Distributes parse requests across idle workers; queues requests when all
 * workers are busy. Each worker processes at most one request at a time so
 * a crash/timeout affects exactly the one in-flight file on that worker:
 *   - The request resolves as kind:"unknown" (soundness: unknown ≠ safe).
 *   - That worker respawns internally (IsolatedParser handles this).
 *   - All other workers continue unaffected.
 *
 * Workers are started lazily on first demand: a slot's child process is only
 * spawned when a parse request is dispatched to it. A scan of 5 files with
 * N=8 spawns at most 5 workers, not 8. This keeps the total child-process
 * count proportional to actual concurrency demand, which matters when many
 * test files run in parallel inside the same vitest session.
 *
 * Pool size is tunable via the `concurrency` constructor option (default:
 * DEFAULT_POOL_CONCURRENCY). Tests inject a smaller value.
 *
 * Protocol: start() (optional, warms the first slot) → parse() … → stop().
 * stop() is idempotent and terminates all started workers.
 */

import os from "node:os";
import { IsolatedParser, type SpawnCommand } from "./isolated-parser.js";
import type { ParsedModule } from "./types.js";

/**
 * Number of workers used when no explicit concurrency is given.
 * Tunable here without changing call sites.
 */
export const DEFAULT_POOL_CONCURRENCY = Math.min(8, Math.max(2, os.cpus().length));

interface WorkerSlot {
  parser: IsolatedParser;
  busy: boolean;
  started: boolean;
}

interface QueuedRequest {
  file: string;
  resolve: (result: ParsedModule) => void;
}

export class ParserPool {
  private readonly slots: WorkerSlot[];
  private readonly queue: QueuedRequest[] = [];
  private stopped = false;

  constructor(options?: {
    /** Number of workers. Defaults to DEFAULT_POOL_CONCURRENCY. */
    concurrency?: number;
    /** Injectable spawn command for tests. */
    spawnCmd?: SpawnCommand;
  }) {
    const concurrency = options?.concurrency ?? DEFAULT_POOL_CONCURRENCY;
    if (concurrency < 1) throw new RangeError("concurrency must be >= 1");

    this.slots = Array.from({ length: concurrency }, () => ({
      parser: new IsolatedParser(options?.spawnCmd),
      busy: false,
      started: false,
    }));
  }

  /**
   * Warm the first worker so it is ready for the initial parse.
   * Optional: parse() starts workers lazily even without calling start() first.
   * Idempotent.
   */
  start(): void {
    if (this.stopped) return;
    // Warm only the first slot; the rest start on demand.
    const first = this.slots[0];
    if (first && !first.started) {
      first.parser.start();
      first.started = true;
    }
  }

  /**
   * Parse a file, routing to the next idle worker.
   *
   * If all workers are busy, the request is queued and dispatched when a
   * worker becomes free. Returns kind:"unknown" if the pool has been stopped
   * or if the assigned worker crashes/times out — never throws.
   */
  parse(file: string): Promise<ParsedModule> {
    if (this.stopped) {
      return Promise.resolve({
        kind: "unknown",
        file,
        reason: "parser pool has been stopped",
      });
    }

    return new Promise<ParsedModule>((resolve) => {
      // Find an idle worker slot (prefer already-started slots to minimize spawns)
      const slot =
        this.slots.find((s) => !s.busy && s.started) ??
        this.slots.find((s) => !s.busy);
      if (slot !== undefined) {
        this.dispatch(slot, file, resolve);
      } else {
        // All workers busy — enqueue
        this.queue.push({ file, resolve });
      }
    });
  }

  /** Stop all started workers. Idempotent. Resolves any queued requests as unknown. */
  stop(): void {
    if (this.stopped) return;
    this.stopped = true;

    // Drain queued requests (not yet dispatched)
    for (const req of this.queue.splice(0)) {
      req.resolve({ kind: "unknown", file: req.file, reason: "parser pool has been stopped" });
    }

    // Stop all started workers (IsolatedParser.stop() handles in-flight + idempotency)
    for (const slot of this.slots) {
      if (slot.started) {
        slot.parser.stop();
      }
    }
  }

  // ── Private ───────────────────────────────────────────────────────────────────

  private dispatch(slot: WorkerSlot, file: string, resolve: (r: ParsedModule) => void): void {
    // Start the worker lazily on first dispatch
    if (!slot.started) {
      slot.parser.start();
      slot.started = true;
    }
    slot.busy = true;
    slot.parser.parse(file).then((result) => {
      slot.busy = false;
      resolve(result);
      // Dequeue next waiting request for this slot
      this.drainQueue(slot);
    });
    // IsolatedParser.parse() never rejects, so no .catch needed.
  }

  private drainQueue(slot: WorkerSlot): void {
    if (this.stopped) return;
    const next = this.queue.shift();
    if (next !== undefined) {
      this.dispatch(slot, next.file, next.resolve);
    }
  }
}
