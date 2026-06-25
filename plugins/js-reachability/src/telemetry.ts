/**
 * Lightweight, env-gated performance telemetry for the reachability plugin.
 *
 * Enabled only when ANST_DEBUG or ANST_TELEMETRY is set to a truthy value;
 * otherwise every entry point is a cheap no-op (a single boolean check) so it
 * costs nothing on normal scans.
 *
 * All output goes to STDERR. STDOUT carries the gRPC / JSON protocol and must
 * never be polluted by telemetry.
 *
 * Three primitives:
 *   span(name)   → returns a stop() closure; on stop, the elapsed ms is added
 *                  to a named bucket (with a call count). Use for timing a
 *                  repeated operation (e.g. each parse).
 *   count(name)  → increments a named counter.
 *   observe(n,v) → records a distribution sample (sum / max / n) — e.g. the
 *                  size of each transitive-closure result.
 *
 * flush(label) writes one sorted, human-readable summary block to stderr.
 */

const TRUTHY = new Set(["1", "true", "yes", "on"]);

function readEnabled(): boolean {
  const a = process.env.ANST_DEBUG;
  const b = process.env.ANST_TELEMETRY;
  return (
    (a !== undefined && TRUTHY.has(a.toLowerCase())) ||
    (b !== undefined && TRUTHY.has(b.toLowerCase()))
  );
}

let enabled = readEnabled();

interface SpanAgg {
  totalMs: number;
  calls: number;
}
interface DistAgg {
  sum: number;
  max: number;
  n: number;
}

const spans = new Map<string, SpanAgg>();
const counters = new Map<string, number>();
const dists = new Map<string, DistAgg>();

const noop = (): void => {};

/**
 * Start a timing span. Returns a stop function; calling it records the elapsed
 * milliseconds against `name`. No-op (and returns a no-op stopper) when disabled.
 */
export function span(name: string): () => void {
  if (!enabled) return noop;
  const start = performance.now();
  return () => {
    const elapsed = performance.now() - start;
    const agg = spans.get(name);
    if (agg) {
      agg.totalMs += elapsed;
      agg.calls += 1;
    } else {
      spans.set(name, { totalMs: elapsed, calls: 1 });
    }
  };
}

/** Increment a named counter by n (default 1). No-op when disabled. */
export function count(name: string, n = 1): void {
  if (!enabled) return;
  counters.set(name, (counters.get(name) ?? 0) + n);
}

/** Record one sample of a distribution (sum / max / count). No-op when disabled. */
export function observe(name: string, value: number): void {
  if (!enabled) return;
  const agg = dists.get(name);
  if (agg) {
    agg.sum += value;
    agg.n += 1;
    if (value > agg.max) agg.max = value;
  } else {
    dists.set(name, { sum: value, max: value, n: 1 });
  }
}

/** True when telemetry is active (lets callers skip expensive debug-only work). */
export function isEnabled(): boolean {
  return enabled;
}

/**
 * Write a single sorted summary block to stderr. No-op when disabled.
 * Output is grouped (spans, counters, distributions) and sorted by name so
 * runs are diff-friendly. Durations are reported but not wall-clock stamps.
 */
export function flush(label = "telemetry"): void {
  if (!enabled) return;
  const lines: string[] = [`[${label}] ── performance summary ──`];

  const spanNames = [...spans.keys()].sort();
  for (const name of spanNames) {
    const s = spans.get(name)!;
    const avg = s.calls > 0 ? s.totalMs / s.calls : 0;
    lines.push(
      `[${label}] span ${name}: total=${s.totalMs.toFixed(1)}ms calls=${s.calls} avg=${avg.toFixed(3)}ms`
    );
  }
  const counterNames = [...counters.keys()].sort();
  for (const name of counterNames) {
    lines.push(`[${label}] count ${name}: ${counters.get(name)}`);
  }
  const distNames = [...dists.keys()].sort();
  for (const name of distNames) {
    const d = dists.get(name)!;
    const avg = d.n > 0 ? d.sum / d.n : 0;
    lines.push(
      `[${label}] dist ${name}: n=${d.n} sum=${d.sum} max=${d.max} avg=${avg.toFixed(2)}`
    );
  }
  process.stderr.write(lines.join("\n") + "\n");
}

/** Reset all accumulators and re-read the env gate. For tests. */
export function reset(): void {
  spans.clear();
  counters.clear();
  dists.clear();
  enabled = readEnabled();
}
