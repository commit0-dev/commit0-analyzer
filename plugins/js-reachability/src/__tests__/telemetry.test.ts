/**
 * Tests for src/telemetry.ts — env-gated performance telemetry.
 *
 * Verifies: disabled → every primitive is a no-op and flush writes nothing;
 * enabled → spans/counts/observations accumulate and flush emits a sorted
 * summary to STDERR (never stdout); reset() clears state and re-reads the gate.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TELEMETRY = "../telemetry.js";

/** Capture everything written to process.stderr while fn runs. */
async function captureStderr(fn: () => void | Promise<void>): Promise<string> {
  let buf = "";
  const spy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: unknown): boolean => {
      buf += String(chunk);
      return true;
    });
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
  return buf;
}

describe("telemetry – disabled (no env var)", () => {
  let telemetry: typeof import("../telemetry.js");

  beforeEach(async () => {
    delete process.env.COMMIT0_DEBUG;
    delete process.env.COMMIT0_TELEMETRY;
    telemetry = await import(TELEMETRY);
    telemetry.reset();
  });

  it("reports not enabled", () => {
    expect(telemetry.isEnabled()).toBe(false);
  });

  it("span/count/observe are no-ops and never throw", () => {
    expect(() => telemetry.span("foo")()).not.toThrow();
    expect(() => telemetry.count("bar", 3)).not.toThrow();
    expect(() => telemetry.observe("baz", 42)).not.toThrow();
  });

  it("flush writes nothing to stderr", async () => {
    telemetry.count("bar");
    const out = await captureStderr(() => telemetry.flush("label"));
    expect(out).toBe("");
  });
});

describe("telemetry – enabled via COMMIT0_DEBUG=1", () => {
  let telemetry: typeof import("../telemetry.js");

  beforeEach(async () => {
    process.env.COMMIT0_DEBUG = "1";
    delete process.env.COMMIT0_TELEMETRY;
    telemetry = await import(TELEMETRY);
    telemetry.reset();
  });

  afterEach(() => {
    delete process.env.COMMIT0_DEBUG;
    telemetry.reset();
  });

  it("reports enabled", () => {
    expect(telemetry.isEnabled()).toBe(true);
  });

  it("accumulates counts and emits them in the flush summary", async () => {
    telemetry.count("widgets", 2);
    telemetry.count("widgets", 3);
    const out = await captureStderr(() => telemetry.flush("plugin"));
    expect(out).toContain("[plugin] ── performance summary ──");
    expect(out).toContain("[plugin] count widgets: 5");
  });

  it("accumulates span totals and call counts", async () => {
    telemetry.span("work")();
    telemetry.span("work")();
    const out = await captureStderr(() => telemetry.flush("plugin"));
    expect(out).toMatch(/\[plugin\] span work: total=[\d.]+ms calls=2/);
  });

  it("records distribution sum/max/n via observe", async () => {
    telemetry.observe("size", 10);
    telemetry.observe("size", 30);
    const out = await captureStderr(() => telemetry.flush("plugin"));
    expect(out).toContain("[plugin] dist size: n=2 sum=40 max=30 avg=20.00");
  });

  it("reset() clears accumulated state", async () => {
    telemetry.count("widgets", 9);
    telemetry.reset();
    const out = await captureStderr(() => telemetry.flush("plugin"));
    // After reset the gate is still enabled (env unchanged) but counters are empty.
    expect(out).toContain("performance summary");
    expect(out).not.toContain("widgets");
  });
});
