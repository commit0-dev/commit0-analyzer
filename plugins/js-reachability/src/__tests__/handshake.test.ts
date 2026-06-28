import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { buildHandshakeLine, checkMagicCookie, serveUntilDone } from "../handshake.js";

const MAGIC_COOKIE_KEY = "COMMIT0_PLUGIN_MAGIC_COOKIE";
const MAGIC_COOKIE_VALUE = "commit0-analyzer-v0-plugin";

describe("buildHandshakeLine", () => {
  it("produces the correct 5-field go-plugin handshake line for port 12345", () => {
    const line = buildHandshakeLine(12345);
    expect(line).toBe("1|1|tcp|127.0.0.1:12345|grpc\n");
  });

  it("uses CoreProtocol=1 (literal)", () => {
    const line = buildHandshakeLine(9000);
    expect(line.startsWith("1|")).toBe(true);
  });

  it("uses AppProto=1 (ProtocolMajor+1 where ProtocolMajor=0)", () => {
    const [, appProto] = buildHandshakeLine(9000).split("|");
    expect(appProto).toBe("1");
  });

  it("specifies tcp network", () => {
    const parts = buildHandshakeLine(9000).split("|");
    expect(parts[2]).toBe("tcp");
  });

  it("binds to 127.0.0.1 loopback", () => {
    const parts = buildHandshakeLine(9000).split("|");
    expect(parts[3]).toBe("127.0.0.1:9000");
  });

  it("uses the literal grpc protocol token", () => {
    const parts = buildHandshakeLine(9000).split("|");
    // Last field includes the trailing newline; strip it for comparison.
    expect(parts[4].trimEnd()).toBe("grpc");
  });

  it("terminates with a newline", () => {
    const line = buildHandshakeLine(1);
    expect(line[line.length - 1]).toBe("\n");
  });

  it("handles ephemeral port 0", () => {
    const line = buildHandshakeLine(0);
    expect(line).toBe("1|1|tcp|127.0.0.1:0|grpc\n");
  });
});

describe("checkMagicCookie", () => {
  let originalEnv: string | undefined;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let exitSpy: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stderrSpy: any;

  beforeEach(() => {
    originalEnv = process.env[MAGIC_COOKIE_KEY];
    exitSpy = vi.spyOn(process, "exit").mockImplementation((_code?: number | string | null) => {
      throw new Error(`process.exit(${_code})`);
    });
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env[MAGIC_COOKIE_KEY];
    } else {
      process.env[MAGIC_COOKIE_KEY] = originalEnv;
    }
    exitSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it("passes when the correct magic cookie is set", () => {
    process.env[MAGIC_COOKIE_KEY] = MAGIC_COOKIE_VALUE;
    expect(() => checkMagicCookie()).not.toThrow();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("exits 1 when the magic cookie env var is absent", () => {
    delete process.env[MAGIC_COOKIE_KEY];
    expect(() => checkMagicCookie()).toThrow("process.exit(1)");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("exits 1 when the magic cookie has the wrong value", () => {
    process.env[MAGIC_COOKIE_KEY] = "wrong-value";
    expect(() => checkMagicCookie()).toThrow("process.exit(1)");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("writes a human-readable error to stderr when cookie is missing", () => {
    delete process.env[MAGIC_COOKIE_KEY];
    try {
      checkMagicCookie();
    } catch {
      // expected
    }
    const written = stderrSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("");
    expect(written).toContain(MAGIC_COOKIE_KEY);
    expect(written).toContain(MAGIC_COOKIE_VALUE);
  });

  it("includes the expected key and value in the error message", () => {
    process.env[MAGIC_COOKIE_KEY] = "bad";
    try {
      checkMagicCookie();
    } catch {
      // expected
    }
    const written = stderrSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("");
    expect(written).toContain(MAGIC_COOKIE_KEY);
    expect(written).toContain(MAGIC_COOKIE_VALUE);
  });
});

describe("serveUntilDone", () => {
  it("resolves immediately when SIGTERM is emitted", async () => {
    // Build a minimal stub that satisfies the grpc.Server shape needed by serveUntilDone.
    let shutdownCalled = false;
    const fakeServer = {
      forceShutdown: () => { shutdownCalled = true; },
    } as unknown as import("@grpc/grpc-js").Server;

    const done = serveUntilDone(fakeServer);

    // Emit SIGTERM — the handler must fire synchronously, resolving the promise.
    process.emit("SIGTERM");

    await done;

    expect(shutdownCalled).toBe(true);
  });

  it("calls forceShutdown exactly once even if SIGTERM fires multiple times", async () => {
    let shutdownCount = 0;
    const fakeServer = {
      forceShutdown: () => { shutdownCount++; },
    } as unknown as import("@grpc/grpc-js").Server;

    const done = serveUntilDone(fakeServer);

    process.emit("SIGTERM");
    process.emit("SIGTERM");

    await done;

    expect(shutdownCount).toBe(1);
  });
});
