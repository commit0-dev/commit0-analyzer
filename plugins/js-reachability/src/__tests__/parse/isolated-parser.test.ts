/**
 * Tests for the crash-safe isolated parser (IsolatedParser) and its pool
 * (ParserPool).
 *
 * Uses the tsx ESM loader to spawn workers directly from TypeScript source —
 * no bun binary required. Workers are spawned via an injectable SpawnCommand
 * so tests can control child processes independently of the production
 * bun-binary self-dispatch mechanism.
 *
 * Soundness invariants verified for IsolatedParser:
 *   - Happy path: a valid file returns kind:"parsed" with expected imports.
 *   - Crash recovery: a worker crash resolves the in-flight file as kind:"unknown"
 *     AND the next parse of a normal file still succeeds (worker respawned).
 *   - Timeout: a hanging request resolves as kind:"unknown" within the timeout
 *     and subsequent parses still work.
 *
 * ParserPool invariants verified:
 *   - N=4 pool parses concurrent files and returns correct results.
 *   - A __CRASH__ sentinel on one worker resolves that request as kind:"unknown";
 *     other workers are unaffected and the pool keeps serving requests.
 *   - stop() terminates all workers and is idempotent.
 *
 * Determinism invariants (build-level):
 *   - Two buildCallGraph runs on the same multi-file fixture produce byte-
 *     identical reachableFiles (sorted), importSites, and unknownFrontiers.
 */

import { describe, it, expect, afterEach } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { IsolatedParser } from "../../parse/isolated-parser.js";
import { ParserPool } from "../../parse/parser-pool.js";
import { buildCallGraph } from "../../cg/build.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Absolute path to the worker TypeScript source
const workerSrc = path.resolve(__dirname, "../../parse/parse-worker.ts");

// A real fixture file we can parse
const fixtureDir = path.resolve(__dirname, "../../../testdata/projects/resolve-fixtures/src");
const realFile = path.join(fixtureDir, "index.js");

/** Build a SpawnCommand that runs the worker via npx tsx (tsx available via npx). */
function tsxSpawnCommand() {
  return {
    cmd: "npx",
    args: ["tsx", workerSrc],
  };
}

describe("IsolatedParser – happy path", () => {
  let parser: IsolatedParser;

  afterEach(async () => {
    parser?.stop();
  });

  it("returns kind:parsed for a valid fixture file", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    const result = await parser.parse(realFile);

    expect(result.kind).toBe("parsed");
    if (result.kind === "parsed") {
      const specifiers = result.imports.map((i) => i.specifier);
      // index.js exports helper and util — it has no imports, but we confirm
      // the parse succeeded (kind:"parsed" is the key assertion)
      expect(Array.isArray(result.imports)).toBe(true);
      expect(Array.isArray(result.exports)).toBe(true);
    }
  });

  it("parses an ESM file with imports and returns the import specifiers", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    const appFile = path.join(fixtureDir, "app.js");
    const result = await parser.parse(appFile);

    expect(result.kind).toBe("parsed");
    if (result.kind === "parsed") {
      const specifiers = result.imports.map((i) => i.specifier);
      expect(specifiers).toContain("lodash");
      expect(specifiers).toContain("./index.js");
    }
  });

  it("returns kind:unknown for a non-existent file (not a throw)", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    const result = await parser.parse("/does/not/exist/nowhere.js");

    expect(result.kind).toBe("unknown");
    if (result.kind === "unknown") {
      expect(result.reason).toBeTruthy();
    }
  });

  it("can parse multiple files sequentially", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    const files = [
      path.join(fixtureDir, "index.js"),
      path.join(fixtureDir, "app.js"),
      path.join(fixtureDir, "cjs-module.cjs"),
    ];

    for (const file of files) {
      const result = await parser.parse(file);
      expect(result.kind).toBe("parsed");
    }
  });
});

describe("IsolatedParser – crash recovery", () => {
  let parser: IsolatedParser;

  afterEach(async () => {
    parser?.stop();
  });

  it("resolves in-flight file as kind:unknown when the worker crashes", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    // Send the crash sentinel — the worker calls process.exit(1) on this path
    const crashResult = await parser.parse("__CRASH__");

    expect(crashResult.kind).toBe("unknown");
    if (crashResult.kind === "unknown") {
      expect(crashResult.reason).toBeTruthy();
    }
  });

  it("respawns the worker after a crash and parses the next file successfully", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    // Crash the worker
    const crashResult = await parser.parse("__CRASH__");
    expect(crashResult.kind).toBe("unknown");

    // A small delay to let the exit event propagate before next parse
    await new Promise((r) => setTimeout(r, 50));

    // Next parse should succeed (worker respawned)
    const result = await parser.parse(realFile);
    expect(result.kind).toBe("parsed");
  });

  it("crash reason contains 'crashed' or is non-empty", async () => {
    parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();

    const result = await parser.parse("__CRASH__");
    expect(result.kind).toBe("unknown");
    if (result.kind === "unknown") {
      expect(result.reason.length).toBeGreaterThan(0);
    }
  });
});

describe("IsolatedParser – timeout", () => {
  let timeoutParser: IsolatedParser;

  afterEach(() => {
    timeoutParser?.stop();
  });

  it("resolves as kind:unknown when the worker hangs, and the next parse still works", async () => {
    // We can't shorten PARSE_TIMEOUT_MS without patching internals, so instead
    // we verify the __HANG__ sentinel resolves eventually. To keep tests fast,
    // we test timeout behaviour by asserting the __HANG__ request produces
    // kind:"unknown" within (PARSE_TIMEOUT_MS + margin). In CI this is 20s,
    // which is acceptable for a soundness-critical path test.
    //
    // We use a 25s vitest timeout for this specific test.
    timeoutParser = new IsolatedParser(tsxSpawnCommand());
    timeoutParser.start();

    // This will wait up to PARSE_TIMEOUT_MS (20s) for the timeout to fire
    const result = await timeoutParser.parse("__HANG__");

    expect(result.kind).toBe("unknown");
    if (result.kind === "unknown") {
      expect(result.reason).toContain("timed out");
    }

    // After the timeout the worker should have been respawned — next parse works
    const next = await timeoutParser.parse(realFile);
    expect(next.kind).toBe("parsed");
  }, 30_000); // 30s timeout: PARSE_TIMEOUT_MS (20s) + parse time + margin
});

describe("IsolatedParser – stop is idempotent", () => {
  it("can be stopped multiple times without error", () => {
    const parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();
    parser.stop();
    parser.stop(); // second stop must not throw
  });

  it("returns kind:unknown for parse() after stop()", async () => {
    const parser = new IsolatedParser(tsxSpawnCommand());
    parser.start();
    parser.stop();

    const result = await parser.parse(realFile);
    expect(result.kind).toBe("unknown");
  });
});

// ── ParserPool tests ──────────────────────────────────────────────────────────

describe("ParserPool – concurrent parses return correct results", () => {
  let pool: ParserPool;

  afterEach(() => {
    pool?.stop();
  });

  it("N=4 pool parses multiple real files concurrently and all succeed", async () => {
    pool = new ParserPool({ concurrency: 4, spawnCmd: tsxSpawnCommand() });
    pool.start();

    const files = [
      path.join(fixtureDir, "index.js"),
      path.join(fixtureDir, "app.js"),
      path.join(fixtureDir, "cjs-module.cjs"),
      path.join(fixtureDir, "helpers.js"),
      path.join(fixtureDir, "utils.js"),
      path.join(fixtureDir, "base.js"),
    ];

    // Fire all parses concurrently
    const results = await Promise.all(files.map((f) => pool.parse(f)));

    for (const r of results) {
      expect(r.kind).toBe("parsed");
    }
  });

  it("parses app.js and returns expected imports (specifiers include lodash)", async () => {
    pool = new ParserPool({ concurrency: 2, spawnCmd: tsxSpawnCommand() });
    pool.start();

    const appFile = path.join(fixtureDir, "app.js");
    const result = await pool.parse(appFile);

    expect(result.kind).toBe("parsed");
    if (result.kind === "parsed") {
      const specifiers = result.imports.map((i) => i.specifier);
      expect(specifiers).toContain("lodash");
    }
  });

  it("returns kind:unknown for a non-existent file (never throws)", async () => {
    pool = new ParserPool({ concurrency: 2, spawnCmd: tsxSpawnCommand() });
    pool.start();

    const result = await pool.parse("/does/not/exist.js");
    expect(result.kind).toBe("unknown");
  });
});

describe("ParserPool – crash isolation: one worker crash does not affect others", () => {
  it("crash on one worker resolves that request as unknown; pool keeps serving other files", async () => {
    // Use N=4 so multiple workers are available. The __CRASH__ sentinel kills
    // exactly one worker. The pool should continue serving the remaining files
    // on the other workers (or the respawned worker).
    const pool = new ParserPool({ concurrency: 4, spawnCmd: tsxSpawnCommand() });
    pool.start();

    try {
      const realFiles = [
        path.join(fixtureDir, "index.js"),
        path.join(fixtureDir, "app.js"),
        path.join(fixtureDir, "helpers.js"),
      ];

      // Dispatch the crash alongside real files concurrently
      const [crashResult, ...realResults] = await Promise.all([
        pool.parse("__CRASH__"),
        ...realFiles.map((f) => pool.parse(f)),
      ]);

      // The crashed request must resolve as unknown
      expect(crashResult.kind).toBe("unknown");

      // Real files must still be parsed successfully (other workers unaffected)
      for (const r of realResults) {
        expect(r.kind).toBe("parsed");
      }

      // After recovery, further parses must still work
      const afterCrash = await pool.parse(path.join(fixtureDir, "utils.js"));
      expect(afterCrash.kind).toBe("parsed");
    } finally {
      pool.stop();
    }
  });
});

describe("ParserPool – stop() is idempotent", () => {
  it("can be stopped multiple times without error", () => {
    const pool = new ParserPool({ concurrency: 2, spawnCmd: tsxSpawnCommand() });
    pool.start();
    pool.stop();
    pool.stop(); // second stop must not throw
  });

  it("returns kind:unknown for parse() after stop()", async () => {
    const pool = new ParserPool({ concurrency: 2, spawnCmd: tsxSpawnCommand() });
    pool.start();
    pool.stop();

    const result = await pool.parse(realFile);
    expect(result.kind).toBe("unknown");
  });

  it("stop() drains queued (not-yet-dispatched) requests as unknown", async () => {
    // concurrency=1 means only one parse runs at a time; extra requests queue
    const pool = new ParserPool({ concurrency: 1, spawnCmd: tsxSpawnCommand() });
    pool.start();

    // Start a slow-ish parse to occupy the single slot
    const inFlight = pool.parse(path.join(fixtureDir, "app.js"));
    // Queue another request (will be queued since concurrency=1 and slot is busy)
    const queued = pool.parse(path.join(fixtureDir, "index.js"));

    // Stop immediately — queued request must drain as unknown
    pool.stop();

    const [r1, r2] = await Promise.all([inFlight, queued]);
    // The queued request is drained as unknown
    expect(r2.kind).toBe("unknown");
    // The in-flight request may succeed or be unknown depending on timing — just
    // verify it resolved and did not throw
    expect(r1.kind).toMatch(/^(parsed|unknown)$/);
  });
});

// ── Determinism test (build-level) ────────────────────────────────────────────

describe("buildCallGraph – concurrent BFS produces deterministic output", () => {
  it("two runs on the same fixture produce identical reachableFiles, importSites, and unknownFrontiers", async () => {
    // Use the transitive-cross-pkg fixture which has dep traversal and frontiers
    const fixture = path.resolve(__dirname, "../../../testdata/projects/transitive-cross-pkg");
    const entrypoint = path.join(fixture, "index.js");

    const opts = { projectRoot: fixture, entrypoints: [entrypoint] };

    const run1 = await buildCallGraph(opts);
    const run2 = await buildCallGraph(opts);

    // Reachable files: sort both and compare
    const files1 = [...run1.reachableFiles].sort();
    const files2 = [...run2.reachableFiles].sort();
    expect(files1).toEqual(files2);

    // Import sites: same packages with same sorted entries
    const pkgs1 = [...run1.importSites.keys()].sort();
    const pkgs2 = [...run2.importSites.keys()].sort();
    expect(pkgs1).toEqual(pkgs2);
    for (const pkg of pkgs1) {
      const sites1 = run1.importSites.get(pkg)!;
      const sites2 = run2.importSites.get(pkg)!;
      expect(sites1).toEqual(sites2);
    }

    // Unknown frontiers: same list (already sorted by build.ts before return)
    expect(run1.unknownFrontiers).toEqual(run2.unknownFrontiers);
  });
});
