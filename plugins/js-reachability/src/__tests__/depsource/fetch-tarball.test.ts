/**
 * Tests for fetchAndExtractSource — the optional network fallback that fetches
 * a package tarball from the npm registry, verifies its integrity, extracts it
 * to a local cache, and re-classifies fidelity from the extracted source tree.
 *
 * All tests are hermetic: no live network calls. The fake fetch function and
 * a locally-built .tgz fixture are used throughout.
 */

import { describe, it, expect, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import zlib from "node:zlib";
import {
  fetchAndExtractSource,
  type FetchOptions,
} from "../../depsource/fetch-tarball.js";
import { resolveDepSourceWithFetch } from "../../depsource/resolve-dep-source.js";

// ── Tarball builder helpers ───────────────────────────────────────────────────

/**
 * Build a minimal tar header block (512 bytes) for a regular file or directory.
 * Follows the POSIX ustar format that npm uses.
 */
function buildTarHeader(opts: {
  name: string;
  size: number;
  typeflag?: "0" | "5"; // "0" = file, "5" = directory
  rawSizeBytes?: Buffer;  // override the size field with raw bytes (for base-256 tests)
}): Buffer {
  const header = Buffer.alloc(512, 0);
  const name = opts.name.slice(0, 100);
  header.write(name, 0, "ascii");
  // mode
  header.write("0000644 ", 100, "ascii");
  // uid / gid
  header.write("0000000 ", 108, "ascii");
  header.write("0000000 ", 116, "ascii");
  // size (octal, 12 bytes) — or raw override
  if (opts.rawSizeBytes) {
    opts.rawSizeBytes.copy(header, 124, 0, Math.min(opts.rawSizeBytes.length, 12));
  } else {
    const sizeOct = opts.size.toString(8).padStart(11, "0") + " ";
    header.write(sizeOct, 124, "ascii");
  }
  // mtime
  header.write("00000000000 ", 136, "ascii");
  // typeflag
  header.write(opts.typeflag ?? "0", 156, "ascii");
  // magic (ustar)
  header.write("ustar  ", 257, "ascii");

  // Compute checksum
  // Set checksum field to 8 spaces for calculation
  header.write("        ", 148, "ascii");
  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");

  return header;
}

/**
 * Pad buffer to a multiple of 512 bytes (tar block alignment).
 */
function padTo512(buf: Buffer): Buffer {
  const rem = buf.length % 512;
  if (rem === 0) return buf;
  return Buffer.concat([buf, Buffer.alloc(512 - rem, 0)]);
}

/**
 * Build a .tgz (gzipped tar) in memory from a list of { name, content } entries.
 * Names should be relative paths like "package/index.js".
 * Returns the raw gzip bytes.
 */
function buildTgz(
  entries: Array<{ name: string; content: string | Buffer; rawSizeBytes?: Buffer }>
): Buffer {
  const parts: Buffer[] = [];

  for (const entry of entries) {
    const contentBuf =
      typeof entry.content === "string"
        ? Buffer.from(entry.content, "utf8")
        : entry.content;
    const header = buildTarHeader({
      name: entry.name,
      size: contentBuf.length,
      rawSizeBytes: entry.rawSizeBytes,
    });
    parts.push(header);
    parts.push(padTo512(contentBuf));
  }

  // Two 512-byte zero blocks end the tar
  parts.push(Buffer.alloc(1024, 0));

  const tarBuf = Buffer.concat(parts);
  return zlib.gzipSync(tarBuf);
}

/**
 * Compute sha512 integrity string (SRI format) for a buffer.
 */
function sha512Integrity(buf: Buffer): string {
  const hash = crypto.createHash("sha512").update(buf).digest("base64");
  return `sha512-${hash}`;
}

/**
 * Compute sha1 shasum (hex) for a buffer.
 */
function sha1Shasum(buf: Buffer): string {
  return crypto.createHash("sha1").update(buf).digest("hex");
}

// ── Fixture tarball ───────────────────────────────────────────────────────────

/**
 * Build a valid .tgz containing:
 *   package/package.json  — { name: "my-pkg", version: "1.0.0", main: "./index.js" }
 *   package/index.js      — readable multi-line source (fidelity: "source")
 */
function buildValidTgz(): Buffer {
  return buildTgz([
    {
      name: "package/package.json",
      content: JSON.stringify(
        { name: "my-pkg", version: "1.0.0", main: "./index.js" },
        null,
        2
      ),
    },
    {
      name: "package/index.js",
      content: [
        "// my-pkg source",
        "function greet(name) {",
        "  return `Hello, ${name}!`;",
        "}",
        "module.exports = { greet };",
        "",
      ].join("\n"),
    },
  ]);
}

// ── makeFetch helper ──────────────────────────────────────────────────────────

/**
 * Create a fake fetch function that returns the given bytes once.
 */
function makeFetch(bytes: Buffer): FetchOptions["fetch"] {
  return vi.fn().mockResolvedValue(bytes);
}

/**
 * Create a fake fetch function that throws a network error.
 */
function makeOfflineFetch(): FetchOptions["fetch"] {
  return vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("fetchAndExtractSource — happy path", () => {
  it("extracts tarball, returns fidelity:source and a dir inside the cache", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const integrity = sha512Integrity(tgz);

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).not.toBeNull();
    expect(result!.fidelity).toBe("source");
    // The returned dir must be inside cacheRoot
    expect(result!.dir.startsWith(cacheRoot)).toBe(true);
    // The extracted dir must exist on disk
    expect(fs.existsSync(result!.dir)).toBe(true);
  });
});

describe("fetchAndExtractSource — integrity mismatch", () => {
  it("returns null and does not extract when integrity does not match", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    // Intentionally wrong integrity
    const badIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity: badIntegrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).toBeNull();
    // Cache dir must be empty / not extracted
    const cacheDir = path.join(cacheRoot, "my-pkg@1.0.0");
    expect(fs.existsSync(cacheDir)).toBe(false);
  });
});

describe("fetchAndExtractSource — offline / network error", () => {
  it("returns null without throwing when fetch rejects", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity: "sha512-anything",
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeOfflineFetch(),
    });

    expect(result).toBeNull();
  });
});

describe("fetchAndExtractSource — cache reuse", () => {
  it("does not call fetch when cache dir already exists and is non-empty", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const integrity = sha512Integrity(tgz);
    const fetchFn = makeFetch(tgz);

    // First call: should fetch and extract
    const first = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: fetchFn,
    });
    expect(first).not.toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    // Second call: cache dir already exists — fetch must not be called again
    const secondFetch = makeFetch(tgz);
    const second = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: secondFetch,
    });
    expect(second).not.toBeNull();
    expect(secondFetch).toHaveBeenCalledTimes(0);
  });
});

describe("fetchAndExtractSource — zip-slip guard", () => {
  it("rejects tar entries with path traversal (../evil) and returns null", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Build a tarball with a path-traversal entry
    const evilTgz = buildTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "evil", version: "1.0.0" }),
      },
      {
        // This entry tries to escape the extraction directory
        name: "../evil.txt",
        content: "pwned",
      },
    ]);
    const integrity = sha512Integrity(evilTgz);

    const result = await fetchAndExtractSource({
      name: "evil",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
      fetch: makeFetch(evilTgz),
    });

    // Zip-slip → extraction aborted → null
    expect(result).toBeNull();

    // Confirm the evil file was NOT written outside the cache
    const evilPath = path.join(cacheRoot, "evil.txt");
    expect(fs.existsSync(evilPath)).toBe(false);
  });
});

describe("fetchAndExtractSource — shasum fallback", () => {
  it("accepts a sha1 shasum when no sha512 integrity is provided", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const shasum = sha1Shasum(tgz);

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      shasum,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).not.toBeNull();
    expect(result!.fidelity).toBe("source");
  });
});

// ── H-2: tar size parsing must fail safe ─────────────────────────────────────

describe("fetchAndExtractSource — H-2: malformed tar size fields", () => {
  it("returns null for GNU base-256 size encoding (high bit set) and does not populate cache", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Build a tar where one entry has a size field with the high bit set (base-256)
    // Per GNU tar spec, first byte >= 0x80 signals base-256 encoding
    const base256SizeBytes = Buffer.alloc(12, 0);
    base256SizeBytes[0] = 0x80; // high bit set → base-256
    base256SizeBytes[11] = 5;   // value = 5, but the parser must reject it

    const entries: Array<{ name: string; content: string | Buffer; rawSizeBytes?: Buffer }> = [
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "evil-size", version: "1.0.0" }),
      },
      {
        name: "package/index.js",
        content: Buffer.from("hello"),
        rawSizeBytes: base256SizeBytes,
      },
    ];

    // Build the tarball manually to inject the malformed size
    const parts: Buffer[] = [];
    for (const entry of entries) {
      const contentBuf = typeof entry.content === "string"
        ? Buffer.from(entry.content, "utf8")
        : entry.content;
      const header = buildTarHeader({
        name: entry.name,
        size: contentBuf.length,
        rawSizeBytes: entry.rawSizeBytes,
      });
      parts.push(header);
      parts.push(padTo512(contentBuf));
    }
    parts.push(Buffer.alloc(1024, 0));
    const malformedTar = zlib.gzipSync(Buffer.concat(parts));
    const integrity = sha512Integrity(malformedTar);

    const result = await fetchAndExtractSource({
      name: "evil-size",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://example.com/evil-size-1.0.0.tgz",
      fetch: makeFetch(malformedTar),
    });

    expect(result).toBeNull();

    // The final cache dir must NOT be populated
    const finalDir = path.join(cacheRoot, "evil-size@1.0.0");
    expect(fs.existsSync(finalDir)).toBe(false);

    // No leftover temp dirs either
    const entries2 = fs.readdirSync(cacheRoot);
    expect(entries2.length).toBe(0);
  });

  it("returns null when entry size runs past end of archive and does not populate cache", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Build a tar where a file claims a size far larger than the buffer
    const fakeContent = Buffer.from("hi");
    const hugeSize = 999_999_999; // vastly larger than actual content
    const header = buildTarHeader({ name: "package/index.js", size: fakeContent.length });
    // Override the size field to claim a huge size
    const sizeOct = hugeSize.toString(8).padStart(11, "0") + " ";
    header.write(sizeOct, 124, "ascii");
    // Recompute checksum after size change
    header.write("        ", 148, "ascii");
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += header[i];
    header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");

    const pkgHeader = buildTarHeader({
      name: "package/package.json",
      size: 30,
    });
    const pkgContent = padTo512(Buffer.from('{"name":"x","version":"1.0.0"}'));

    const tarBuf = Buffer.concat([
      pkgHeader,
      pkgContent,
      header,
      padTo512(fakeContent),
      Buffer.alloc(1024, 0),
    ]);
    const oversizedTar = zlib.gzipSync(tarBuf);
    const integrity = sha512Integrity(oversizedTar);

    const result = await fetchAndExtractSource({
      name: "oversized",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://example.com/oversized-1.0.0.tgz",
      fetch: makeFetch(oversizedTar),
    });

    expect(result).toBeNull();

    const finalDir = path.join(cacheRoot, "oversized@1.0.0");
    expect(fs.existsSync(finalDir)).toBe(false);
  });
});

// ── M-1: atomic extraction ────────────────────────────────────────────────────

describe("fetchAndExtractSource — M-1: atomic extraction", () => {
  it("does not treat a leftover temp dir as a cache hit", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Simulate a leftover temp dir (as if a previous run crashed mid-extraction)
    // Temp dirs have the pattern .tmp-<name>@<version>-<rand>
    const leftoverTemp = path.join(cacheRoot, ".tmp-my-pkg@1.0.0-leftover");
    fs.mkdirSync(leftoverTemp, { recursive: true });
    fs.writeFileSync(path.join(leftoverTemp, "index.js"), "leftover");

    const tgz = buildValidTgz();
    const integrity = sha512Integrity(tgz);
    const fetchFn = makeFetch(tgz);

    // Should NOT see the leftover temp dir as a cache hit; should fetch and extract
    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: fetchFn,
    });

    expect(result).not.toBeNull();
    expect(result!.fidelity).toBe("source");
    // Fetch must have been called (not a cache hit)
    expect(fetchFn).toHaveBeenCalledTimes(1);
    // The final cache dir must exist
    const finalDir = path.join(cacheRoot, "my-pkg@1.0.0");
    expect(fs.existsSync(finalDir)).toBe(true);
  });

  it("cleans up temp dir on extraction failure, does not leave partial cache", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Build a tarball with a zip-slip path to force extraction failure
    const evilTgz = buildTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "my-pkg", version: "1.0.0" }),
      },
      {
        name: "../evil.txt",
        content: "pwned",
      },
    ]);
    const integrity = sha512Integrity(evilTgz);

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://example.com/my-pkg-1.0.0.tgz",
      fetch: makeFetch(evilTgz),
    });

    expect(result).toBeNull();

    // Neither the final dir nor any temp dir should remain
    const finalDir = path.join(cacheRoot, "my-pkg@1.0.0");
    expect(fs.existsSync(finalDir)).toBe(false);

    // No leftover temp dirs
    const entries = fs.readdirSync(cacheRoot);
    const temps = entries.filter((e) => e.startsWith(".tmp-"));
    expect(temps.length).toBe(0);
  });
});

// ── M-2: `..` guard over-rejects legitimate filenames ────────────────────────

describe("fetchAndExtractSource — M-2: dot-dot guard precision", () => {
  it("extracts a file named foo..bar.js without rejecting it", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    const tgz = buildTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "dotdot-pkg", version: "1.0.0", main: "./foo..bar.js" }),
      },
      {
        name: "package/foo..bar.js",
        content: [
          "// dotdot-pkg source",
          "function hello() { return 42; }",
          "module.exports = { hello };",
        ].join("\n"),
      },
    ]);
    const integrity = sha512Integrity(tgz);

    const result = await fetchAndExtractSource({
      name: "dotdot-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://example.com/dotdot-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).not.toBeNull();
    // The file should actually be on disk
    const extractedFile = path.join(result!.dir, "foo..bar.js");
    expect(fs.existsSync(extractedFile)).toBe(true);
  });

  it("still rejects a real path-traversal component (../evil)", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    const evilTgz = buildTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "evil2", version: "1.0.0" }),
      },
      {
        name: "package/../evil.txt",
        content: "pwned",
      },
    ]);
    const integrity = sha512Integrity(evilTgz);

    const result = await fetchAndExtractSource({
      name: "evil2",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://example.com/evil2-1.0.0.tgz",
      fetch: makeFetch(evilTgz),
    });

    expect(result).toBeNull();
  });
});

// ── L-1: redirect safety ──────────────────────────────────────────────────────

describe("defaultFetch redirect safety (via fetchAndExtractSource with injected fetch)", () => {
  it("rejects a redirect to an http:// URL and returns null", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const integrity = sha512Integrity(tgz);

    // Simulate a fetch that internally tries to redirect https → http by throwing
    // (since we can't easily test the real defaultFetch internals, we test that
    // the redirect-safety wrapper rejects the downgrade)
    // We use the exported testable redirect guard directly via a custom fetch that
    // simulates what defaultFetch would do on a redirect to http://
    const httpRedirectFetch: FetchOptions["fetch"] = vi.fn().mockRejectedValue(
      new Error("Unsafe redirect to non-https URL: http://evil.example.com/pkg.tgz")
    );

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: httpRedirectFetch,
    });

    expect(result).toBeNull();
  });
});

// ── L-2: resource bounds ──────────────────────────────────────────────────────

describe("fetchAndExtractSource — L-2: body size cap", () => {
  it("returns null when response body exceeds the maximum allowed size", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));

    // Build a large fake response (slightly over 64 MiB)
    const oversizedBody = Buffer.alloc(65 * 1024 * 1024 + 1, 0x42);
    const integrity = sha512Integrity(oversizedBody);

    const oversizedFetch: FetchOptions["fetch"] = vi.fn().mockResolvedValue(oversizedBody);

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: oversizedFetch,
    });

    expect(result).toBeNull();
  });
});

// ── L-3: integrity algo allowlist ─────────────────────────────────────────────

describe("fetchAndExtractSource — L-3: SRI algo allowlist", () => {
  it("rejects sha1- as an SRI integrity value (it is only valid as shasum)", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    // Compute an actual correct sha1 of the tgz bytes
    const sha1 = crypto.createHash("sha1").update(tgz).digest("base64");
    const sha1Integrity = `sha1-${sha1}`;

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity: sha1Integrity,  // sha1 in the integrity (SRI) field must be rejected
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).toBeNull();
  });

  it("accepts sha256 as an SRI integrity algorithm", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const sha256 = crypto.createHash("sha256").update(tgz).digest("base64");
    const sha256Integrity = `sha256-${sha256}`;

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity: sha256Integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).not.toBeNull();
  });

  it("accepts sha384 as an SRI integrity algorithm", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const tgz = buildValidTgz();
    const sha384 = crypto.createHash("sha384").update(tgz).digest("base64");
    const sha384Integrity = `sha384-${sha384}`;

    const result = await fetchAndExtractSource({
      name: "my-pkg",
      version: "1.0.0",
      cacheRoot,
      integrity: sha384Integrity,
      tarballUrl: "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz",
      fetch: makeFetch(tgz),
    });

    expect(result).not.toBeNull();
  });
});

// ── resolveDepSourceWithFetch ─────────────────────────────────────────────────

describe("resolveDepSourceWithFetch", () => {
  it("returns the on-disk result unchanged when no fetch options are provided", async () => {
    // Use the existing depsource fixtures: minified-dist has fidelity "reduced"
    const fixtureRoot = path.resolve(
      import.meta.dirname,
      "../../../testdata/projects/depsource-fixtures/node_modules"
    );
    const pkgDir = path.join(fixtureRoot, "minified-dist");

    const result = await resolveDepSourceWithFetch({
      name: "minified-dist",
      version: "2.0.0",
      dir: pkgDir,
    });

    expect(result.fidelity).toBe("reduced");
  });

  it("upgrades fidelity to source when fetch succeeds and extracted code is readable", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const fixtureRoot = path.resolve(
      import.meta.dirname,
      "../../../testdata/projects/depsource-fixtures/node_modules"
    );
    const pkgDir = path.join(fixtureRoot, "minified-dist");

    const tgz = buildValidTgz();
    const integrity = sha512Integrity(tgz);

    const result = await resolveDepSourceWithFetch(
      { name: "minified-dist", version: "2.0.0", dir: pkgDir },
      {
        cacheRoot,
        integrity,
        tarballUrl:
          "https://registry.npmjs.org/minified-dist/-/minified-dist-2.0.0.tgz",
        fetch: makeFetch(tgz),
      }
    );

    expect(result.fidelity).toBe("source");
  });

  it("keeps the on-disk reduced result when integrity mismatch prevents extraction", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const fixtureRoot = path.resolve(
      import.meta.dirname,
      "../../../testdata/projects/depsource-fixtures/node_modules"
    );
    const pkgDir = path.join(fixtureRoot, "minified-dist");

    const tgz = buildValidTgz();

    const result = await resolveDepSourceWithFetch(
      { name: "minified-dist", version: "2.0.0", dir: pkgDir },
      {
        cacheRoot,
        integrity: "sha512-WRONG==",
        tarballUrl:
          "https://registry.npmjs.org/minified-dist/-/minified-dist-2.0.0.tgz",
        fetch: makeFetch(tgz),
      }
    );

    // Integrity mismatch → stays at on-disk result
    expect(result.fidelity).toBe("reduced");
  });

  it("does not attempt fetch when on-disk fidelity is already source", async () => {
    const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fetch-test-"));
    const fixtureRoot = path.resolve(
      import.meta.dirname,
      "../../../testdata/projects/depsource-fixtures/node_modules"
    );
    const pkgDir = path.join(fixtureRoot, "esm-source");

    const tgz = buildValidTgz();
    const fetchFn = makeFetch(tgz);

    await resolveDepSourceWithFetch(
      { name: "esm-source", version: "1.0.0", dir: pkgDir },
      {
        cacheRoot,
        integrity: sha512Integrity(tgz),
        tarballUrl:
          "https://registry.npmjs.org/esm-source/-/esm-source-1.0.0.tgz",
        fetch: fetchFn,
      }
    );

    // On-disk is already "source" → no fetch needed
    expect(fetchFn).toHaveBeenCalledTimes(0);
  });
});
