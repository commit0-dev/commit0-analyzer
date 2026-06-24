/**
 * Optional network fallback: fetch a package tarball from the npm registry,
 * verify its integrity, extract it to a local cache, and re-classify fidelity
 * from the extracted source tree.
 *
 * Security invariant: integrity is verified BEFORE any bytes are written to
 * disk. A mismatch or any error returns null — the caller's current (on-disk)
 * classification is preserved unchanged. Never throws.
 *
 * Extraction safety:
 *   - Tar entries with absolute paths or `..` path components are rejected
 *     (zip-slip guard). Any such entry aborts the entire extraction.
 *   - GNU base-256 size encoding (high bit set) is unsupported and causes
 *     rejection of the entire archive.
 *   - Claimed sizes that extend beyond the end of the archive are rejected.
 *   - Only the POSIX ustar / GNU tar formats written by npm are supported.
 *   - Each entry is extracted relative to the cache directory.
 *   - Extraction is atomic: bytes are written to a temp sibling dir and
 *     renamed into the final cache path only after complete success.
 *
 * Cache semantics:
 *   - If <cacheRoot>/<name>@<version>/ already exists and is non-empty, reuse
 *     it without fetching (idempotent across process restarts).
 *   - Leftover temp dirs (prefix `.tmp-`) are never treated as cache hits.
 *
 * Resource bounds:
 *   - Response bodies larger than MAX_COMPRESSED_BYTES are rejected before
 *     integrity check or decompression.
 *   - Gunzip output is capped at MAX_DECOMPRESSED_BYTES to prevent zip-bombs.
 *
 * Redirect safety:
 *   - Only absolute https:// redirect targets are followed; relative locations
 *     and any non-https scheme cause the request to fail.
 *
 * Integrity algorithm allowlist:
 *   - The `integrity` (SRI) field accepts only sha256, sha384, or sha512.
 *   - The legacy `shasum` field uses sha1 (npm registry metadata).
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { resolveDepSource } from "./resolve-dep-source.js";
import type { DepSource } from "./types.js";

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum compressed tarball size accepted from the network (64 MiB). */
const MAX_COMPRESSED_BYTES = 64 * 1024 * 1024;

/** Maximum decompressed tar size passed to the extractor (512 MiB). */
const MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024;

/** SRI algorithm names accepted in the `integrity` field. */
const ALLOWED_SRI_ALGOS = new Set(["sha256", "sha384", "sha512"]);

// ── Public types ──────────────────────────────────────────────────────────────

/** Injectable fetch function: given a URL, returns the raw response bytes. */
export type FetchFn = (url: string) => Promise<Buffer>;

/** Options for fetchAndExtractSource. */
export interface FetchOptions {
  /** Package name (e.g. "lodash"). */
  name: string;
  /** Exact version string (e.g. "4.17.21"). */
  version: string;
  /** Root directory under which per-package cache subdirectories are created. */
  cacheRoot: string;
  /** Tarball URL to fetch when no cached copy exists. */
  tarballUrl: string;
  /**
   * Expected SRI integrity string (sha256/sha384/sha512-<base64>). When
   * provided it is verified against the downloaded bytes before extraction.
   * sha1 is NOT accepted here; use `shasum` for the legacy sha1 field.
   */
  integrity?: string;
  /**
   * Expected sha1 hex checksum (the `shasum` field in npm registry metadata).
   * Used as a fallback when `integrity` is not provided.
   */
  shasum?: string;
  /**
   * Injectable fetch implementation. Defaults to a thin Node https wrapper.
   * Tests supply a fake that returns fixture bytes without network calls.
   */
  fetch?: FetchFn;
}

/** Result from a successful fetch-and-extract. */
export interface FetchResult {
  /** Absolute path to the extracted package directory inside the cache. */
  dir: string;
  /** Fidelity of the extracted source, as classified by resolveDepSource. */
  fidelity: DepSource["fidelity"];
  /** Entry file inside the extracted directory, or null. */
  entryFile: string | null;
}

// ── Default fetch implementation ──────────────────────────────────────────────

/**
 * Minimal https-based fetch that returns the response body as a Buffer.
 * Follows up to 3 redirects. Only follows redirects to absolute https:// URLs.
 * Rejects on non-2xx status or unsafe redirect targets.
 * Rejects when the response body exceeds MAX_COMPRESSED_BYTES.
 */
async function defaultFetch(url: string, redirectsLeft = 3): Promise<Buffer> {
  const { default: https } = await import("node:https");
  return new Promise((resolve, reject) => {
    if (!url.startsWith("https://")) {
      reject(new Error(`Unsafe redirect to non-https URL: ${url}`));
      return;
    }
    https
      .get(url, (res) => {
        // Follow redirects only to absolute https:// URLs.
        if (
          redirectsLeft > 0 &&
          res.statusCode !== undefined &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          const location = res.headers.location;
          res.resume();
          if (!location.startsWith("https://")) {
            reject(
              new Error(`Unsafe redirect to non-https URL: ${location}`)
            );
            return;
          }
          defaultFetch(location, redirectsLeft - 1).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        res.on("data", (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_COMPRESSED_BYTES) {
            res.destroy();
            reject(
              new Error(
                `Response body exceeds maximum allowed size (${MAX_COMPRESSED_BYTES} bytes) for ${url}`
              )
            );
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

// ── Integrity verification ────────────────────────────────────────────────────

/**
 * Verify the integrity of `bytes` against either the SRI integrity string or
 * the sha1 shasum. Returns true when the check passes, false on mismatch.
 * When neither value is provided, returns false (no unverified extraction).
 *
 * The SRI `integrity` field is restricted to sha256, sha384, and sha512.
 * sha1 is only accepted via the legacy `shasum` field.
 */
function verifyIntegrity(
  bytes: Buffer,
  integrity: string | undefined,
  shasum: string | undefined
): boolean {
  if (integrity !== undefined) {
    const m = integrity.match(/^(sha\d+)-(.+)$/);
    if (m === null) return false;
    const [, algo, expected] = m;
    // Restrict SRI to the safe modern hash algorithms.
    if (!ALLOWED_SRI_ALGOS.has(algo)) return false;
    const actual = crypto
      .createHash(algo)
      .update(bytes)
      .digest("base64");
    return actual === expected;
  }
  if (shasum !== undefined) {
    const actual = crypto.createHash("sha1").update(bytes).digest("hex");
    return actual === shasum;
  }
  return false;
}

// ── Tar extraction ────────────────────────────────────────────────────────────

const TAR_BLOCK = 512;

/**
 * Extract a gzip-compressed tar archive into `destDir`.
 *
 * Safety rules:
 *   - GNU base-256 size encoding (first size byte has high bit set) is
 *     unsupported; throws immediately to avoid silent desync.
 *   - Claimed sizes that exceed the buffer bounds are rejected.
 *   - End-of-archive is signalled by two consecutive zero blocks; a single
 *     zero block or empty name is not treated as termination.
 *   - Entries with absolute paths are rejected (zip-slip guard).
 *   - Entries whose path contains a `..` component (a segment that is exactly
 *     `..`) are rejected. Filenames like `foo..bar.js` are NOT rejected.
 *   - Entries whose resolved destination is outside `destDir` are rejected.
 *   - Any rejection aborts the entire extraction and throws.
 *
 * Only regular-file (typeflag "0" or "\0") and directory (typeflag "5")
 * entries are processed. All others are skipped.
 *
 * npm tarballs nest files under a `package/` prefix; this function strips that
 * prefix so the extracted layout matches a typical node_modules installation.
 */
function extractTgz(tgzBytes: Buffer, destDir: string): void {
  const tar = zlib.gunzipSync(tgzBytes, { maxOutputLength: MAX_DECOMPRESSED_BYTES });

  let offset = 0;
  let consecutiveZeroBlocks = 0;

  while (offset + TAR_BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK);
    offset += TAR_BLOCK;

    if (isZeroBlock(header)) {
      consecutiveZeroBlocks++;
      if (consecutiveZeroBlocks >= 2) {
        // Canonical end-of-archive: two consecutive zero blocks.
        break;
      }
      continue;
    }
    consecutiveZeroBlocks = 0;

    const name = readString(header, 0, 100);
    if (name === "") {
      // Unnamed entry after non-zero data; skip rather than break.
      continue;
    }

    const typeflag = String.fromCharCode(header[156]);

    // Detect GNU base-256 size encoding: first byte of size field has high bit set.
    const firstSizeByte = header[124];
    if (firstSizeByte & 0x80) {
      throw new Error(
        `tar: unsupported GNU base-256 size encoding in entry ${JSON.stringify(name)}`
      );
    }

    const sizeStr = readString(header, 124, 12).trim();
    const size = parseInt(sizeStr, 8);

    // Reject NaN or negative sizes.
    if (!Number.isFinite(size) || size < 0) {
      throw new Error(
        `tar: invalid size field in entry ${JSON.stringify(name)}: ${JSON.stringify(sizeStr)}`
      );
    }

    const blocksForData = Math.ceil(size / TAR_BLOCK);

    // Reject sizes that extend beyond the end of the archive.
    if (offset + size > tar.length) {
      throw new Error(
        `tar: entry size extends beyond archive bounds in ${JSON.stringify(name)}: claimed ${size}, available ${tar.length - offset}`
      );
    }

    // Strip the leading "package/" prefix that npm uses in its tarballs.
    const strippedName = name.startsWith("package/")
      ? name.slice("package/".length)
      : name;

    // Skip empty stripped names (the "package/" directory entry itself).
    if (strippedName === "" || strippedName === "./") {
      offset += blocksForData * TAR_BLOCK;
      continue;
    }

    // Zip-slip guard: reject absolute paths.
    if (path.isAbsolute(strippedName)) {
      throw new Error(
        `tar: unsafe absolute entry path rejected: ${JSON.stringify(name)}`
      );
    }

    // Reject entries whose path contains a component that is exactly `..`.
    // Split on both `/` and the platform separator to cover all cases.
    // This intentionally allows filenames like `foo..bar.js`.
    const components = strippedName.split(/[/\\]/);
    for (const component of components) {
      if (component === "..") {
        throw new Error(
          `tar: unsafe path traversal component in entry: ${JSON.stringify(name)}`
        );
      }
    }

    const dest = path.join(destDir, strippedName);

    // Defense-in-depth: verify the resolved path stays inside destDir.
    if (!dest.startsWith(destDir + path.sep) && dest !== destDir) {
      throw new Error(
        `tar: path escapes destination: ${JSON.stringify(dest)}`
      );
    }

    if (typeflag === "5") {
      // Directory entry
      fs.mkdirSync(dest, { recursive: true });
    } else if (typeflag === "0" || typeflag === "\0") {
      // Regular file
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const dataStart = offset;
      const dataEnd = dataStart + size;
      fs.writeFileSync(dest, tar.subarray(dataStart, dataEnd));
    }
    // Skip other entry types (symlinks, hard links, etc.)

    offset += blocksForData * TAR_BLOCK;
  }
}

function isZeroBlock(block: Buffer): boolean {
  for (let i = 0; i < TAR_BLOCK; i++) {
    if (block[i] !== 0) return false;
  }
  return true;
}

function readString(buf: Buffer, start: number, len: number): string {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return buf.subarray(start, end).toString("utf8");
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

/** Return the final cache directory path for a given package name + version. */
function cacheDir(cacheRoot: string, name: string, version: string): string {
  // Use "@" as the separator; safe on all platforms since npm uses it.
  return path.join(cacheRoot, `${name}@${version}`);
}

/**
 * Return a temp sibling directory path for atomic extraction.
 * The `.tmp-` prefix ensures these are never mistaken for completed cache dirs.
 */
function tempCacheDir(
  cacheRoot: string,
  name: string,
  version: string
): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return path.join(cacheRoot, `.tmp-${name}@${version}-${rand}`);
}

/** Return true when `dir` exists and contains at least one entry. */
function dirNonEmpty(dir: string): boolean {
  try {
    return fs.readdirSync(dir).length > 0;
  } catch {
    return false;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Fetch a package tarball, verify integrity, extract to a cache directory, and
 * classify the fidelity of the extracted source.
 *
 * Returns null on any failure: integrity mismatch, network/fetch error,
 * extraction error (including zip-slip), or missing integrity values.
 * Never throws.
 *
 * Extraction is atomic: bytes are written to a temp dir and renamed into the
 * final cache path only after the full extraction succeeds. On any failure the
 * temp dir is removed, leaving the cache in its prior state.
 *
 * Temp dirs (`.tmp-` prefix) are never treated as cache hits.
 */
export async function fetchAndExtractSource(
  opts: FetchOptions
): Promise<FetchResult | null> {
  const { name, version, cacheRoot, tarballUrl, integrity, shasum } = opts;
  const fetchFn = opts.fetch ?? defaultFetch;

  const dest = cacheDir(cacheRoot, name, version);

  // Cache hit: if the FINAL directory already exists and is non-empty, reuse it.
  // Temp dirs (.tmp- prefix) are not cache hits even if non-empty.
  if (dirNonEmpty(dest)) {
    const cached = resolveDepSource({ name, version, dir: dest });
    return { dir: dest, fidelity: cached.fidelity, entryFile: cached.entryFile };
  }

  // Enforce body size cap before any disk work.
  let bytes: Buffer;
  try {
    bytes = await fetchFn(tarballUrl);
  } catch {
    return null;
  }

  // Reject oversized responses from injected fetch implementations.
  if (bytes.length > MAX_COMPRESSED_BYTES) {
    return null;
  }

  // Verify integrity BEFORE writing anything to disk.
  if (!verifyIntegrity(bytes, integrity, shasum)) {
    return null;
  }

  // Atomic extraction: write to a temp dir, rename on success.
  const tmpDir = tempCacheDir(cacheRoot, name, version);
  try {
    fs.mkdirSync(cacheRoot, { recursive: true });
    fs.mkdirSync(tmpDir, { recursive: true });

    extractTgz(bytes, tmpDir);

    // Rename into final location atomically.
    fs.renameSync(tmpDir, dest);
  } catch {
    // Remove the temp dir so no partial state is left.
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup; ignore secondary errors.
    }
    return null;
  }

  // Classify fidelity from the extracted source.
  const result = resolveDepSource({ name, version, dir: dest });
  return { dir: dest, fidelity: result.fidelity, entryFile: result.entryFile };
}
