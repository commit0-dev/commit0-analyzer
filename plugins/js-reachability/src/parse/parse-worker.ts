/**
 * Isolated parser worker — runs as a child process.
 *
 * Reads newline-delimited JSON requests from stdin:
 *   { "id": number, "file": string }
 *
 * For each request, applies the same bundle/minified guard thresholds as the
 * call-graph builder (MAX_PARSE_BYTES, MAX_LINE_BYTES) before calling parseModule.
 * A guarded file returns { kind: "unknown", reason: "skipped: bundle/minified" }
 * without feeding dangerous content to the native oxc parser.
 *
 * Writes one newline-delimited JSON response per request to stdout:
 *   { "id": number, "result": ParsedModule }
 *
 * Nothing else is written to stdout — diagnostics go to stderr only.
 * Processes requests sequentially; the parent relies on this for crash isolation
 * (at most one file is in flight at a time, so a crash affects exactly one file).
 *
 * Special sentinel: a file path of "__CRASH__" causes process.exit(1) so tests
 * can trigger deterministic worker crashes.
 * A file path of "__HANG__" sleeps forever so tests can trigger the timeout path.
 */

import fs from "node:fs";
import readline from "node:readline";
import { parseModule } from "./index.js";
import { MAX_PARSE_BYTES, MAX_LINE_BYTES, hasLineLongerThan } from "./parse-limits.js";
import type { ParsedModule } from "./types.js";

interface WorkerRequest {
  id: number;
  file: string;
}

interface WorkerResponse {
  id: number;
  result: ParsedModule;
}

async function processRequest(req: WorkerRequest): Promise<WorkerResponse> {
  const { id, file } = req;

  // Crash sentinel for testing
  if (file === "__CRASH__") {
    process.stderr.write(`[parse-worker] crash sentinel received\n`);
    process.exit(1);
  }

  // Hang sentinel for testing (sleep forever to trigger timeout in parent)
  if (file === "__HANG__") {
    process.stderr.write(`[parse-worker] hang sentinel received\n`);
    await new Promise<void>(() => {
      // Never resolves — parent will kill the process via timeout
    });
    // TypeScript: unreachable, but satisfies return type
    return { id, result: { kind: "unknown", file, reason: "hang sentinel" } };
  }

  // Apply bundle/minified guard before calling the native oxc parser.
  // A stat failure is non-fatal: fall through to parseModule which handles it.
  let fileSize = 0;
  try {
    fileSize = fs.statSync(file).size;
  } catch {
    // stat failure — let parseModule surface the read error
  }

  if (fileSize > MAX_PARSE_BYTES) {
    const result: ParsedModule = {
      kind: "unknown",
      file,
      reason: `skipped: bundle/minified (${fileSize} bytes exceeds ${MAX_PARSE_BYTES})`,
    };
    return { id, result };
  }

  if (fileSize > 0) {
    let source: string | undefined;
    try {
      source = fs.readFileSync(file, "utf8");
    } catch {
      // read failure — let parseModule handle it
    }
    if (source !== undefined && hasLineLongerThan(source, MAX_LINE_BYTES)) {
      const result: ParsedModule = {
        kind: "unknown",
        file,
        reason: `skipped: bundle/minified (line exceeds ${MAX_LINE_BYTES} bytes)`,
      };
      return { id, result };
    }
  }

  const result = await parseModule(file);
  return { id, result };
}

async function main(): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let req: WorkerRequest;
    try {
      req = JSON.parse(trimmed) as WorkerRequest;
    } catch (err) {
      process.stderr.write(`[parse-worker] invalid JSON request: ${err}\n`);
      continue;
    }

    try {
      const response = await processRequest(req);
      process.stdout.write(JSON.stringify(response) + "\n");
    } catch (err) {
      // Unexpected error in processRequest (parseModule never throws, but guard anyway)
      process.stderr.write(`[parse-worker] error processing request ${req.id}: ${err}\n`);
      const response: WorkerResponse = {
        id: req.id,
        result: { kind: "unknown", file: req.file, reason: `worker error: ${String(err)}` },
      };
      process.stdout.write(JSON.stringify(response) + "\n");
    }
  }
}

main().catch((err) => {
  process.stderr.write(`[parse-worker] fatal: ${err}\n`);
  process.exit(1);
});
