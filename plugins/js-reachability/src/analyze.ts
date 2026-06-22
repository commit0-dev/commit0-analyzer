/**
 * --analyze mode: standalone reachability analysis shim.
 *
 * Reads an AnalyzeRequest JSON from the file path given as the next CLI
 * argument (or from stdin when the argument is "-"), runs the engine, and
 * writes a Finding[] JSON array to stdout.  No gRPC, no host required.
 *
 * Usage:
 *   dist/anst-js-reachability --analyze <request.json>
 *   dist/anst-js-reachability --analyze -   # reads stdin
 *
 * Determinism: two runs with identical input produce byte-identical output.
 */

import fs from "node:fs";
import { analyze } from "./engine/analyze.js";
import { Advisory, AnalyzeRequest, Finding } from "./gen/anst/v1/plugin.js";

export async function run(): Promise<void> {
  const arg = process.argv[3]; // argv[2] is "--analyze"

  let raw: string;
  if (!arg || arg === "-") {
    raw = fs.readFileSync("/dev/stdin", "utf8");
  } else {
    if (!fs.existsSync(arg)) {
      process.stderr.write(`--analyze: file not found: ${arg}\n`);
      process.exit(1);
    }
    raw = fs.readFileSync(arg, "utf8");
  }

  let req: AnalyzeRequest;
  try {
    req = AnalyzeRequest.fromJSON(JSON.parse(raw));
  } catch (err) {
    process.stderr.write(`--analyze: failed to parse request JSON: ${err}\n`);
    process.exit(1);
  }

  if (!req.moduleRoot) {
    process.stderr.write("--analyze: request must include moduleRoot\n");
    process.exit(1);
  }

  let findings: Finding[];
  try {
    findings = await analyze({
      moduleRoot: req.moduleRoot,
      entrypoints: req.entrypoints,
      advisories: req.advisories,
    });
  } catch (err) {
    process.stderr.write(`--analyze: engine error: ${err}\n`);
    process.exit(1);
  }

  // Write deterministic JSON: sorted findings, stable property key order.
  const output = findings.map((f) => Finding.toJSON(f));
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
}
