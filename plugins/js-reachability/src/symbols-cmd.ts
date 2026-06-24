/**
 * --extract-symbols subcommand.
 *
 * Reads a JSON payload from STDIN:
 *   { "patch": string, "files": [{ "path": string, "content": string }] }
 *
 * Path contract
 * -------------
 * `patch` must be a standard unified diff.  `parseUnifiedDiff` strips the
 * git "a/"/"b/" prefix, yielding repo-relative paths like `src/utils.ts`.
 * Every entry in `files[].path` MUST use that same repo-relative form
 * (e.g. `src/utils.ts`, not `a/src/utils.ts` or an absolute path).
 * A mismatch causes the changed file to be dropped — no symbols are extracted
 * for it and a diagnostic is written to STDERR (see below).  The subprocess
 * exits 0 and writes the (possibly empty) symbol array to STDOUT regardless.
 *
 * Runs parseUnifiedDiff on the patch, hydrates each ChangedFile's newContent
 * from the supplied files array (exact path match), drops files with no
 * matching content, then calls extractVulnerableSymbols.
 *
 * Writes the resulting VulnerableSymbol[] as JSON to STDOUT.
 * When one or more changed files from the diff have no matching supplied
 * content, a diagnostic is written to STDERR so path-convention mismatches
 * are observable rather than silent false-negatives.
 * Never throws — malformed input → emit [] and exit 0.
 */

import {
  parseUnifiedDiff,
  extractVulnerableSymbols,
  type VulnerableSymbol,
} from "./symbols/index.js";

/** Shape of the JSON object read from STDIN. */
interface ExtractRequest {
  patch: string;
  files: Array<{ path: string; content: string }>;
}

/**
 * Core logic: parse the patch, hydrate content, extract symbols.
 * Returns [] on any input problem rather than throwing.
 *
 * When changed files from the diff have no matching entry in `req.files`,
 * a diagnostic is written to STDERR so path-convention mismatches are
 * observable rather than silent false-negatives.  The function still returns
 * whatever symbols it can extract from the matched files and exits cleanly.
 *
 * The optional `stderrWrite` parameter overrides the stderr sink — useful in
 * tests to capture output without forking a subprocess.
 */
export async function extractSymbols(
  req: Partial<ExtractRequest>,
  stderrWrite: (msg: string) => void = (msg) => process.stderr.write(msg)
): Promise<VulnerableSymbol[]> {
  try {
    const patch = req.patch ?? "";
    const fileList = req.files ?? [];

    // Build a lookup from path → content for O(1) hydration.
    const contentMap = new Map<string, string>();
    for (const f of fileList) {
      if (f && typeof f.path === "string" && typeof f.content === "string") {
        contentMap.set(f.path, f.content);
      }
    }

    // Parse the diff to get changed-line metadata (newContent is "" at this point).
    const changedFiles = parseUnifiedDiff(patch);

    // Hydrate newContent from the supplied files.  Drop any file whose path
    // has no matching entry — the extractor requires real content to parse.
    const dropped: string[] = [];
    const hydrated = changedFiles
      .map((cf) => {
        const content = contentMap.get(cf.path);
        if (content === undefined) {
          dropped.push(cf.path);
          return null;
        }
        return { ...cf, newContent: content };
      })
      .filter((cf): cf is NonNullable<typeof cf> => cf !== null);

    // Emit a diagnostic so path-convention mismatches are not silent.
    if (dropped.length > 0) {
      stderrWrite(
        `extract-symbols: ${dropped.length} of ${changedFiles.length} changed files had no supplied content: ${dropped.join(", ")}\n`
      );
    }

    return extractVulnerableSymbols(hydrated);
  } catch {
    return [];
  }
}

/**
 * Parse a raw STDIN string, run extractSymbols, and return the JSON string
 * to write to STDOUT.  Never throws — malformed input → "[]".
 */
export async function runFromStdin(raw: string): Promise<string> {
  try {
    if (!raw || !raw.trim()) return "[]";
    const req: Partial<ExtractRequest> = JSON.parse(raw);
    const symbols = await extractSymbols(req);
    return JSON.stringify(symbols);
  } catch {
    return "[]";
  }
}

/** Entry point dispatched from main.ts when --extract-symbols is the first arg. */
export async function run(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  const output = await runFromStdin(raw);
  process.stdout.write(output + "\n");
}
