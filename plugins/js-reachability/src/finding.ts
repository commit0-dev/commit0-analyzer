/**
 * Finding proto builder.
 *
 * Constructs Finding messages from query results. Enforces:
 *   - ReachabilityPath present only for SYMBOL_REACHABLE.
 *   - properties["algorithm"] = "conservative-flow" always set.
 *   - properties["language"] derived from file extension.
 *   - properties["phantom"] = "true" when the dep is undeclared.
 *   - properties["import_graph_verdict"] = the import-graph-only verdict
 *     string for Metric V1-JS (P6 comparison).
 *   - Findings sorted by stable key: advisory.id + module for determinism.
 */

import { Confidence, Ecosystem, Severity } from "./gen/anst/v1/plugin.js";
import type {
  Finding,
  Advisory,
  ReachabilityPath,
} from "./gen/anst/v1/plugin.js";
import type { QueryAdvisory } from "./reach/query.js";

// ── Public API ────────────────────────────────────────────────────────────────

export interface BuildFindingOptions {
  advisory: QueryAdvisory;
  confidence: Confidence;
  /** Workspace the finding was computed for. */
  workspace: string;
  /** The file that imports the vulnerable package (for language detection). */
  importingFile?: string;
  /** ReachabilityPath — required for SYMBOL_REACHABLE, undefined otherwise. */
  path?: ReachabilityPath;
  /** Whether the dep is phantom (undeclared in manifest). */
  phantom?: boolean;
  /**
   * Import-graph-only verdict (cheaper check without call-graph edges).
   * Exposed as a property for P6 Metric V1-JS comparison.
   */
  importGraphVerdict?: Confidence;
  /**
   * True when the package is reachable only from devDependencies, not from
   * any runtime dep. The Go gate uses this to mark the finding non-gating.
   */
  devOnly?: boolean;
}

/**
 * Build a single Finding proto value.
 * Path is stripped unless confidence === SYMBOL_REACHABLE.
 */
export function buildFinding(opts: BuildFindingOptions): Finding {
  const {
    advisory,
    confidence,
    workspace,
    importingFile,
    phantom,
    importGraphVerdict,
    devOnly,
  } = opts;

  // Path only for SYMBOL_REACHABLE
  const path =
    confidence === Confidence.CONFIDENCE_SYMBOL_REACHABLE
      ? opts.path
      : undefined;

  const language = detectLanguage(importingFile);

  const properties: Record<string, string> = {
    algorithm: "conservative-flow",
    language,
    workspace,
  };

  if (phantom) {
    properties["phantom"] = "true";
  }

  if (devOnly) {
    properties["dev_only"] = "true";
  }

  // Metric V1-JS: expose import-graph-only verdict for P6 comparison
  const igv = importGraphVerdict ?? confidence;
  properties["import_graph_verdict"] = confidenceLabel(igv);

  return {
    advisory: {
      id: advisory.id,
      url: "",
      aliases: [],
    },
    module: advisory.module,
    confidence,
    severity: Severity.SEVERITY_UNSPECIFIED,
    path,
    properties,
    pillar: "sca",
    language,
    ecosystem: Ecosystem.ECOSYSTEM_NPM,
    incomplete: false,
  };
}

/**
 * Sort findings by stable key for determinism.
 * Key: advisory.id + "\x00" + module + "\x00" + workspace
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const ka = `${a.advisory?.id ?? ""}\x00${a.module}\x00${a.properties["workspace"] ?? ""}`;
    const kb = `${b.advisory?.id ?? ""}\x00${b.module}\x00${b.properties["workspace"] ?? ""}`;
    return ka.localeCompare(kb);
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function detectLanguage(file?: string): string {
  if (!file) return "js";
  const ext = file.split(".").pop() ?? "";
  if (ext === "ts" || ext === "tsx" || ext === "mts" || ext === "cts") {
    return "ts";
  }
  return "js";
}

function confidenceLabel(c: Confidence): string {
  switch (c) {
    case Confidence.CONFIDENCE_SYMBOL_REACHABLE:
      return "CONFIDENCE_SYMBOL_REACHABLE";
    case Confidence.CONFIDENCE_PACKAGE_REACHABLE:
      return "CONFIDENCE_PACKAGE_REACHABLE";
    case Confidence.CONFIDENCE_NOT_REACHABLE:
      return "CONFIDENCE_NOT_REACHABLE";
    default:
      return "CONFIDENCE_UNKNOWN";
  }
}
