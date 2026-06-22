/**
 * Resolves a package.json "exports" or "imports" map entry to a concrete
 * file path, given a set of active conditions.
 *
 * Spec references:
 *   https://nodejs.org/api/packages.html#exports
 *   https://nodejs.org/api/packages.html#subpath-patterns
 *
 * Invariants:
 *   - Unknown condition with no "default" → return null (caller emits UNKNOWN).
 *   - Subpath patterns ("./features/*") are resolved by substituting the
 *     pattern key's "*" with the matched suffix.
 *   - Result paths are relative to the package root; caller makes them absolute.
 *   - Never throws — missing/null map values yield null.
 */

/** A raw exports/imports map value as it appears in package.json. */
export type ExportsMapValue =
  | string
  | null
  | ExportsConditionMap
  | (string | ExportsConditionMap)[];

/** A conditions object, e.g. { "import": "./esm.js", "require": "./cjs.js" }. */
export interface ExportsConditionMap {
  [condition: string]: ExportsMapValue;
}

/**
 * Resolve a subpath (e.g. ".", "./utils", "./features/auth") against an
 * exports map from package.json, honoring the active conditions in priority
 * order.
 *
 * @param exportsMap  The value of package.json "exports".
 * @param subpath     The subpath to resolve ("." for the package root entry).
 * @param conditions  Ordered list of active conditions, highest priority first.
 *                    Typically ["import","default"] or ["require","default"].
 * @returns Relative file path within the package, or null if not resolvable.
 */
export function resolveExportsMap(
  exportsMap: ExportsMapValue,
  subpath: string,
  conditions: string[]
): string | null {
  // Shorthand: "exports": "./index.js" — only valid for the root entry "."
  if (typeof exportsMap === "string") {
    if (subpath === ".") return exportsMap;
    return null;
  }

  if (exportsMap === null || exportsMap === undefined) return null;

  if (Array.isArray(exportsMap)) {
    // Array of alternatives — try each in order
    for (const alt of exportsMap) {
      const resolved = resolveExportsMap(alt, subpath, conditions);
      if (resolved !== null) return resolved;
    }
    return null;
  }

  // Object shape: may be a subpath map OR a conditions map.
  // Distinguish by whether the first key starts with "." (subpath) or not.
  const keys = Object.keys(exportsMap as ExportsConditionMap);
  if (keys.length === 0) return null;

  const firstKey = keys[0];

  if (firstKey.startsWith(".")) {
    // Subpath map: { "./utils": ..., "./features/*": ... }
    return resolveSubpathMap(exportsMap as ExportsConditionMap, subpath, conditions);
  }

  // Conditions map: { "import": ..., "require": ..., "default": ... }
  // Only valid when resolving the root entry or when called recursively.
  return resolveConditionMap(exportsMap as ExportsConditionMap, conditions);
}

/**
 * Resolve a subpath within a subpath map, supporting exact matches and
 * wildcard/pattern matches (e.g. "./features/*").
 */
function resolveSubpathMap(
  map: ExportsConditionMap,
  subpath: string,
  conditions: string[]
): string | null {
  // 1. Exact match
  if (Object.prototype.hasOwnProperty.call(map, subpath)) {
    return resolveConditionOrValue(map[subpath], conditions);
  }

  // 2. Pattern match: look for a key containing "*"
  // Iterate in insertion order (deterministic for committed package.json files).
  for (const key of Object.keys(map)) {
    if (!key.includes("*")) continue;
    const patternMatch = matchSubpathPattern(key, subpath);
    if (patternMatch !== null) {
      const valueTemplate = resolveConditionOrValue(map[key], conditions);
      if (valueTemplate === null) return null;
      // Replace "*" in the resolved value with the matched portion
      return valueTemplate.replace(/\*/g, patternMatch);
    }
  }

  return null;
}

/**
 * Returns the "*" substitution string if `subpath` matches the pattern key,
 * or null if it does not match.
 *
 * Example: key="./features/*", subpath="./features/auth" → "auth"
 */
function matchSubpathPattern(key: string, subpath: string): string | null {
  const starIdx = key.indexOf("*");
  if (starIdx === -1) return null;

  const prefix = key.slice(0, starIdx);
  const suffix = key.slice(starIdx + 1);

  if (!subpath.startsWith(prefix)) return null;
  if (suffix && !subpath.endsWith(suffix)) return null;

  const matched = subpath.slice(
    prefix.length,
    suffix ? subpath.length - suffix.length : undefined
  );
  // Disallow path traversal in matched segment (security invariant)
  if (matched.includes("..")) return null;
  return matched;
}

/**
 * Resolve a value that may be either a conditions map or a leaf string.
 */
function resolveConditionOrValue(
  value: ExportsMapValue,
  conditions: string[]
): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const alt of value) {
      const r = resolveConditionOrValue(alt, conditions);
      if (r !== null) return r;
    }
    return null;
  }
  // Object → conditions map
  return resolveConditionMap(value as ExportsConditionMap, conditions);
}

/**
 * Walk a conditions object in the order of `conditions`, trying each
 * active condition. Falls back to "default" if present and no condition matched.
 */
function resolveConditionMap(
  map: ExportsConditionMap,
  conditions: string[]
): string | null {
  for (const cond of conditions) {
    if (Object.prototype.hasOwnProperty.call(map, cond)) {
      const r = resolveConditionOrValue(map[cond], conditions);
      if (r !== null) return r;
    }
  }
  // Explicit "default" fallback (only if not already in conditions list)
  if (
    !conditions.includes("default") &&
    Object.prototype.hasOwnProperty.call(map, "default")
  ) {
    return resolveConditionOrValue(map["default"], conditions);
  }
  return null;
}

/**
 * Extract the package name and subpath from an import specifier.
 *
 * Examples:
 *   "lodash"            → { name: "lodash", subpath: "." }
 *   "lodash/fp"         → { name: "lodash", subpath: "./fp" }
 *   "@scope/pkg"        → { name: "@scope/pkg", subpath: "." }
 *   "@scope/pkg/utils"  → { name: "@scope/pkg", subpath: "./utils" }
 */
export function parsePackageSpecifier(specifier: string): {
  name: string;
  subpath: string;
} {
  if (specifier.startsWith("@")) {
    // Scoped: "@scope/name" or "@scope/name/sub/path"
    const slashAfterScope = specifier.indexOf("/", 1);
    if (slashAfterScope === -1) {
      return { name: specifier, subpath: "." };
    }
    const secondSlash = specifier.indexOf("/", slashAfterScope + 1);
    if (secondSlash === -1) {
      return { name: specifier, subpath: "." };
    }
    return {
      name: specifier.slice(0, secondSlash),
      subpath: "." + specifier.slice(secondSlash),
    };
  }

  const slash = specifier.indexOf("/");
  if (slash === -1) {
    return { name: specifier, subpath: "." };
  }
  return {
    name: specifier.slice(0, slash),
    subpath: "." + specifier.slice(slash),
  };
}
