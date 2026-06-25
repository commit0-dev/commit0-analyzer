/**
 * Platform matching for npm/node os/cpu constraint arrays.
 *
 * npm uses the same token set as Node's `process.platform` and `process.arch`:
 *   os  tokens: "darwin", "linux", "win32", ...
 *   cpu tokens: "x64", "arm64", "ia32", ...
 *
 * Each array entry may be prefixed with "!" to negate (exclude) the token.
 * An empty array or absent field means "any" — no constraint.
 */

/**
 * Returns true when a platform constraint array matches the given value.
 *
 * Rules (mirrors npm's own algorithm):
 *   - Empty / absent → always matches (no constraint).
 *   - If ANY entry is a bare (non-negated) string, the array is an allowlist:
 *     the value must appear in that positive set.
 *   - If ALL entries are negated ("!token"), the array is a denylist:
 *     the value must NOT appear in the negated set.
 *   - Mixed (positive + negative) — positive entries form the allowlist AND
 *     the value must not match any negated entry.
 */
function matchesConstraint(value: string, constraints: string[]): boolean {
  if (!constraints || constraints.length === 0) return true;

  const positive = constraints.filter((c) => !c.startsWith("!"));
  const negative = constraints
    .filter((c) => c.startsWith("!"))
    .map((c) => c.slice(1));

  // Denied explicitly
  if (negative.includes(value)) return false;

  // No positive allowlist → value is allowed unless denied above
  if (positive.length === 0) return true;

  // Positive allowlist must include value
  return positive.includes(value);
}

/**
 * Returns true when the package is EXCLUDED from the current host platform.
 *
 * A package is platform-excluded when its `os` constraint does NOT match
 * `process.platform` OR its `cpu` constraint does NOT match `process.arch`.
 *
 * If both constraints are absent/empty, the package runs everywhere → not excluded.
 */
export function isPlatformExcluded(
  os: string[] | undefined,
  cpu: string[] | undefined,
  platform: string = process.platform,
  arch: string = process.arch
): boolean {
  const osOk = matchesConstraint(platform, os ?? []);
  const cpuOk = matchesConstraint(arch, cpu ?? []);
  return !osOk || !cpuOk;
}
