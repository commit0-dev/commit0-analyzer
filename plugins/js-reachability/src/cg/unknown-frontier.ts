/**
 * UNKNOWN frontier collector for the call graph.
 *
 * Every place where static analysis cannot determine the callee or the
 * import target emits one of these markers. They are consulted by the
 * reachability query to decide whether UNKNOWN (not NOT_REACHABLE) is the
 * correct verdict when no concrete path exists.
 *
 * Invariant: unknown ≠ safe. A reachable UNKNOWN frontier that is the only
 * candidate path to a vulnerable package must yield CONFIDENCE_UNKNOWN, not
 * CONFIDENCE_NOT_REACHABLE.
 */

import type { UnknownMarker, UnknownReason } from "../engine/graph.js";

export type { UnknownMarker, UnknownReason };

/** Build an UnknownMarker value. */
export function makeUnknownMarker(
  reason: UnknownReason,
  detail: string,
  fromFile: string,
  line: number,
  column: number,
  couldReach?: string[]
): UnknownMarker {
  const marker: UnknownMarker = { reason, detail, fromFile, line, column };
  if (couldReach && couldReach.length > 0) {
    marker.couldReach = couldReach;
  }
  return marker;
}
