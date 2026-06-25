"""
confidence.py — confidence-tier decision logic for Python reachability.

Maps the call-graph outcome + advisory metadata + dist-import-map provenance
to one of the four confidence tiers defined in the plan:

    SYMBOL_REACHABLE > PACKAGE_REACHABLE > NOT_REACHABLE > UNKNOWN

Hard invariants (from plan phase-03-python-deep-dive.md Red-Team Corrections)
------------------------------------------------------------------------------
1. NOT_REACHABLE is ONLY emitted when:
   - The dist is absent from the call-graph import closure, AND
   - graph.can_claim_not_reachable() is True (no UNKNOWN frontier), AND
   - The dist-import mapping provenance is IMPORTLIB or CURATED (not HEURISTIC).

2. Any HEURISTIC dist-import mapping => result.is_unknown == True =>
   outcome is UNKNOWN, never NOT_REACHABLE.

3. UNKNOWN frontier (parse failure, dynamic construct, unresolvable import)
   sets graph.incomplete = True => NOT_REACHABLE is forbidden for the whole
   scan unless a per-dist complete-graph proof exists.

4. No-venv / manifest-only / heuristic dist miss => UNKNOWN + incomplete.

Only Python stdlib is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Confidence tiers
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    SYMBOL_REACHABLE  = "SYMBOL_REACHABLE"
    PACKAGE_REACHABLE = "PACKAGE_REACHABLE"
    NOT_REACHABLE     = "NOT_REACHABLE"
    UNKNOWN           = "UNKNOWN"


# ---------------------------------------------------------------------------
# Advisory metadata (minimal view needed for confidence decision)
# ---------------------------------------------------------------------------

@dataclass
class AdvisoryMeta:
    """
    Minimal advisory data needed to compute the confidence tier.

    Fields
    ------
    dist_name   : PyPI dist name (e.g. "celery", "requests")
    symbols     : vulnerable symbol names extracted from the advisory or
                  from fix-patch analysis (e.g. ["safe_decode",
                  "Encoder.encode"]).  Empty list means no symbol-level data.
    """
    dist_name: str
    symbols: List[str]


# ---------------------------------------------------------------------------
# ConfidenceDecision
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceDecision:
    """
    Output of decide_confidence().

    Fields
    ------
    confidence : the assigned Confidence tier
    incomplete : True when the analysis graph is partial and NOT_REACHABLE
                 cannot be claimed (propagated from the call graph)
    reason     : human-readable explanation (for telemetry / debug)
    dev_only   : True when the dist is only imported from test files
    """
    confidence: Confidence
    incomplete: bool = False
    reason: str = ""
    dev_only: bool = False


# ---------------------------------------------------------------------------
# Compiled-extension detection
# ---------------------------------------------------------------------------

def _dist_has_source(dist_name: str, site_packages: Optional[str]) -> bool:
    """
    Return True if the dist appears to have Python source available
    (i.e. is not a compiled-only C extension).

    Heuristic: check whether site-packages/<dist_name>/__init__.py exists
    (or a top-level .py).  If not, assume compiled (.so / .pyd only).
    """
    if not site_packages:
        return False
    import os
    # Try the dist name directly (lowercase)
    for name in (dist_name, dist_name.lower(), dist_name.replace("-", "_")):
        pkg_init = os.path.join(site_packages, name, "__init__.py")
        pkg_py   = os.path.join(site_packages, name + ".py")
        if os.path.isfile(pkg_init) or os.path.isfile(pkg_py):
            return True
    return False


# ---------------------------------------------------------------------------
# Core decision function
# ---------------------------------------------------------------------------

def decide_confidence(
    advisory: AdvisoryMeta,
    graph: Any,                            # CallGraph from cg/call_graph.py
    resolved_import: Any,                  # ResolvedImports from dist_import_map
    site_packages: Optional[str] = None,
    call_path: Optional[List[str]] = None, # concrete call chain if available
    is_dev_only: bool = False,
) -> ConfidenceDecision:
    """
    Determine the confidence tier for one (advisory, package) pair.

    Parameters
    ----------
    advisory        : the advisory being evaluated
    graph           : CallGraph built by CallGraphBuilder
    resolved_import : ResolvedImports from dist_import_map.resolve_dist_imports()
    site_packages   : optional path to site-packages for source detection
    call_path       : optional concrete call chain (from_func -> ... -> symbol);
                      non-empty => SYMBOL_REACHABLE candidate
    is_dev_only     : True when the dist is imported only in test files

    Returns
    -------
    ConfidenceDecision
    """
    dist = advisory.dist_name
    incomplete = graph.incomplete

    # ------------------------------------------------------------------
    # Guard: HEURISTIC or ambiguous dist-import mapping => UNKNOWN
    # ------------------------------------------------------------------
    if resolved_import.is_unknown:
        return ConfidenceDecision(
            confidence=Confidence.UNKNOWN,
            incomplete=True,
            reason=(
                f"dist-import mapping for '{dist}' is "
                f"{resolved_import.provenance}/ambiguous — cannot prove reachability"
            ),
            dev_only=is_dev_only,
        )

    # ------------------------------------------------------------------
    # Is the dist present in the import closure?
    # ------------------------------------------------------------------
    dist_imported = graph.imports_dist(dist)

    if not dist_imported:
        # Dist not seen in the traversal closure.
        if graph.can_claim_not_reachable():
            # Complete graph + curated/importlib mapping => safe NOT_REACHABLE
            return ConfidenceDecision(
                confidence=Confidence.NOT_REACHABLE,
                incomplete=False,
                reason=f"'{dist}' not in import closure; graph complete",
                dev_only=is_dev_only,
            )
        else:
            # Incomplete graph => cannot claim NOT_REACHABLE
            return ConfidenceDecision(
                confidence=Confidence.UNKNOWN,
                incomplete=True,
                reason=(
                    f"'{dist}' not seen in partial import closure; "
                    "graph has UNKNOWN frontier — cannot emit NOT_REACHABLE"
                ),
                dev_only=is_dev_only,
            )

    # ------------------------------------------------------------------
    # Dist IS imported — determine symbol vs package level
    # ------------------------------------------------------------------

    # SYMBOL_REACHABLE: concrete call path provided + advisory has symbols.
    # Dynamic dispatch markers (eval/getattr/__getattr__) degrade SYMBOL-level
    # confidence only — they do NOT affect package-level PACKAGE_REACHABLE.
    if call_path and advisory.symbols:
        # If there are dynamic dispatch constructs in the graph, we cannot
        # confirm the exact symbol path (dispatch may redirect calls).
        if _has_dynamic_path_to_dist(dist, graph):
            return ConfidenceDecision(
                confidence=Confidence.UNKNOWN,
                incomplete=True,
                reason=f"'{dist}' reachable but dynamic dispatch construct in graph — symbol path unconfirmed",
                dev_only=is_dev_only,
            )
        matched = _symbols_in_path(advisory.symbols, call_path)
        if matched:
            return ConfidenceDecision(
                confidence=Confidence.SYMBOL_REACHABLE,
                incomplete=incomplete,
                reason=f"call path reaches vulnerable symbol(s): {matched}",
                dev_only=is_dev_only,
            )

    # Compiled extension (no Python source) => PACKAGE_REACHABLE
    has_source = _dist_has_source(dist, site_packages)
    if not has_source and site_packages:
        return ConfidenceDecision(
            confidence=Confidence.PACKAGE_REACHABLE,
            incomplete=incomplete,
            reason=f"'{dist}' is imported but appears to be a compiled extension (no .py source)",
            dev_only=is_dev_only,
        )

    # Advisory has no symbol-level data => PACKAGE_REACHABLE
    if not advisory.symbols:
        return ConfidenceDecision(
            confidence=Confidence.PACKAGE_REACHABLE,
            incomplete=incomplete,
            reason=f"'{dist}' is imported; no symbol-level advisory data available",
            dev_only=is_dev_only,
        )

    # Advisory has symbols but we have no confirmed call path => UNKNOWN
    # (We cannot claim the symbol is reachable without a call path.)
    if not call_path:
        return ConfidenceDecision(
            confidence=Confidence.UNKNOWN,
            incomplete=True,
            reason=(
                f"'{dist}' is imported and advisory names symbols {advisory.symbols!r} "
                "but no concrete call path was established"
            ),
            dev_only=is_dev_only,
        )

    # call_path present but none of the vulnerable symbols appear in it
    return ConfidenceDecision(
        confidence=Confidence.UNKNOWN,
        incomplete=incomplete,
        reason=(
            f"call path to '{dist}' exists but does not reach "
            f"vulnerable symbol(s) {advisory.symbols!r}"
        ),
        dev_only=is_dev_only,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_dynamic_path_to_dist(dist_name: str, graph: Any) -> bool:
    """
    Return True if any dynamic DISPATCH marker file exists anywhere in the graph.

    This is a whole-graph approximation, not a path-specific check: if ANY
    file in the visited set contains dynamic dispatch constructs (eval/exec/
    dynamic getattr/__getattr__) the function returns True regardless of whether
    those constructs are on a code path to *dist_name*.  This is intentionally
    over-conservative at the SYMBOL level (sound for symbol reachability) but
    these constructs do NOT affect package-level reachability.

    IMPORTANT: This function is used only for the symbol-tier confidence
    decision (whether to degrade a reachable dist to UNKNOWN for symbol
    analysis).  It must NOT be used to gate package-level NOT_REACHABLE —
    that is governed by graph.can_claim_not_reachable() / graph.incomplete,
    which is only set by unbounded dynamic imports and parse failures.
    """
    return bool(graph.dynamic_files)


def _symbols_in_path(symbols: List[str], call_path: List[str]) -> List[str]:
    """
    Return the subset of *symbols* that appear in *call_path*.

    Matching is suffix-based: "safe_decode" matches "requests.safe_decode"
    and "celery.kombu.utils.encoding.safe_decode".
    """
    matched: List[str] = []
    for sym in symbols:
        for node in call_path:
            if node == sym or node.endswith("." + sym):
                matched.append(sym)
                break
    return matched
