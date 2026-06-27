"""
dist_import_map.py — PyPI dist-name -> import-module(s) mapping.

Provenance cascade (highest to lowest confidence):
  1. importlib  — importlib.metadata on a live venv
  2. curated    — hand-maintained static map for well-known dist/import mismatches
  3. heuristic  — lowercase + hyphen-to-underscore normalisation

Hard invariants (matching plan phase-03-python-deep-dive.md):
  - ANY result tagged HEURISTIC MUST be treated as UNKNOWN by the caller,
    regardless of whether imports is empty or non-empty.  The heuristic
    mapping is a guess: even if the caller finds that a guessed module name is
    "not imported", it cannot emit NOT_REACHABLE — that conclusion is only safe
    when based on IMPORTLIB or CURATED provenance.
    Check `result.is_unknown` (or `result.provenance == Provenance.HEURISTIC`)
    and emit UNKNOWN for any "not imported" outcome on a HEURISTIC result.
  - Ambiguity (multiple possible import roots with no clear winner) ->
    result.ambiguous=True -> result.is_unknown=True.  The caller must not emit
    NOT_REACHABLE when is_unknown is True.
  - When a venv was available but importlib missed the dist (degraded to
    curated or heuristic), result.incomplete=True signals that the analysis
    graph may be partial.  Callers must treat incomplete=True as UNKNOWN for
    any NOT_REACHABLE decision.

Usage
-----
    from dist_import_map import resolve_dist_imports, resolve_many, Provenance

    # With venv active / detectable:
    r = resolve_dist_imports("PyYAML", venv_available=True)
    print(r.imports, r.provenance)   # ['yaml'], 'curated' or 'importlib'

    # Batch:
    results = resolve_many(["requests", "Pillow"], venv_available=True)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Provenance constants
# ---------------------------------------------------------------------------

class Provenance:
    """Tag values attached to every ResolvedImports result."""
    IMPORTLIB = "importlib"
    CURATED   = "curated"
    HEURISTIC = "heuristic"


# ---------------------------------------------------------------------------
# Curated static map
#
# Keys MUST be lowercase (canonical lookup; caller lowercases dist names).
# Values are lists of top-level import names.  A dist that installs exactly
# one import root is listed with a single-element list.
#
# Criteria for inclusion:
#   - The dist name differs from the import name in a non-obvious way.
#   - Commonly vulnerable packages (to keep false-negative rate low).
# ---------------------------------------------------------------------------

CURATED_MAP: Dict[str, List[str]] = {
    # Image / vision
    "pillow":                     ["PIL"],
    "opencv-python":              ["cv2"],
    "opencv-contrib-python":      ["cv2"],
    "opencv-python-headless":     ["cv2"],

    # Data / ML
    "scikit-learn":               ["sklearn"],
    "scikit-image":               ["skimage"],
    "beautifulsoup4":             ["bs4"],
    "pyyaml":                     ["yaml"],
    "protobuf":                   ["google.protobuf"],
    "mysqlclient":                ["MySQLdb"],

    # Auth / crypto
    "pyjwt":                      ["jwt"],
    "pyotp":                      ["pyotp"],
    "python-jose":                ["jose"],
    "cryptography":               ["cryptography"],
    "pyopenssl":                  ["OpenSSL"],
    "bcrypt":                     ["bcrypt"],

    # Dates / i18n
    "python-dateutil":            ["dateutil"],
    "babel":                      ["babel"],
    "pytz":                       ["pytz"],

    # Web / HTTP
    "python-multipart":           ["multipart"],
    "python-dotenv":              ["dotenv"],
    "dnspython":                  ["dns"],
    "urllib3":                    ["urllib3"],

    # DB / ORM
    "psycopg2":                   ["psycopg2"],
    "psycopg2-binary":            ["psycopg2"],
    "pymysql":                    ["pymysql"],
    "sqlalchemy":                 ["sqlalchemy"],

    # Serialisation
    "msgpack-python":             ["msgpack"],
    "msgpack":                    ["msgpack"],

    # Async / networking
    "websockets":                 ["websockets"],
    "aiohttp":                    ["aiohttp"],

    # Testing (still important for dev_only detection)
    "pytest":                     ["pytest"],
    "pytest-asyncio":             ["pytest_asyncio"],
    "factory-boy":                ["factory"],

    # Misc
    "python-magic":               ["magic"],
    "python-slugify":             ["slugify"],
    "click":                      ["click"],
    "rich":                       ["rich"],
    "tqdm":                       ["tqdm"],
    "attrs":                      ["attr", "attrs"],
    "six":                        ["six"],
}


# ---------------------------------------------------------------------------
# Internal importlib shim (thin wrapper so tests can patch it cleanly)
# ---------------------------------------------------------------------------

def _importlib_distribution(dist_name: str):
    """Thin wrapper around importlib.metadata.distribution for testability."""
    from importlib.metadata import distribution  # type: ignore[import]
    return distribution(dist_name)


def _heuristic_imports(dist_name: str) -> List[str]:
    """
    Derive a plausible import name from a dist name with NO external info.

    Algorithm:
      1. Lowercase the name.
      2. Replace hyphens and dots with underscores.
      3. Return as a single-element list.

    This is a guess.  The caller MUST tag the result as HEURISTIC and treat
    any 'not imported' outcome as UNKNOWN rather than NOT_REACHABLE.
    """
    normalised = re.sub(r"[-.]", "_", dist_name.lower())
    return [normalised] if normalised else []


# ---------------------------------------------------------------------------
# RECORD parser helpers
# ---------------------------------------------------------------------------

_DIST_INFO_RE = re.compile(r"\.dist-info[/\\]")
_DATA_RE      = re.compile(r"\.data[/\\]")


def _roots_from_record(record_text: str) -> List[str]:
    """
    Extract top-level import roots from a dist's RECORD file.

    RECORD format: path,hash,size  (CSV, path relative to site-packages).
    We collect the first path component, filter out:
      - .dist-info dirs
      - .data dirs  (install-time data, not importable)
      - bare filenames (no slash) that end in .py  (e.g. single-file modules)
    """
    roots: set = set()
    for line in record_text.splitlines():
        line = line.strip()
        if not line:
            continue
        path = line.split(",")[0]
        # Skip dist-info / data directories
        if _DIST_INFO_RE.search(path) or _DATA_RE.search(path):
            continue
        if "/" in path or "\\" in path:
            # Take the first component
            root = re.split(r"[/\\]", path)[0]
        else:
            # Single-file module — strip .py suffix
            if path.endswith(".py"):
                root = path[:-3]
            else:
                continue  # compiled extension or other — skip
        if root:
            roots.add(root)
    return sorted(roots)


# ---------------------------------------------------------------------------
# Core dist-to-imports query (importlib path)
# ---------------------------------------------------------------------------

def dist_to_imports(dist_name: str) -> List[str]:
    """
    Query importlib.metadata for the top-level import names of *dist_name*.

    Returns an empty list if the distribution is not found in the current
    (or active) environment.  Callers should then fall through to curated/
    heuristic.

    Priority inside importlib:
      1. top_level.txt  (explicit list; most reliable)
      2. RECORD         (infer from installed paths)
    """
    try:
        dist = _importlib_distribution(dist_name)
    except Exception:
        return []

    # 1. top_level.txt
    try:
        txt = dist.read_text("top_level.txt")
        if txt:
            names = [ln.strip() for ln in txt.splitlines() if ln.strip()]
            if names:
                return names
    except Exception:
        pass

    # 2. RECORD fallback
    try:
        record = dist.read_text("RECORD")
        if record:
            roots = _roots_from_record(record)
            if roots:
                return roots
    except Exception:
        pass

    return []


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ResolvedImports:
    """
    The result of mapping a single dist name to its importable module names.

    Fields
    ------
    dist_name   : original (un-normalised) dist name
    imports     : list of top-level import names (may be empty; see is_unknown)
    provenance  : one of Provenance.{IMPORTLIB,CURATED,HEURISTIC}
    ambiguous   : True when the mapping is uncertain because multiple equally-
                  plausible names exist (caller must not emit NOT_REACHABLE)

    Derived property
    ----------------
    is_unknown  : True when this result MUST NOT be used to prove NOT_REACHABLE.
                  True iff:
                    - provenance is HEURISTIC (any heuristic result, regardless
                      of whether imports is empty or non-empty), OR
                    - ambiguous is True, OR
                    - incomplete is True
    incomplete  : True when a venv was available but importlib failed to find
                  this dist, causing silent degradation to curated/heuristic.
                  Callers must treat incomplete=True as a partial-graph signal
                  and emit UNKNOWN for any NOT_REACHABLE decision.
    """
    dist_name  : str
    imports    : List[str]
    provenance : str
    ambiguous  : bool = False
    incomplete : bool = False

    @property
    def is_unknown(self) -> bool:
        if self.ambiguous:
            return True
        if self.provenance == Provenance.HEURISTIC:
            # ALL heuristic results are UNKNOWN: the mapping is a guess and
            # cannot safely prove NOT_REACHABLE even when imports is non-empty.
            return True
        if self.incomplete:
            return True
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def resolve_dist_imports(
    dist_name: str,
    *,
    venv_available: bool,
) -> ResolvedImports:
    """
    Resolve *dist_name* -> list of top-level import names.

    Provenance cascade
    ------------------
    1. If *venv_available* is True, try importlib.metadata first.
       On success (non-empty list) -> Provenance.IMPORTLIB.
       Multiple top-level names -> ambiguous=True (cannot safely select one
       for a NOT_REACHABLE claim without knowing which the advisory targets).

    2. Check CURATED_MAP (case-insensitive on the dist name).
       -> Provenance.CURATED.

    3. Fall back to the lowercase+hyphen-to-underscore heuristic.
       -> Provenance.HEURISTIC.
       Callers MUST treat any "not imported" conclusion from a HEURISTIC
       result as UNKNOWN, never NOT_REACHABLE.

    Parameters
    ----------
    dist_name       : PyPI distribution name (any casing)
    venv_available  : True if a venv is active/detected for the target project
    """
    canonical = dist_name.lower()

    # Track whether importlib was available but failed to find this dist.
    # If so, any fallback (curated or heuristic) is an incomplete result.
    importlib_miss = False

    # --- 1. importlib ---
    if venv_available:
        il_imports = dist_to_imports(dist_name)
        if il_imports:
            # Multiple top-level names: expose all but mark ambiguous so the
            # caller knows it cannot safely claim NOT_REACHABLE.
            ambiguous = len(il_imports) > 1
            return ResolvedImports(
                dist_name=dist_name,
                imports=il_imports,
                provenance=Provenance.IMPORTLIB,
                ambiguous=ambiguous,
                incomplete=False,
            )
        # importlib was available but did not find the dist — degraded path.
        importlib_miss = True

    # --- 2. curated ---
    if canonical in CURATED_MAP:
        return ResolvedImports(
            dist_name=dist_name,
            imports=list(CURATED_MAP[canonical]),
            provenance=Provenance.CURATED,
            ambiguous=False,
            incomplete=importlib_miss,
        )

    # --- 3. heuristic ---
    h_imports = _heuristic_imports(dist_name)
    return ResolvedImports(
        dist_name=dist_name,
        imports=h_imports,
        provenance=Provenance.HEURISTIC,
        ambiguous=False,
        incomplete=importlib_miss,
    )


# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def resolve_many(
    dist_names: List[str],
    *,
    venv_available: bool,
) -> Dict[str, ResolvedImports]:
    """
    Resolve a list of dist names in one call.

    Returns a dict keyed by the original dist name (preserving casing).
    """
    return {
        name: resolve_dist_imports(name, venv_available=venv_available)
        for name in dist_names
    }


# ---------------------------------------------------------------------------
# CLI — useful for manual testing / integration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    names = sys.argv[1:] if len(sys.argv) > 1 else ["requests", "PyYAML", "Pillow"]
    venv = True  # assume venv if run directly

    results = resolve_many(names, venv_available=venv)
    output = [
        {
            "dist": r.dist_name,
            "imports": r.imports,
            "provenance": r.provenance,
            "ambiguous": r.ambiguous,
            "is_unknown": r.is_unknown,
        }
        for r in results.values()
    ]
    print(json.dumps(output, indent=2))
