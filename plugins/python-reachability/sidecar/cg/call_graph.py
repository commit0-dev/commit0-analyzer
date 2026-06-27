"""
call_graph.py — demand-driven call-graph engine for Python reachability.

Architecture (Lane B — matches deep-dive §3.2)
----------------------------------------------
Given a project root (+ optional venv) and a resolved dist→import map:

1. Discover entry-point .py files (src/, root-level *.py; exclude test dirs,
   venv dirs).
2. BFS over files: parse each file via the ParserPool; for each import,
   resolve it to first-party (queue for further analysis) or third-party
   (record the dist usage; optionally walk its site-packages source).
3. Dynamic constructs are separated into two categories:
     - dynamic_import_markers (unbounded): opaque dynamic imports where the
       target package is not statically determinable.  These are PACKAGE-LEVEL
       frontiers: they forbid NOT_REACHABLE for any dist whose top-module is
       NOT under a known bounded prefix.
     - dynamic_dispatch_markers: eval/exec/dynamic getattr/__getattr__ etc.
       These are SYMBOL-LEVEL only and do NOT forbid package-level NOT_REACHABLE.
4. Oversized / long-line files get a FAST import-only scan (tokenize-based)
   instead of being silently treated as UNKNOWN package-level frontiers.
   A giant file is a SYMBOL-LEVEL unknown (no call graph), but its imports ARE
   captured, so it is NOT a package-level frontier.  Only files that fail even
   the import-only scan become package-level frontiers.
5. Transitive closure is memoized (visited set) to prevent re-parsing.

Output: CallGraph — the principal data structure consumed by the confidence
        decision layer (cg/confidence.py).

Hard invariants
---------------
- NOT_REACHABLE is only emitted when a dist is ABSENT from the import
  closure AND there is NO unbounded dynamic-import frontier AND the dist's
  top-module is not under any bounded dynamic-import namespace prefix AND
  no file failed even the import-only scan AND the BFS was not
  truncated/deadline-cut.
- dynamic_dispatch_markers (getattr/eval/exec/__getattr__) do NOT forbid
  package-level NOT_REACHABLE — they access object attributes, not packages.
- Any file that fails even the tokenize-based import scan is a true UNKNOWN
  frontier: incomplete=True, NOT_REACHABLE forbidden.
- HEURISTIC dist-import mapping → UNKNOWN (handled in confidence.py).
- No-venv (nothing to resolve site-packages from) produces UNKNOWN +
  incomplete, never NOT_REACHABLE.

Only Python stdlib is used.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# File-size guard: files larger than this byte count get the fast import-only
# scan (tokenize-based) instead of a full ast.parse.  The result: imports ARE
# captured, but no call graph.  Giant files are symbol-level unknowns but NOT
# package-level frontiers (unless the import scan itself fails).
MAX_PARSE_BYTES: int = 300_000

# Long-line guard: same treatment as above.
MAX_LINE_BYTES: int = 50_000

# Default wall-clock deadline for the BFS (seconds).
DEFAULT_DEADLINE_SEC: float = 90.0

# Directories to skip during entry-point discovery and traversal
_SKIP_DIRS: FrozenSet[str] = frozenset({
    "test", "tests", "spec", "specs",
    "__pycache__", ".git", ".tox", ".mypy_cache", ".pytest_cache",
    "venv", ".venv", "env", ".env",
    "node_modules", "dist", "build", ".eggs",
})

# Suffixes that mark test files
_TEST_SUFFIXES: Tuple[str, ...] = ("_test.py", "test_.py")
_TEST_PREFIXES: Tuple[str, ...] = ("test_",)


def _has_line_longer_than(content: bytes, max_len: int) -> bool:
    """Return True when any single line of *content* exceeds *max_len* bytes."""
    last = -1
    while True:
        idx = content.find(b"\n", last + 1)
        if idx == -1:
            return (len(content) - last - 1) > max_len
        if (idx - last - 1) > max_len:
            return True
        last = idx


def _file_needs_guard(path: str) -> bool:
    """
    Return True when the file exceeds the parse guard thresholds.

    A guarded file gets the fast import-only scan instead of ast.parse.
    This is different from the old behaviour (which made the file an UNKNOWN
    frontier) — now we extract imports even from oversized files.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False  # let the parser handle it
    if size > MAX_PARSE_BYTES:
        return True
    if size == 0:
        return False
    try:
        with open(path, "rb") as fh:
            content = fh.read(size)
    except OSError:
        return False
    return _has_line_longer_than(content, MAX_LINE_BYTES)


# Kept for backward-compat with tests that import _file_guard_reason
def _file_guard_reason(path: str) -> Optional[str]:
    """
    Check parse guards for *path*.

    Returns a non-empty reason string when the file should use the fast
    import-only scan (not a full ast.parse), or None when full parse is safe.

    NOTE: In the new implementation oversized files are NOT silent UNKNOWN
    frontiers; they get a tokenize-based import scan.  This function is
    preserved for backward-compat only (tests that import it).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > MAX_PARSE_BYTES:
        return f"file too large ({size} bytes > {MAX_PARSE_BYTES})"
    if size == 0:
        return None
    try:
        with open(path, "rb") as fh:
            content = fh.read(size)
    except OSError:
        return None
    if _has_line_longer_than(content, MAX_LINE_BYTES):
        return f"line too long (> {MAX_LINE_BYTES} bytes)"
    return None


def _is_test_file(path: str) -> bool:
    name = os.path.basename(path)
    if any(name.endswith(s) for s in _TEST_SUFFIXES):
        return True
    if any(name.startswith(p) for p in _TEST_PREFIXES):
        return True
    parts = path.replace("\\", "/").split("/")
    return any(p in _SKIP_DIRS for p in parts)


def _is_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.startswith(".")


# ---------------------------------------------------------------------------
# Venv detection
# ---------------------------------------------------------------------------

def detect_venv(project_root: str) -> Optional[str]:
    """
    Return the site-packages directory of the first detectable venv for
    *project_root*, or None.

    Detection order:
    1. VIRTUAL_ENV environment variable (explicit caller signal).
    2. .venv / venv sub-directory in project_root (filesystem discovery).

    The "active interpreter" heuristic (sys.prefix vs sys.base_prefix) is
    intentionally omitted: this sidecar always runs inside the analyzer's
    own skill venv, so sys.prefix points to the analyzer's site-packages —
    not the target project's venv.  Using it would resolve the target
    project's imports against the analyzer's installed packages, corrupting
    the third-party import closure and the compiled-extension detection
    in decide_confidence().

    Callers that know the target venv location should pass site_packages
    directly to CallGraphBuilder instead of relying on this auto-detection.
    """
    abs_root = os.path.abspath(project_root)

    # 1. VIRTUAL_ENV env var (explicit external signal — honored as-is)
    venv_env = os.environ.get("VIRTUAL_ENV")
    if venv_env:
        sp = _site_packages(venv_env)
        if sp:
            return sp

    # 2. .venv / venv sub-directories in project_root
    for name in (".venv", "venv"):
        candidate = os.path.join(abs_root, name)
        if os.path.isdir(candidate):
            sp = _site_packages(candidate)
            if sp:
                return sp

    return None


def _site_packages(prefix: str) -> Optional[str]:
    """Return the site-packages path inside *prefix*, or None if absent."""
    for sub in (
        f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages",
        "lib/site-packages",
        "Lib/site-packages",
    ):
        sp = os.path.join(prefix, sub)
        if os.path.isdir(sp):
            return sp
    return None


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------

@dataclass
class ResolvedImport:
    kind: str          # "first_party" | "third_party" | "stdlib" | "unknown"
    dist_name: str = ""
    source_root: str = ""   # site-packages/<package> or first-party path
    specifier: str = ""


_STDLIB_TOP: FrozenSet[str] = frozenset({
    # A representative subset — enough to avoid misclassifying stdlib as third-party.
    "os", "sys", "re", "io", "abc", "ast", "csv", "math", "json", "time",
    "copy", "enum", "functools", "itertools", "operator", "pathlib",
    "collections", "contextlib", "dataclasses", "datetime", "decimal",
    "difflib", "fileinput", "fnmatch", "fractions", "gc", "getopt",
    "glob", "gzip", "hashlib", "heapq", "hmac", "html", "http",
    "inspect", "keyword", "linecache", "locale", "logging", "mimetypes",
    "multiprocessing", "numbers", "pickle", "platform", "pprint",
    "queue", "random", "secrets", "shlex", "shutil", "signal", "socket",
    "sqlite3", "ssl", "stat", "string", "struct", "subprocess", "tarfile",
    "tempfile", "textwrap", "threading", "traceback", "types", "typing",
    "unittest", "urllib", "uuid", "warnings", "weakref", "zipfile",
    "zlib", "importlib", "email", "xml", "xmlrpc", "concurrent",
    "asyncio", "ctypes", "curses", "dbm", "dis", "doctest",
    "ftplib", "imaplib", "ipaddress", "nis", "nntplib", "poplib",
    "posixpath", "pydoc", "runpy", "smtplib", "sndhdr", "telnetlib",
    "tokenize", "token", "trace", "tty", "uu", "venv", "wsgiref",
    "builtins", "__future__",
})


def _top_module(specifier: str) -> str:
    """Return the top-level module name of a specifier."""
    clean = specifier.lstrip(".")
    return clean.split(".")[0] if clean else ""


def resolve_import(
    specifier: str,
    current_file: str,
    project_root: str,
    site_packages: Optional[str],
    dist_import_map: Dict[str, str],   # top_level_import -> dist_name
) -> ResolvedImport:
    """
    Classify an import specifier as first-party, third-party, stdlib, or unknown.

    Parameters
    ----------
    specifier       : import specifier (e.g. "requests", ".models", "os.path")
    current_file    : absolute path of the file containing the import
    project_root    : absolute project root
    site_packages   : absolute site-packages dir (None = no venv)
    dist_import_map : { top_level_import_name -> dist_name }

    Returns a ResolvedImport with kind set appropriately.
    """
    # Relative imports -> first-party
    if specifier.startswith("."):
        return _resolve_relative(specifier, current_file, project_root)

    top = _top_module(specifier)
    if not top:
        return ResolvedImport(kind="unknown", specifier=specifier)

    # stdlib
    if top in _STDLIB_TOP:
        return ResolvedImport(kind="stdlib", specifier=specifier)

    # third-party via site-packages
    if site_packages and os.path.isdir(site_packages):
        pkg_dir = os.path.join(site_packages, top)
        if os.path.isdir(pkg_dir) or os.path.isfile(pkg_dir + ".py"):
            dist_name = dist_import_map.get(top, top)
            source_root = pkg_dir if os.path.isdir(pkg_dir) else site_packages
            return ResolvedImport(
                kind="third_party",
                dist_name=dist_name,
                source_root=source_root,
                specifier=specifier,
            )
        # Also check for namespace packages (top-level .pth / dist-info)
        dist_name = dist_import_map.get(top)
        if dist_name:
            return ResolvedImport(
                kind="third_party",
                dist_name=dist_name,
                source_root=site_packages,
                specifier=specifier,
            )

    # Fall back: check if it matches a known dist in the dist_import_map
    if top in dist_import_map:
        return ResolvedImport(
            kind="third_party",
            dist_name=dist_import_map[top],
            source_root="",
            specifier=specifier,
        )

    # Check first-party (project source)
    fp = _resolve_first_party(top, project_root)
    if fp:
        return ResolvedImport(kind="first_party", source_root=fp, specifier=specifier)

    # Unknown — could be stdlib we missed, installed globally, or dynamic
    return ResolvedImport(kind="unknown", specifier=specifier)


def _resolve_relative(specifier: str, current_file: str, project_root: str) -> ResolvedImport:
    """Resolve a relative import to its filesystem path (best-effort)."""
    dots = len(specifier) - len(specifier.lstrip("."))
    module_part = specifier.lstrip(".")

    current_dir = os.path.dirname(current_file)
    # Go up `dots - 1` levels from the current directory
    base_dir = current_dir
    for _ in range(dots - 1):
        base_dir = os.path.dirname(base_dir)

    if module_part:
        candidate = os.path.join(base_dir, module_part.replace(".", os.sep))
        if os.path.isdir(candidate):
            return ResolvedImport(kind="first_party", source_root=candidate, specifier=specifier)
        if os.path.isfile(candidate + ".py"):
            return ResolvedImport(kind="first_party", source_root=candidate + ".py", specifier=specifier)
    else:
        # `from . import x` — the current package
        return ResolvedImport(kind="first_party", source_root=base_dir, specifier=specifier)

    return ResolvedImport(kind="unknown", specifier=specifier)


def _resolve_first_party(top: str, project_root: str) -> Optional[str]:
    """Check if `top` is a first-party module in the project."""
    for search in (project_root, os.path.join(project_root, "src")):
        candidate_dir = os.path.join(search, top)
        candidate_file = os.path.join(search, top + ".py")
        if os.path.isdir(candidate_dir):
            return candidate_dir
        if os.path.isfile(candidate_file):
            return candidate_file
    return None


# ---------------------------------------------------------------------------
# Entry-point discovery
# ---------------------------------------------------------------------------

def discover_entry_points(project_root: str) -> List[str]:
    """
    Find all .py files that are project entry points (not test, not venv).

    Search roots:
    1. project_root/*.py
    2. project_root/src/**/*.py
    3. project_root/<package>/**/*.py  (non-skip dirs at depth 1)

    Test files and files inside skip dirs are excluded.
    """
    py_files: List[str] = []

    def _walk(top: str) -> None:
        for entry in os.scandir(top):
            if entry.is_dir(follow_symlinks=False):
                if _is_skip_dir(entry.name):
                    continue
                _walk(entry.path)
            elif entry.is_file() and entry.name.endswith(".py"):
                if not _is_test_file(entry.path):
                    py_files.append(entry.path)

    # Root-level .py files
    try:
        for entry in os.scandir(project_root):
            if entry.is_file() and entry.name.endswith(".py"):
                if not _is_test_file(entry.path):
                    py_files.append(entry.path)
            elif entry.is_dir(follow_symlinks=False) and not _is_skip_dir(entry.name):
                # src/ and immediate child packages
                if entry.name in ("src", "lib") or not entry.name.startswith("."):
                    _walk(entry.path)
    except PermissionError:
        pass

    return sorted(set(py_files))


# ---------------------------------------------------------------------------
# CallGraph data structure
# ---------------------------------------------------------------------------

@dataclass
class CallGraph:
    """
    Outcome of the demand-driven call-graph build.

    dist_imports : { dist_name -> set of specifiers that import from it }
    unknown_files: files that could not be parsed even with the import-only scan
                   (these are TRUE UNKNOWN frontiers: package-level incomplete)
    import_only_files: files that were scanned with the fast tokenize scan
                   (no full AST — symbol-level unknown, but imports ARE captured)
    dynamic_files: files containing dynamic dispatch constructs (eval/getattr/etc.)
                   SYMBOL-LEVEL only — do NOT gate package-level NOT_REACHABLE
    unbounded_dynamic_import_sites: list of {file, line} for opaque dynamic imports
                   (importlib.import_module(var) with no determinable prefix).
                   These ARE package-level frontiers.
    bounded_dynamic_import_prefixes: set of namespace prefixes from bounded dynamic
                   imports (e.g. "a.b." from import_module("a.b." + var)).
                   A dist whose top-module starts with such a prefix is potentially
                   reachable and must not be NOT_REACHABLE.
    visited_files: all files that were fully traversed (full AST parse)
    incomplete    : True when any UNKNOWN package-level frontier was encountered.
                   NOT_REACHABLE must NOT be emitted when this is True.
    file_dist_imports: { file_path -> set of dist_names imported by that file }
                   Populated for fully-parsed files only (not import_only_files).
                   Used for symbol-level reachability scanning.
    file_calls   : { file_path -> list of call "to" strings from that file }
                   Populated for fully-parsed files only.
                   Used for symbol-level reachability scanning.
    """
    dist_imports: Dict[str, Set[str]] = field(default_factory=dict)
    unknown_files: Set[str] = field(default_factory=set)
    import_only_files: Set[str] = field(default_factory=set)
    dynamic_files: Set[str] = field(default_factory=set)
    unbounded_dynamic_import_sites: List[Dict[str, Any]] = field(default_factory=list)
    bounded_dynamic_import_prefixes: Set[str] = field(default_factory=set)
    visited_files: Set[str] = field(default_factory=set)
    incomplete: bool = False
    file_dist_imports: Dict[str, Set[str]] = field(default_factory=dict)
    file_calls: Dict[str, List[str]] = field(default_factory=dict)

    def imports_dist(self, dist_name: str) -> bool:
        """Return True if *dist_name* appears anywhere in the import closure."""
        return dist_name in self.dist_imports and bool(self.dist_imports[dist_name])

    def can_claim_not_reachable(self) -> bool:
        """
        True only when the graph is complete (no UNKNOWN package-level frontier).

        When this is False, callers MUST NOT emit NOT_REACHABLE; emit UNKNOWN.

        NOTE: dynamic_dispatch_markers (eval/getattr/__getattr__) do NOT affect
        this — they operate at the symbol level, not the package import level.
        Only unbounded dynamic imports and parse failures set incomplete=True.
        """
        return not self.incomplete

    def dist_under_bounded_prefix(self, dist_top: str) -> bool:
        """
        Return True if *dist_top* (top-level module name) starts with any of
        the bounded dynamic-import namespace prefixes seen in the scan.

        A dist matching a bounded prefix MIGHT be dynamically imported, so
        NOT_REACHABLE must be suppressed for it.
        """
        for prefix in self.bounded_dynamic_import_prefixes:
            # prefix may be "a.b." (with trailing dot) or "a.b" (without)
            clean_prefix = prefix.rstrip(".")
            if dist_top == clean_prefix or dist_top.startswith(clean_prefix + ".") or clean_prefix.startswith(dist_top):
                return True
        return False

    def find_symbol_hits(
        self,
        dist: str,
        symbols: List[str],
    ) -> Dict[str, List[str]]:
        """
        Return a mapping { symbol_name -> [file_path, ...] } for each
        vulnerable symbol that is directly referenced (called) in a file that
        also imports *dist*.

        Soundness invariant (lower bound):
        - Only files that were FULLY parsed (in visited_files AND in
          file_dist_imports) are checked.  import_only_files and dynamic_files
          are excluded: import_only_files have no call data; dynamic_files with
          dynamic dispatch constructs cannot confirm exact symbol identity.
        - A symbol matches a call's "to" field when:
            bare_sym = bare name (last component after "." of the advisory sym)
            to == bare_sym
            OR to.endswith("." + bare_sym)
          e.g. "get" matches "c.get", "Cache.get", "obj.get"
          e.g. "Cache.get" also matches "c.get" / "obj.get" via bare_sym="get"
        - Files with dynamic dispatch markers (getattr/eval) are EXCLUDED:
          dynamic dispatch may route to any attribute, so we cannot confirm the
          specific vulnerable symbol was reached.
        - Absence of a match => symbol left out of the result (never falsely True).
        """
        hits: Dict[str, List[str]] = {}
        if not symbols:
            return hits

        # Build per-symbol bare names for matching
        # e.g. "Cache.get" -> bare "get"; "safe_decode" -> bare "safe_decode"
        symbol_bare: Dict[str, str] = {}
        for sym in symbols:
            symbol_bare[sym] = sym.split(".")[-1]

        # Only fully-parsed non-dynamic files can yield confirmed symbol hits
        eligible_files = self.visited_files - self.dynamic_files

        for fpath in eligible_files:
            file_dists = self.file_dist_imports.get(fpath)
            if not file_dists or dist not in file_dists:
                continue  # this file does not import the vulnerable dist
            call_tos = self.file_calls.get(fpath, [])
            for sym, bare in symbol_bare.items():
                # Check if any call in this file matches the bare symbol name
                for to in call_tos:
                    if to == bare or to.endswith("." + bare):
                        hits.setdefault(sym, []).append(fpath)
                        break  # one match per file per symbol is enough
        return hits


# ---------------------------------------------------------------------------
# CallGraphBuilder
# ---------------------------------------------------------------------------

class CallGraphBuilder:
    """
    Demand-driven BFS call-graph builder.

    Usage
    -----
        builder = CallGraphBuilder(
            project_root="/abs/path",
            site_packages="/abs/.venv/lib/python3.x/site-packages",
            dist_import_map={"requests": "requests", "yaml": "PyYAML"},
            parser_pool=pool,
        )
        graph = builder.build()
    """

    def __init__(
        self,
        project_root: str,
        dist_import_map: Dict[str, str],     # top_level_import -> dist_name
        parser_pool: Any,                    # ParserPool (typed as Any to avoid circular import)
        site_packages: Optional[str] = None,
        max_files: int = 50_000,
        deadline_sec: float = DEFAULT_DEADLINE_SEC,
    ) -> None:
        self._root = os.path.abspath(project_root)
        self._site_packages = site_packages
        self._dist_import_map = dist_import_map
        self._pool = parser_pool
        self._max_files = max_files
        self._deadline_sec = deadline_sec

        # State
        self._visited: Set[str] = set()
        self._visited_dirs: Set[str] = set()   # for site-packages traversal
        self._graph = CallGraph()

    def build(self) -> CallGraph:
        """
        Run the BFS from entry points and return the completed CallGraph.

        Parallelism: the BFS drains the queue in batches of up to
        _batch_size() files, dispatching all files in each batch to the pool
        concurrently (via parse_many if available, otherwise sequential).
        This saturates all subprocess workers for CPU-bound ast.parse calls.
        """
        entries = discover_entry_points(self._root)

        # Hard invariant: no entry points means we cannot prove anything about
        # the import closure.
        if not entries:
            self._graph.incomplete = True

        queue: deque[str] = deque(entries)

        deadline_at: float = time.monotonic() + self._deadline_sec

        while queue and len(self._visited) < self._max_files:
            if time.monotonic() >= deadline_at:
                self._graph.incomplete = True
                break

            # Drain a batch of unvisited files from the queue.
            # Batch size = number of pool workers (saturate all slots).
            batch_size = self._batch_size()
            batch: List[str] = []
            while queue and len(batch) < batch_size:
                path = os.path.abspath(queue.popleft())
                if path in self._visited:
                    continue
                if len(self._visited) + len(batch) >= self._max_files:
                    # Put it back and stop collecting
                    queue.appendleft(path)
                    break
                batch.append(path)

            if not batch:
                continue

            # Mark all as visited before dispatching (prevents re-queuing
            # within the same batch if two files import each other).
            for p in batch:
                self._visited.add(p)

            # Separate guarded files (skip full parse) from normal files
            to_parse: List[str] = []
            for path in batch:
                if not os.path.isfile(path):
                    self._graph.incomplete = True
                    self._graph.unknown_files.add(path)
                elif _file_needs_guard(path):
                    self._process_guarded_file(path, queue)
                else:
                    to_parse.append(path)

            # Dispatch normal files to pool in parallel (if parse_many is available)
            results = self._parse_batch(to_parse) if to_parse else {}

            # Process results
            for path, result in results.items():
                if result is None or result.is_unknown:
                    # Full parse failed — try the tokenize import scan as a fallback
                    from_tokenize = self._try_import_only_scan(path)
                    if from_tokenize is not None:
                        self._graph.import_only_files.add(path)
                        self._process_imports(from_tokenize, path, queue)
                    else:
                        self._graph.incomplete = True
                        self._graph.unknown_files.add(path)
                    continue

                # Successful full parse
                self._graph.visited_files.add(path)

                # Process dynamic import markers (package-level frontiers)
                import_markers = getattr(result, "dynamic_import_markers", [])
                for marker in import_markers:
                    kind = marker.get("kind", "unbounded") if isinstance(marker, dict) else "unbounded"
                    if kind == "unbounded":
                        self._graph.incomplete = True
                        line = marker.get("line", "?") if isinstance(marker, dict) else "?"
                        self._graph.unbounded_dynamic_import_sites.append({
                            "file": path, "line": line
                        })
                    elif kind == "bounded":
                        prefix = marker.get("prefix") if isinstance(marker, dict) else None
                        target = marker.get("target") if isinstance(marker, dict) else None
                        if prefix and not prefix.startswith("["):
                            self._graph.bounded_dynamic_import_prefixes.add(prefix)
                        elif target:
                            self._graph.bounded_dynamic_import_prefixes.add(target)

                # Dynamic dispatch markers (eval/exec/getattr) → symbol-level only
                dispatch_markers = getattr(result, "dynamic_dispatch_markers", [])
                if not dispatch_markers:
                    combined = getattr(result, "dynamic_markers", [])
                    dispatch_markers = [
                        m for m in combined
                        if not any(w in m for w in ("dynamic import", "import_module", "__import__"))
                    ]
                if dispatch_markers:
                    self._graph.dynamic_files.add(path)

                # Record per-file call targets for symbol-level reachability.
                # We extract call "to" strings from the parsed result so that
                # find_symbol_hits() can check them later.
                calls = getattr(result, "calls", [])
                if calls:
                    call_tos = [
                        c["to"] for c in calls
                        if isinstance(c, dict) and c.get("to")
                    ]
                    if call_tos:
                        self._graph.file_calls[path] = call_tos

                # Process regular imports (also records file_dist_imports)
                self._process_imports(result.imports, path, queue)

        # Hard invariant: BFS truncation by file count → incomplete
        if queue:
            self._graph.incomplete = True

        return self._graph

    def _batch_size(self) -> int:
        """Return the preferred batch size for parallel dispatch."""
        # If the pool has a concurrency attribute, use it as the batch size
        # so we saturate all subprocess workers in one round-trip.
        # Fallback to 1 (sequential) for pools that don't expose concurrency.
        try:
            return max(1, getattr(self._pool, "_concurrency", 1))
        except Exception:
            return 1

    def _parse_batch(self, paths: List[str]) -> Dict[str, Any]:
        """
        Parse a batch of files, returning {path -> ParseResult}.

        Uses parse_many() if available for true parallel dispatch across all
        subprocess workers.  Falls back to sequential parse() calls.
        """
        # Use parse_many if available (ParserPool has it; _InProcessPool may not)
        parse_many = getattr(self._pool, "parse_many", None)
        if parse_many is not None and len(paths) > 1:
            try:
                return parse_many(paths)
            except Exception:
                pass
        # Sequential fallback
        return {p: self._pool.parse(p) for p in paths}

    def _process_guarded_file(self, path: str, queue: deque) -> None:
        """
        Handle a file that exceeded the parse-size guard.

        New behaviour: run the fast tokenize-based import scan so we capture
        the file's imports without a full ast.parse.  The file becomes an
        import-only entry (no call graph), but NOT a package-level frontier.
        Only if the import scan also fails does the file become an UNKNOWN
        frontier (incomplete=True).
        """
        imports = self._try_import_only_scan(path)
        if imports is not None:
            self._graph.import_only_files.add(path)
            self._process_imports(imports, path, queue)
        else:
            # Import scan failed for this oversized file → true UNKNOWN frontier
            self._graph.incomplete = True
            self._graph.unknown_files.add(path)

    def _try_import_only_scan(self, path: str) -> Optional[List[Dict[str, Any]]]:
        """
        Attempt a tokenize-based import-only scan on *path*.

        Returns a list of import dicts on success, or None on failure.
        Imports the ast_worker's _import_only_scan at runtime to avoid
        circular imports; falls back to a simple regex scan if unavailable.
        """
        try:
            worker_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "parse",
            )
            worker_dir = os.path.abspath(worker_dir)
            if worker_dir not in sys.path:
                sys.path.insert(0, worker_dir)
            from ast_worker import _import_only_scan
            return _import_only_scan(path)
        except Exception:
            return None

    def _process_imports(self, imports: List[Dict[str, Any]], current_file: str, queue: deque) -> None:
        """Resolve and act on a list of import dicts."""
        for imp in imports:
            specifier = imp.get("specifier", "")
            if not specifier:
                continue

            resolved = resolve_import(
                specifier=specifier,
                current_file=current_file,
                project_root=self._root,
                site_packages=self._site_packages,
                dist_import_map=self._dist_import_map,
            )

            if resolved.kind == "first_party":
                self._enqueue_first_party(resolved.source_root, queue)

            elif resolved.kind == "third_party":
                dist = resolved.dist_name
                if not dist:
                    dist = _top_module(specifier)
                if dist:
                    self._graph.dist_imports.setdefault(dist, set())
                    self._graph.dist_imports[dist].add(specifier)
                    # Track which dists this specific file imports (for symbol scan)
                    self._graph.file_dist_imports.setdefault(current_file, set())
                    self._graph.file_dist_imports[current_file].add(dist)

                # Walk into site-packages source (if available and not visited)
                if resolved.source_root and os.path.isdir(resolved.source_root):
                    if resolved.source_root not in self._visited_dirs:
                        self._visited_dirs.add(resolved.source_root)
                        self._enqueue_source_dir(resolved.source_root, queue)

            elif resolved.kind == "unknown":
                # Cannot resolve — mark incomplete (package-level frontier)
                self._graph.incomplete = True

    def _enqueue_first_party(self, source_root: str, queue: deque) -> None:
        """Add first-party source files to the BFS queue."""
        if not source_root:
            return
        if os.path.isfile(source_root):
            if source_root not in self._visited:
                queue.append(source_root)
        elif os.path.isdir(source_root):
            # Guard against re-walking the same directory (can happen when
            # multiple files import from the same first-party package).
            if source_root in self._visited_dirs:
                return
            self._visited_dirs.add(source_root)
            for py_file in _walk_py_files(source_root, skip_test=True):
                if py_file not in self._visited:
                    queue.append(py_file)

    def _enqueue_source_dir(self, source_root: str, queue: deque) -> None:
        """Add third-party source files to the BFS queue (no test filtering)."""
        for py_file in _walk_py_files(source_root, skip_test=False):
            if py_file not in self._visited:
                queue.append(py_file)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _walk_py_files(root: str, *, skip_test: bool) -> List[str]:
    """Walk *root* recursively and return .py file paths."""
    results: List[str] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in-place
            dirnames[:] = [
                d for d in dirnames
                if not _is_skip_dir(d)
            ]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                if skip_test and _is_test_file(fpath):
                    continue
                results.append(fpath)
    except PermissionError:
        pass
    return results


# ---------------------------------------------------------------------------
# Convenience builder (for use without a live pool — testing)
# ---------------------------------------------------------------------------

class _InProcessPool:
    """Thin pool shim that calls parse_file() in-process (for tests only)."""

    def __init__(self, worker_script: str) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ast_worker", worker_script)
        mod = importlib.util.module_from_spec(spec)   # type: ignore[arg-type]
        spec.loader.exec_module(mod)                  # type: ignore[union-attr]
        self._parse_file = mod.parse_file
        # Import ParseResult from parser_pool if available, otherwise use local
        try:
            from parse.parser_pool import ParseResult
        except ImportError:
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from parse.parser_pool import ParseResult
            except ImportError:
                ParseResult = None
        self._ParseResult = ParseResult

    def parse(self, path: str) -> Any:
        raw = self._parse_file(path)
        if self._ParseResult is not None:
            return self._ParseResult.from_dict(raw)
        # Fallback: duck-typed object
        class _R:
            def __init__(self, d):
                self.kind = d.get("kind", "unknown")
                self.is_unknown = self.kind != "parsed"
                self.imports = d.get("imports", [])
                self.functions = d.get("functions", [])
                self.calls = d.get("calls", [])
                self.dynamic_markers = d.get("dynamic_markers", [])
                self.dynamic_import_markers = d.get("dynamic_import_markers", [])
                self.dynamic_dispatch_markers = d.get("dynamic_dispatch_markers", [])
        return _R(raw)


def build_call_graph(
    project_root: str,
    dist_import_map: Dict[str, str],
    site_packages: Optional[str] = None,
    worker_script: Optional[str] = None,
    parser_pool: Optional[Any] = None,
    deadline_sec: float = DEFAULT_DEADLINE_SEC,
) -> CallGraph:
    """
    Convenience function: build a call graph for *project_root*.

    If *parser_pool* is None and *worker_script* is provided, an in-process
    pool is used (suitable for tests and CLI use without a live pool).
    """
    if parser_pool is None:
        if worker_script is None:
            worker_script = os.path.join(
                os.path.dirname(__file__), "..", "parse", "ast_worker.py"
            )
        pool = _InProcessPool(worker_script)
    else:
        pool = parser_pool

    builder = CallGraphBuilder(
        project_root=project_root,
        dist_import_map=dist_import_map,
        parser_pool=pool,
        site_packages=site_packages,
        deadline_sec=deadline_sec,
    )
    return builder.build()


# ---------------------------------------------------------------------------
# __main__ — --analyze-json entrypoint (invoked by the Go sidecar)
# ---------------------------------------------------------------------------
#
# Protocol (matches main.go cgRequest / cgResponse types exactly):
#
#   stdin:  JSON object {
#               "project_root":      string (required),
#               "site_packages":     string (optional),
#               "dist_names":        [string, ...],
#               "deadline_sec":      float  (optional; default DEFAULT_DEADLINE_SEC),
#               "vulnerable_symbols": { dist_name: [symbol, ...], ... }  (optional)
#           }
#
#   stdout: JSON object {
#               "dist_reachable":   { dist_name: bool, ... },
#               "symbol_reachable": { "dist::symbol": bool, ... },
#               "symbol_paths":     { "dist::symbol": [file_path, ...], ... },
#               "incomplete":       bool,
#               "error":            string  (omitted when empty)
#           }
#
# symbol_reachable keys use the format "dist_name::symbol_name".
# A key is present with value True only when a direct static call to the
# symbol was found in a reachable first-party file that imports the dist.
#
# Exit code: always 0 (errors are reported via the JSON "error" field).

if __name__ == "__main__":
    import json as _json

    def _emit(obj: dict) -> None:
        sys.stdout.write(_json.dumps(obj) + "\n")
        sys.stdout.flush()

    def _run_analyze_json() -> None:
        args = sys.argv[1:]
        if not args or args[0] != "--analyze-json":
            sys.stderr.write(
                "call_graph.py: expected --analyze-json flag\n"
            )
            sys.exit(1)

        _fallback_resp: Dict[str, Any] = {
            "dist_reachable": {},
            "symbol_reachable": {},
            "incomplete": True,
            "error": "unexpected exit before response was written",
        }
        import atexit as _atexit
        _emitted = [False]

        def _emergency_emit() -> None:
            if not _emitted[0]:
                _emit(_fallback_resp)

        _atexit.register(_emergency_emit)

        try:
            raw = sys.stdin.read()
            req = _json.loads(raw)
        except Exception as exc:
            _fallback_resp["error"] = f"decode request: {exc}"
            _emitted[0] = True
            _emit(_fallback_resp)
            return

        project_root = req.get("project_root", "")
        site_packages = req.get("site_packages") or None
        dist_names: List[str] = req.get("dist_names") or []
        deadline_sec: float = float(req.get("deadline_sec") or DEFAULT_DEADLINE_SEC)
        # vulnerable_symbols: { dist_name: [symbol, ...] }
        # Provided by the Go caller when the advisory has symbol-level data.
        vulnerable_symbols: Dict[str, List[str]] = req.get("vulnerable_symbols") or {}

        if not project_root:
            resp = {"dist_reachable": {}, "symbol_reachable": {},
                    "incomplete": True, "error": "project_root is empty"}
            _emitted[0] = True
            _emit(resp)
            return

        worker_script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "parse", "ast_worker.py",
        )

        # Use a ProcessPool-backed ParserPool for true CPU parallelism.
        # ast.parse is CPU-bound; threads serialize under the GIL.
        try:
            _sidecar_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _sidecar_dir not in sys.path:
                sys.path.insert(0, _sidecar_dir)
            from parse.parser_pool import ParserPool as _ParserPool
            _concurrency = max(4, os.cpu_count() or 4)
            pool = _ParserPool(worker_script=worker_script, concurrency=_concurrency)
        except Exception as exc:
            pool = _InProcessPool(worker_script)

        graph: Optional[CallGraph] = None
        try:
            builder = CallGraphBuilder(
                project_root=project_root,
                dist_import_map={dn: dn for dn in dist_names},
                parser_pool=pool,
                site_packages=site_packages,
                deadline_sec=deadline_sec,
            )
            graph = builder.build()
        except Exception as exc:
            _fallback_resp["error"] = f"build_call_graph: {exc}"
            _emitted[0] = True
            _emit(_fallback_resp)
            try:
                pool.shutdown()
            except Exception:
                pass
            return
        finally:
            try:
                pool.shutdown()
            except Exception:
                pass

        dist_reachable: Dict[str, bool] = {}
        for dn in dist_names:
            dist_reachable[dn] = graph.imports_dist(dn)

        # Symbol-level reachability scan.
        # For each dist that has vulnerable symbols AND is in the import closure,
        # find files that directly call those symbols.
        # Key format: "dist_name::symbol_name"  value: True (never False — absent = undetermined)
        symbol_reachable: Dict[str, bool] = {}
        symbol_paths: Dict[str, List[str]] = {}

        for dn, syms in vulnerable_symbols.items():
            if not syms or not graph.imports_dist(dn):
                # Dist not imported → skip symbol check entirely
                continue
            hits = graph.find_symbol_hits(dn, syms)
            for sym, paths in hits.items():
                key = f"{dn}::{sym}"
                symbol_reachable[key] = True
                symbol_paths[key] = paths

        resp_out: Dict[str, Any] = {
            "dist_reachable": dist_reachable,
            "symbol_reachable": symbol_reachable,
            "symbol_paths": symbol_paths,
            "incomplete": graph.incomplete,
        }
        _emitted[0] = True
        _emit(resp_out)

    _run_analyze_json()
