"""
extract.py — --extract-symbols sidecar for Python fix-patch symbol extraction.

Protocol
--------
stdin  (JSON):
    {
        "patch": "<unified diff>",
        "files": [
            {"path": "celery/kombu/utils/encoding.py", "content": "def safe_decode(s): ..."}
        ]
    }

stdout (JSON array):
    [
        {
            "file":       "celery/kombu/utils/encoding.py",
            "module":     "celery.kombu.utils.encoding",
            "exportName": "safe_decode",
            "kind":       "function"
        }
    ]

Exit code is always 0; errors are silenced and return [].

The ``module`` field is derived from the file path by stripping the ``.py``
suffix and replacing ``/`` and ``\\`` with ``.``.  It is module-qualified so
that ``symbolextract.Extract`` (Go-side) can populate ``Symbol.Package``
without hard-coding an empty string.

Hard invariants
---------------
- Never exit non-zero (callers treat non-zero as an error and may degrade).
- Never crash; catch all exceptions and emit [] on any fatal path.
- Only Python stdlib is allowed (ast, json, sys, os, re).
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Module-path derivation
# ---------------------------------------------------------------------------

def _path_to_module(file_path: str) -> str:
    """
    Convert a repo-relative file path to a dotted Python module name.

    Examples:
        "celery/kombu/utils/encoding.py" -> "celery.kombu.utils.encoding"
        "src/app/__init__.py"            -> "src.app.__init__"
        "utils.py"                       -> "utils"

    __init__.py is preserved as-is; callers can strip it if desired but we
    do not alter it here — the package boundary is the directory.
    """
    # Normalise separators
    normalised = file_path.replace("\\", "/")
    # Strip .py suffix
    if normalised.endswith(".py"):
        normalised = normalised[:-3]
    # Replace slashes with dots
    return normalised.replace("/", ".")


# ---------------------------------------------------------------------------
# Unified-diff parser
# ---------------------------------------------------------------------------

def _parse_unified_diff(patch: str) -> Dict[str, List[int]]:
    """
    Parse a unified diff and return a mapping of file path -> list of
    added/modified line numbers in the *new* file.

    Only lines prefixed with '+' (additions) inside a hunk are tracked;
    context ('-' removed) lines are ignored.  The hunk header
    ``@@ -old +new_start[,count] @@`` drives the line counter.
    """
    changed: Dict[str, List[int]] = {}
    current_file: Optional[str] = None
    new_line: int = 0

    for line in patch.splitlines():
        if line.startswith("+++ "):
            raw = line[4:]
            # Strip leading "b/" (git diff convention)
            if raw.startswith("b/"):
                raw = raw[2:]
            current_file = raw.strip()
            changed.setdefault(current_file, [])

        elif line.startswith("@@ ") and current_file is not None:
            # @@ -old_start[,old_count] +new_start[,new_count] @@
            m = re.search(r"\+(\d+)(?:,\d+)?", line)
            if m:
                new_line = int(m.group(1)) - 1  # will be incremented on first '+'

        elif current_file is not None:
            if line.startswith("+"):
                new_line += 1
                if not line.startswith("+++"):  # guard against file headers
                    changed[current_file].append(new_line)
            elif line.startswith("-"):
                pass  # removed lines don't advance the new-file counter
            else:
                # Context line
                new_line += 1

    return changed


# ---------------------------------------------------------------------------
# AST symbol extractor
# ---------------------------------------------------------------------------

def _overlaps(node: ast.AST, changed_lines: List[int]) -> bool:
    """Return True if *node* spans any line in *changed_lines*."""
    if not changed_lines:
        return False
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", start)
    if start is None:
        return False
    node_range = set(range(start, (end or start) + 1))
    return bool(node_range.intersection(changed_lines))


def _extract_symbols_from_source(
    file_path: str,
    source: str,
    changed_lines: List[int],
) -> List[Dict[str, str]]:
    """
    Parse *source* with ``ast`` and return symbol dicts for every top-level
    (or class-method) definition that overlaps *changed_lines*.

    If *changed_lines* is empty, all definitions are included (the entire
    file is considered changed — e.g. when the diff added the whole file).

    Returned dict shape:
        {
            "file":       "<repo-relative path>",
            "module":     "<dotted.module.name>",
            "exportName": "<SymbolName>",
            "kind":       "function" | "async_function" | "class" | "method" | "async_method"
        }
    """
    include_all = not changed_lines

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    module_name = _path_to_module(file_path)
    results: List[Dict[str, str]] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "function" if isinstance(node, ast.FunctionDef) else "async_function"
            if include_all or _overlaps(node, changed_lines):
                results.append({
                    "file":       file_path,
                    "module":     module_name,
                    "exportName": node.name,
                    "kind":       kind,
                })

        elif isinstance(node, ast.ClassDef):
            class_touched = include_all or _overlaps(node, changed_lines)
            if class_touched:
                results.append({
                    "file":       file_path,
                    "module":     module_name,
                    "exportName": node.name,
                    "kind":       "class",
                })
            # Extract methods
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "method" if isinstance(item, ast.FunctionDef) else "async_method"
                    if include_all or _overlaps(item, changed_lines):
                        results.append({
                            "file":       file_path,
                            "module":     module_name,
                            "exportName": f"{node.name}.{item.name}",
                            "kind":       kind,
                        })

    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def extract(request: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Core extraction function (separated for testability).

    Parameters
    ----------
    request : dict with keys:
        patch (str)  : unified diff text
        files (list) : [{"path": str, "content": str}]

    Returns a list of symbol dicts as described by _extract_symbols_from_source.
    """
    patch: str = request.get("patch", "")
    files: List[Dict[str, str]] = request.get("files", [])

    # Parse the diff to know which lines changed in which files.
    changed_by_file = _parse_unified_diff(patch) if patch.strip() else {}

    # Index file content by path.
    content_by_path: Dict[str, str] = {
        f["path"]: f.get("content", "")
        for f in files
        if "path" in f
    }

    results: List[Dict[str, str]] = []

    # Process each file that appears in the diff.
    for file_path, changed_lines in changed_by_file.items():
        if not file_path.endswith(".py"):
            continue  # Skip non-Python files (Go, JS, etc.)

        content = content_by_path.get(file_path)
        if content is None:
            # File listed in diff but content not provided — skip.
            continue

        results.extend(
            _extract_symbols_from_source(file_path, content, changed_lines)
        )

    # If no diff was provided but files were, extract from all .py files.
    if not changed_by_file:
        for file_path, content in content_by_path.items():
            if not file_path.endswith(".py"):
                continue
            results.extend(
                _extract_symbols_from_source(file_path, content, [])
            )

    return results


def main() -> None:
    """Read JSON from stdin, extract symbols, write JSON array to stdout."""
    try:
        raw = sys.stdin.read()
        request = json.loads(raw)
    except Exception:
        sys.stdout.write("[]\n")
        sys.exit(0)

    try:
        symbols = extract(request)
    except Exception:
        symbols = []

    sys.stdout.write(json.dumps(symbols))
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
