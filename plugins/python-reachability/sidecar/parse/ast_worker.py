"""
ast_worker.py — crash-isolated AST parse worker (subprocess mode).

Protocol
--------
This script is spawned as a subprocess by the Go shim (or the Python test
harness).  It reads newline-delimited JSON requests from stdin and writes
newline-delimited JSON responses to stdout.

Request  (one JSON object per line):
    { "id": <int>, "path": "<absolute-or-repo-relative .py path>" }

Response (one JSON object per line):
    On success:
        {
            "id": <int>,
            "result": {
                "kind": "parsed",
                "path": "<path>",
                "imports": [
                    { "specifier": "requests", "names": ["get", "post"], "is_from": true }
                ],
                "functions": [
                    { "name": "fetch_data", "start_line": 10, "end_line": 20 }
                ],
                "calls": [
                    { "from_func": "fetch_data", "to": "requests.get", "line": 12 }
                ],
                "dynamic_import_markers": [
                    {"kind": "unbounded", "line": 42}
                ],
                "dynamic_dispatch_markers": ["eval at line 18", "getattr at line 22"],
                "dynamic_markers": ["eval at line 18", "getattr at line 22"]
            }
        }
    On parse failure (syntax error, IO error, any exception):
        {
            "id": <int>,
            "result": { "kind": "unknown", "reason": "<description>" }
        }

Hard invariants
---------------
- Never emit a non-zero exit code for individual parse failures; only exit
  non-zero (exit 1) when stdin is exhausted / an unrecoverable error occurs.
- A crash in parsing ONE file MUST produce a "kind": "unknown" response for
  that request, not a crash of the worker process itself.
- Only Python stdlib is used (ast, json, sys, os, tokenize).

Crash isolation model
---------------------
Each parse runs inside a try/except that catches ALL exceptions.  If the
parse raises (syntax error, recursion overflow, MemoryError, etc.) the worker
emits { kind: "unknown", reason: "<exc>" } and continues reading.

The Go-side pool watches for the worker process dying (stdout EOF before
expected response) and respawns; that case handles unrecoverable crashes
like segfaults.

Marker categories (the key fix)
--------------------------------
dynamic_import_markers: UNBOUNDED/opaque dynamic imports ONLY —
    importlib.import_module / __import__ whose target is NOT statically
    determinable (no literal prefix).  These are PACKAGE-LEVEL frontiers.
    A bounded dynamic import (literal string, literal prefix, first-party
    relative/self) is NOT an unbounded frontier — its target is known.

dynamic_dispatch_markers: eval, exec, dynamic getattr, __getattr__ /
    __getattribute__ / __setattr__.  SYMBOL-LEVEL only — they do NOT import
    packages and MUST NOT gate package-level NOT_REACHABLE.

dynamic_markers: backward-compat combined list (dispatch + unbounded imports).
"""

from __future__ import annotations

import ast
import json
import sys
import os
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Dynamic construct detection — split into two categories
# ---------------------------------------------------------------------------

_DYNAMIC_ATTR_FNS = frozenset({
    "getattr",
    "setattr",
    "delattr",
    "hasattr",
})


def _literal_string(node: ast.expr) -> Optional[str]:
    """Return the string value if *node* is a literal string constant, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.s, str):
        return node.s
    return None


def _literal_prefix_of_concat(node: ast.expr) -> Optional[str]:
    """
    If *node* is a binary-string concat or f-string with a literal prefix,
    return that prefix.  Otherwise None.

    Handles:
      "a.b." + var       -> "a.b."
      f"a.b.{var}"       -> "a.b."
    """
    # BinOp: "prefix" + expr
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_lit = _literal_string(node.left)
        if left_lit is not None:
            return left_lit
    # JoinedStr (f-string): first value may be a literal
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.s, str):
            return first.s
    return None


def _analyze_import_module_arg(first_arg: ast.expr, kwargs: Dict[str, ast.expr]) -> Dict[str, Any]:
    """
    Analyze the first argument to import_module() / __import__().

    Returns a dict:
      { "bounded": bool, "target": str|None, "prefix": str|None }

    bounded=True means we can determine the import namespace (no unbounded frontier).
    """
    # Literal string → fully resolved, bounded
    lit = _literal_string(first_arg)
    if lit is not None:
        return {"bounded": True, "target": lit, "prefix": None}

    # __name__ or first-party relative (import_module(__name__, package=X))
    if isinstance(first_arg, ast.Name) and first_arg.id == "__name__":
        return {"bounded": True, "target": None, "prefix": "__name__"}

    # Relative specifier: import_module("...", package="mypkg") or package=__name__
    # The "package" kwarg means the resulting module is relative → first-party
    if "package" in kwargs:
        pkg_val = kwargs["package"]
        if isinstance(pkg_val, ast.Constant) and isinstance(pkg_val.s, str):
            return {"bounded": True, "target": None, "prefix": f"[relative to {pkg_val.s}]"}
        if isinstance(pkg_val, ast.Name) and pkg_val.id == "__name__":
            return {"bounded": True, "target": None, "prefix": "[relative to __name__]"}

    # Literal-prefixed concat or f-string: import_module("a.b." + var)
    prefix = _literal_prefix_of_concat(first_arg)
    if prefix is not None:
        return {"bounded": True, "target": None, "prefix": prefix}

    # Fully opaque: bare variable, call result, etc.
    return {"bounded": False, "target": None, "prefix": None}


def _classify_dynamic_import(node: ast.Call, lineno: int) -> Optional[Dict[str, Any]]:
    """
    If *node* is a dynamic import call, return a classification dict:
      {
        "kind": "bounded" | "unbounded",
        "line": int,
        "target": str|None,   # resolved literal target (bounded only)
        "prefix": str|None,   # resolved namespace prefix (bounded only)
      }
    Returns None if *node* is not a dynamic import call, or if it's a fully
    static import_module('literal') — those appear only as regular imports.
    """
    func = node.func

    # __import__(arg) — only dynamic when arg is not a literal
    if isinstance(func, ast.Name) and func.id == "__import__":
        if not node.args:
            return {"kind": "unbounded", "line": lineno, "target": None, "prefix": None}
        lit = _literal_string(node.args[0])
        if lit is not None:
            # __import__('requests') is static; captured via imports already
            return None
        # Build kwargs map
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        info = _analyze_import_module_arg(node.args[0], kwargs)
        kind = "bounded" if info["bounded"] else "unbounded"
        return {"kind": kind, "line": lineno, "target": info.get("target"), "prefix": info.get("prefix")}

    # importlib.import_module(arg) or import_module(arg) (bare name after 'from importlib import import_module')
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        if not node.args:
            return {"kind": "unbounded", "line": lineno, "target": None, "prefix": None}
        lit = _literal_string(node.args[0])
        if lit is not None:
            # Literal: import_module('requests') — captured already via imports; NOT an unbounded frontier
            return None
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        info = _analyze_import_module_arg(node.args[0], kwargs)
        kind = "bounded" if info["bounded"] else "unbounded"
        return {"kind": kind, "line": lineno, "target": info.get("target"), "prefix": info.get("prefix")}

    # import_module called as a bare name (after 'from importlib import import_module')
    if isinstance(func, ast.Name) and func.id == "import_module":
        if not node.args:
            return {"kind": "unbounded", "line": lineno, "target": None, "prefix": None}
        lit = _literal_string(node.args[0])
        if lit is not None:
            return None
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        info = _analyze_import_module_arg(node.args[0], kwargs)
        kind = "bounded" if info["bounded"] else "unbounded"
        return {"kind": kind, "line": lineno, "target": info.get("target"), "prefix": info.get("prefix")}

    return None


def _is_dynamic_getattr(node: ast.Call) -> bool:
    """Return True if *node* is getattr(obj, dynamic_attr) — symbol dispatch."""
    func = node.func
    if not (isinstance(func, ast.Name) and func.id in _DYNAMIC_ATTR_FNS):
        return False
    if len(node.args) >= 2:
        return not isinstance(node.args[1], ast.Constant)
    return False


def _detect_markers(tree: ast.Module) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Walk the AST and collect:
      dynamic_import_markers: list of {kind, line, target, prefix} for dynamic imports.
        kind="unbounded" -> opaque package-level frontier
        kind="bounded"   -> deterministic namespace (NOT a frontier)
      dynamic_dispatch_markers: list of strings for eval/exec/dynamic getattr/__getattr__
        These are SYMBOL-LEVEL only and MUST NOT gate package-level NOT_REACHABLE.

    Returns (dynamic_import_markers, dynamic_dispatch_markers).
    """
    import_markers: List[Dict[str, Any]] = []
    dispatch_markers: List[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            lineno = getattr(node, "lineno", "?")
            func = node.func

            # eval / exec → dispatch marker only
            if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                dispatch_markers.append(f"{func.id} at line {lineno}")
                continue

            # Dynamic import (import_module / __import__)
            imp_info = _classify_dynamic_import(node, lineno)
            if imp_info is not None:
                import_markers.append(imp_info)
                continue

            # getattr(obj, dynamic) → dispatch marker
            if _is_dynamic_getattr(node):
                dispatch_markers.append(f"dynamic getattr at line {lineno}")

        # Metaclass / __getattr__ at class level → dispatch marker
        elif isinstance(node, ast.ClassDef):
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name in ("__getattr__", "__getattribute__", "__setattr__"):
                        lineno = getattr(item, "lineno", "?")
                        dispatch_markers.append(f"{item.name} at line {lineno}")

    return import_markers, dispatch_markers


def _detect_dynamic_markers(tree: ast.Module) -> List[str]:
    """
    BACKWARD-COMPAT shim: return the combined list of all dynamic marker strings.

    New code should use _detect_markers() and inspect dynamic_import_markers /
    dynamic_dispatch_markers separately.  This function exists so that existing
    callers (tests, old integrations) continue to work.
    """
    import_markers, dispatch_markers = _detect_markers(tree)
    combined: List[str] = list(dispatch_markers)
    for m in import_markers:
        line = m.get("line", "?")
        kind = m.get("kind", "unbounded")
        combined.append(f"dynamic import ({kind}) at line {line}")
    return combined


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------

def _extract_imports(tree: ast.Module) -> List[Dict[str, Any]]:
    """
    Walk the AST and extract all import statements.

    Returns a list of dicts:
        { "specifier": str, "names": [str, ...], "is_from": bool }

    For `import foo.bar` the specifier is "foo.bar" and names = ["foo.bar"].
    For `from foo import bar, baz` the specifier is "foo" and names = ["bar","baz"].
    For `from . import x` (relative) the specifier is "." and names = ["x"].
    For `from .sub import y` the specifier is ".sub" and names = ["y"].
    """
    imports: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({
                    "specifier": alias.name,
                    "names": [alias.asname or alias.name],
                    "is_from": False,
                })
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            dots = "." * level
            module = node.module or ""
            specifier = dots + module
            names = [alias.asname or alias.name for alias in node.names]
            # "*" import
            if names == ["*"]:
                names = ["*"]
            imports.append({
                "specifier": specifier,
                "names": names,
                "is_from": True,
            })
    return imports


# ---------------------------------------------------------------------------
# Function / class definition extraction
# ---------------------------------------------------------------------------

def _extract_functions(tree: ast.Module) -> List[Dict[str, Any]]:
    """
    Extract top-level and class-level function definitions.

    Returns list of:
        { "name": str, "start_line": int, "end_line": int }

    For class methods the name is "ClassName.method_name".
    """
    functions: List[Dict[str, Any]] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append({
                "name": node.name,
                "start_line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
            })
        elif isinstance(node, ast.ClassDef):
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append({
                        "name": f"{node.name}.{item.name}",
                        "start_line": item.lineno,
                        "end_line": getattr(item, "end_lineno", item.lineno),
                    })

    return functions


# ---------------------------------------------------------------------------
# Call edge extraction
# ---------------------------------------------------------------------------

def _extract_calls(tree: ast.Module) -> List[Dict[str, Any]]:
    """
    Extract call edges from the AST.

    Returns list of:
        { "from_func": str, "to": str, "line": int }

    "from_func" is the enclosing function name (or "" for module-level calls).
    "to" is a best-effort dotted name for the callee (e.g. "requests.get").
    """
    calls: List[Dict[str, Any]] = []

    def _callee_name(node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _callee_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return None

    def _enclosing_name(func_node: ast.FunctionDef | ast.AsyncFunctionDef, class_node: Optional[ast.ClassDef]) -> str:
        if class_node:
            return f"{class_node.name}.{func_node.name}"
        return func_node.name

    # Module-level calls
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            name = _callee_name(node.value.func)
            if name:
                calls.append({"from_func": "", "to": name, "line": node.lineno})

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fname = node.name
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _callee_name(child.func)
                    if name:
                        calls.append({"from_func": fname, "to": name, "line": getattr(child, "lineno", 0)})

        elif isinstance(node, ast.ClassDef):
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mname = f"{node.name}.{item.name}"
                    for child in ast.walk(item):
                        if isinstance(child, ast.Call):
                            name = _callee_name(child.func)
                            if name:
                                calls.append({"from_func": mname, "to": name, "line": getattr(child, "lineno", 0)})

    return calls


# ---------------------------------------------------------------------------
# Import-only scan (tokenize-based, for oversized files)
# ---------------------------------------------------------------------------

def _import_only_scan(path: str) -> Optional[List[Dict[str, Any]]]:
    """
    Fast import extraction using tokenize — no ast.parse.

    Used as a fallback for files that exceed the parse guard thresholds.
    Returns a list of import dicts (same shape as _extract_imports), or None
    if even the tokenize scan fails.

    Only captures top-level 'import X' and 'from X import Y' statements;
    conditional / nested imports are missed — but those are rare in giant files
    (which are usually machine-generated with only top-level imports).
    """
    import tokenize
    import io

    try:
        with open(path, "rb") as fh:
            source_bytes = fh.read()
    except OSError:
        return None

    imports: List[Dict[str, Any]] = []
    # Collect tokens incrementally so that a TokenError partway through
    # still gives us the tokens we've seen up to the error point.
    try:
        gen = tokenize.tokenize(io.BytesIO(source_bytes).readline)
        tokens = []
        while True:
            try:
                tokens.append(next(gen))
            except tokenize.TokenError:
                # Partial tokenize — work with what we have
                break
            except StopIteration:
                break
    except Exception:
        return None

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.type != tokenize.NAME:
            i += 1
            continue

        # --- 'import X' or 'import X as Y' or 'import X, Y' ---
        if tok.string == "import":
            i += 1
            while i < n:
                # Collect dotted name
                parts: List[str] = []
                while i < n and tokens[i].type in (tokenize.NAME, tokenize.OP) and tokens[i].string != ",":
                    if tokens[i].string == "as":
                        # Skip alias: consume 'as' + alias_name
                        i += 2
                        break
                    if tokens[i].type == tokenize.NAME or tokens[i].string == ".":
                        parts.append(tokens[i].string)
                    elif tokens[i].type == tokenize.NEWLINE or tokens[i].type == tokenize.NL or tokens[i].type == tokenize.COMMENT:
                        break
                    i += 1
                specifier = "".join(parts)
                if specifier:
                    imports.append({"specifier": specifier, "names": [specifier], "is_from": False})
                if i < n and tokens[i].string == ",":
                    i += 1
                    continue
                break
            continue

        # --- 'from X import Y' ---
        if tok.string == "from":
            i += 1
            # Collect dotted module name (including leading dots for relative)
            parts = []
            while i < n and tokens[i].type in (tokenize.NAME, tokenize.OP) and tokens[i].string not in ("import", "\n", "\\"):
                if tokens[i].type == tokenize.NAME or tokens[i].string == ".":
                    parts.append(tokens[i].string)
                i += 1
            specifier = "".join(parts)
            # consume 'import'
            if i < n and tokens[i].type == tokenize.NAME and tokens[i].string == "import":
                i += 1
                names: List[str] = []
                # consume names (possibly in parens)
                in_paren = False
                if i < n and tokens[i].string == "(":
                    in_paren = True
                    i += 1
                while i < n:
                    t = tokens[i]
                    if t.type == tokenize.NAME:
                        name = t.string
                        # skip 'as alias'
                        if i + 2 < n and tokens[i + 1].string == "as":
                            name = tokens[i + 2].string
                            i += 2
                        names.append(name)
                    elif t.string == "*":
                        names = ["*"]
                    elif t.string == ",":
                        pass
                    elif t.string == ")" and in_paren:
                        i += 1
                        break
                    elif t.type in (tokenize.NEWLINE, tokenize.NL) and not in_paren:
                        break
                    i += 1
                if specifier:
                    imports.append({"specifier": specifier, "names": names or ["*"], "is_from": True})
            continue

        i += 1

    return imports


# ---------------------------------------------------------------------------
# Core parse function
# ---------------------------------------------------------------------------

def parse_file(path: str) -> Dict[str, Any]:
    """
    Parse a single Python file and return a ParsedModule dict.

    On any error (file not found, syntax error, exception) returns a dict
    with kind="unknown".  This function MUST NOT raise.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        return {"kind": "unknown", "reason": f"read error: {exc}"}

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return {"kind": "unknown", "reason": f"syntax error: {exc}"}
    except Exception as exc:
        return {"kind": "unknown", "reason": f"parse error: {exc}"}

    try:
        imports = _extract_imports(tree)
        functions = _extract_functions(tree)
        calls = _extract_calls(tree)
        import_markers, dispatch_markers = _detect_markers(tree)
        # backward-compat combined list
        dynamic_markers: List[str] = list(dispatch_markers)
        for m in import_markers:
            line = m.get("line", "?")
            kind = m.get("kind", "unbounded")
            dynamic_markers.append(f"dynamic import ({kind}) at line {line}")
    except Exception as exc:
        return {"kind": "unknown", "reason": f"analysis error: {exc}"}

    return {
        "kind": "parsed",
        "path": path,
        "imports": imports,
        "functions": functions,
        "calls": calls,
        "dynamic_import_markers": import_markers,
        "dynamic_dispatch_markers": dispatch_markers,
        "dynamic_markers": dynamic_markers,   # backward-compat combined
    }


# ---------------------------------------------------------------------------
# Worker loop (subprocess stdin/stdout protocol)
# ---------------------------------------------------------------------------

def run_worker() -> None:
    """
    Read JSON requests from stdin (one per line), emit JSON responses to stdout.

    Each request: { "id": <int>, "path": "<file path>" }
    Each response: { "id": <int>, "result": <ParsedModule or unknown> }

    The worker exits when stdin is closed (EOF).  It never exits for a
    per-file parse failure — those produce kind="unknown" responses.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            # Malformed request — emit unknown with id=null if we can't parse
            sys.stdout.write(json.dumps({"id": None, "result": {"kind": "unknown", "reason": f"bad request JSON: {exc}"}}))
            sys.stdout.write("\n")
            sys.stdout.flush()
            continue

        req_id = req.get("id")
        path = req.get("path", "")

        result = parse_file(path)

        response = {"id": req_id, "result": result}
        sys.stdout.write(json.dumps(response))
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_worker()
