"""
test_ast_worker.py — unit tests for parse/ast_worker.py

Tests cover:
- _extract_imports: import / from-import / relative / star
- _extract_functions: top-level funcs, async funcs, class methods
- _extract_calls: caller→callee edges
- _detect_dynamic_markers: eval, exec, dynamic getattr, __import__
- parse_file: full integration (happy path + syntax error + missing file)
- run_worker: subprocess stdin/stdout protocol (end-to-end)

Run with:
    .claude/skills/.venv/bin/python3 -m pytest \
        plugins/python-reachability/sidecar/parse/test_ast_worker.py -v
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Path setup — import from the local sidecar tree, not an installed package
# ---------------------------------------------------------------------------

PARSE_DIR = Path(__file__).parent
sys.path.insert(0, str(PARSE_DIR))

from ast_worker import (
    _detect_dynamic_markers,
    _extract_calls,
    _extract_functions,
    _extract_imports,
    parse_file,
    run_worker,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _parse(source: str):
    return ast.parse(textwrap.dedent(source))


def _write_tmp(source: str, suffix: str = ".py") -> str:
    """Write *source* to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(textwrap.dedent(source))
    return path


# ===========================================================================
# _extract_imports
# ===========================================================================

class TestExtractImports:
    def test_simple_import(self):
        tree = _parse("import requests")
        imps = _extract_imports(tree)
        specifiers = [i["specifier"] for i in imps]
        assert "requests" in specifiers

    def test_from_import(self):
        tree = _parse("from os import path")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "os" and "path" in i["names"] for i in imps)

    def test_from_import_multiple_names(self):
        tree = _parse("from collections import deque, OrderedDict")
        imps = _extract_imports(tree)
        names_all = []
        for i in imps:
            names_all.extend(i["names"])
        assert "deque" in names_all
        assert "OrderedDict" in names_all

    def test_dotted_import(self):
        tree = _parse("import os.path")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "os.path" for i in imps)

    def test_relative_import(self):
        tree = _parse("from . import models")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "." and "models" in i["names"] for i in imps)

    def test_relative_submodule(self):
        tree = _parse("from .utils import helper")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == ".utils" and "helper" in i["names"] for i in imps)

    def test_star_import(self):
        tree = _parse("from os import *")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "os" and i["names"] == ["*"] for i in imps)

    def test_aliased_import(self):
        tree = _parse("import numpy as np")
        imps = _extract_imports(tree)
        # asname takes precedence for the names entry
        assert any(i["specifier"] == "numpy" and "np" in i["names"] for i in imps)

    def test_aliased_from_import(self):
        tree = _parse("from datetime import datetime as dt")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "datetime" and "dt" in i["names"] for i in imps)

    def test_is_from_flag(self):
        tree = _parse("import os\nfrom sys import argv")
        imps = _extract_imports(tree)
        by_spec = {i["specifier"]: i for i in imps}
        assert by_spec["os"]["is_from"] is False
        assert by_spec["sys"]["is_from"] is True

    def test_no_imports(self):
        tree = _parse("x = 1")
        assert _extract_imports(tree) == []

    def test_nested_from_import(self):
        tree = _parse("from celery.kombu.utils import encoding")
        imps = _extract_imports(tree)
        assert any(i["specifier"] == "celery.kombu.utils" for i in imps)


# ===========================================================================
# _extract_functions
# ===========================================================================

class TestExtractFunctions:
    def test_simple_function(self):
        tree = _parse("""\
            def foo():
                pass
        """)
        fns = _extract_functions(tree)
        names = [f["name"] for f in fns]
        assert "foo" in names

    def test_async_function(self):
        tree = _parse("""\
            async def bar():
                pass
        """)
        fns = _extract_functions(tree)
        assert any(f["name"] == "bar" for f in fns)

    def test_class_method(self):
        tree = _parse("""\
            class Foo:
                def baz(self):
                    pass
        """)
        fns = _extract_functions(tree)
        names = [f["name"] for f in fns]
        assert "Foo.baz" in names

    def test_class_async_method(self):
        tree = _parse("""\
            class Enc:
                async def encode(self, s):
                    pass
        """)
        fns = _extract_functions(tree)
        assert any(f["name"] == "Enc.encode" for f in fns)

    def test_line_numbers(self):
        tree = _parse("""\
            def alpha():
                pass

            def beta():
                pass
        """)
        fns = {f["name"]: f for f in _extract_functions(tree)}
        assert fns["alpha"]["start_line"] == 1
        assert fns["beta"]["start_line"] == 4

    def test_no_functions(self):
        tree = _parse("x = 1")
        assert _extract_functions(tree) == []


# ===========================================================================
# _extract_calls
# ===========================================================================

class TestExtractCalls:
    def test_simple_call(self):
        tree = _parse("""\
            def fetch():
                requests.get("http://example.com")
        """)
        calls = _extract_calls(tree)
        assert any(c["from_func"] == "fetch" and c["to"] == "requests.get" for c in calls)

    def test_method_call(self):
        tree = _parse("""\
            class Client:
                def run(self):
                    self.session.post("/api")
        """)
        calls = _extract_calls(tree)
        assert any(c["from_func"] == "Client.run" for c in calls)

    def test_module_level_call(self):
        tree = _parse("print('hello')")
        calls = _extract_calls(tree)
        assert any(c["from_func"] == "" and c["to"] == "print" for c in calls)

    def test_nested_attribute_call(self):
        tree = _parse("""\
            def go():
                a.b.c()
        """)
        calls = _extract_calls(tree)
        assert any(c["to"] == "a.b.c" for c in calls)

    def test_no_calls(self):
        tree = _parse("x = 1 + 2")
        calls = _extract_calls(tree)
        assert calls == []


# ===========================================================================
# _detect_dynamic_markers
# ===========================================================================

class TestDetectDynamicMarkers:
    def test_eval(self):
        tree = _parse("eval('1+1')")
        markers = _detect_dynamic_markers(tree)
        assert any("eval" in m for m in markers)

    def test_exec(self):
        tree = _parse("exec('x=1')")
        markers = _detect_dynamic_markers(tree)
        assert any("exec" in m for m in markers)

    def test_dynamic_getattr(self):
        tree = _parse("""\
            name = get_name()
            getattr(obj, name)
        """)
        markers = _detect_dynamic_markers(tree)
        assert any("getattr" in m for m in markers)

    def test_literal_getattr_not_marked(self):
        """getattr(obj, 'literal') is NOT dynamic — constant string second arg."""
        tree = _parse("getattr(obj, 'fixed_attr')")
        markers = _detect_dynamic_markers(tree)
        # Should NOT produce a dynamic marker for a constant attr name
        assert not any("getattr" in m for m in markers)

    def test_dynamic_import(self):
        tree = _parse("""\
            name = input()
            __import__(name)
        """)
        markers = _detect_dynamic_markers(tree)
        assert any("import" in m for m in markers)

    def test_dunder_getattr_in_class(self):
        tree = _parse("""\
            class Foo:
                def __getattr__(self, name):
                    pass
        """)
        markers = _detect_dynamic_markers(tree)
        assert any("__getattr__" in m for m in markers)

    def test_no_dynamic(self):
        tree = _parse("""\
            def greet(name):
                return f"hello {name}"
        """)
        markers = _detect_dynamic_markers(tree)
        assert markers == []

    def test_importlib_import_module_dynamic(self):
        """importlib.import_module with a variable arg is dynamic."""
        tree = _parse("""\
            import importlib
            mod_name = get_mod()
            importlib.import_module(mod_name)
        """)
        markers = _detect_dynamic_markers(tree)
        assert any("import" in m for m in markers)

    def test_importlib_import_module_literal_not_marked(self):
        """importlib.import_module('requests') is a static import — not dynamic."""
        tree = _parse("""\
            import importlib
            importlib.import_module('requests')
        """)
        markers = _detect_dynamic_markers(tree)
        assert not any("import" in m for m in markers)


# ===========================================================================
# parse_file
# ===========================================================================

class TestParseFile:
    def test_happy_path(self):
        path = _write_tmp("""\
            import requests
            def fetch():
                return requests.get('http://example.com')
        """)
        try:
            result = parse_file(path)
            assert result["kind"] == "parsed"
            assert any(i["specifier"] == "requests" for i in result["imports"])
            assert any(f["name"] == "fetch" for f in result["functions"])
            assert any(c["to"] == "requests.get" for c in result["calls"])
        finally:
            os.unlink(path)

    def test_syntax_error_returns_unknown(self):
        path = _write_tmp("def (:  # broken")
        try:
            result = parse_file(path)
            assert result["kind"] == "unknown"
            assert "syntax error" in result["reason"].lower()
        finally:
            os.unlink(path)

    def test_missing_file_returns_unknown(self):
        result = parse_file("/nonexistent/path/to/file.py")
        assert result["kind"] == "unknown"
        assert "read error" in result["reason"].lower()

    def test_dynamic_markers_populated(self):
        path = _write_tmp("eval('x')")
        try:
            result = parse_file(path)
            assert result["kind"] == "parsed"
            assert any("eval" in m for m in result["dynamic_markers"])
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = _write_tmp("")
        try:
            result = parse_file(path)
            assert result["kind"] == "parsed"
            assert result["imports"] == []
            assert result["functions"] == []
        finally:
            os.unlink(path)

    def test_relative_import(self):
        path = _write_tmp("from . import models")
        try:
            result = parse_file(path)
            assert result["kind"] == "parsed"
            assert any(i["specifier"] == "." for i in result["imports"])
        finally:
            os.unlink(path)


# ===========================================================================
# run_worker — end-to-end subprocess protocol
# ===========================================================================

WORKER_SCRIPT = str(PARSE_DIR / "ast_worker.py")


class TestRunWorkerProtocol:
    def _run(self, requests_lines: List[str]) -> List[dict]:
        """Spawn ast_worker.py as a subprocess, send requests, collect responses."""
        proc = subprocess.Popen(
            [sys.executable, WORKER_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        input_bytes = "\n".join(requests_lines).encode() + b"\n"
        stdout, _ = proc.communicate(input=input_bytes, timeout=15)
        lines = [l for l in stdout.decode().splitlines() if l.strip()]
        return [json.loads(l) for l in lines]

    def test_parse_valid_file(self):
        path = _write_tmp("import os\ndef greet(): pass\n")
        try:
            responses = self._run([json.dumps({"id": 1, "path": path})])
            assert len(responses) == 1
            r = responses[0]
            assert r["id"] == 1
            assert r["result"]["kind"] == "parsed"
            assert any(i["specifier"] == "os" for i in r["result"]["imports"])
        finally:
            os.unlink(path)

    def test_parse_syntax_error(self):
        path = _write_tmp("def (:")
        try:
            responses = self._run([json.dumps({"id": 2, "path": path})])
            assert len(responses) == 1
            assert responses[0]["result"]["kind"] == "unknown"
        finally:
            os.unlink(path)

    def test_parse_missing_file(self):
        responses = self._run([json.dumps({"id": 3, "path": "/no/such/file.py"})])
        assert len(responses) == 1
        assert responses[0]["result"]["kind"] == "unknown"

    def test_multiple_requests(self):
        p1 = _write_tmp("x = 1\n")
        p2 = _write_tmp("import sys\n")
        try:
            reqs = [
                json.dumps({"id": 10, "path": p1}),
                json.dumps({"id": 11, "path": p2}),
            ]
            responses = self._run(reqs)
            assert len(responses) == 2
            ids = {r["id"] for r in responses}
            assert ids == {10, 11}
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_malformed_json_request(self):
        """Malformed JSON line produces an unknown response, worker continues."""
        p = _write_tmp("x = 1\n")
        try:
            reqs = [
                "not valid json",
                json.dumps({"id": 99, "path": p}),
            ]
            responses = self._run(reqs)
            # At minimum the valid request should produce a response
            valid = [r for r in responses if r.get("id") == 99]
            assert len(valid) == 1
            assert valid[0]["result"]["kind"] == "parsed"
        finally:
            os.unlink(p)

    def test_response_ids_match_requests(self):
        p = _write_tmp("import json\n")
        try:
            responses = self._run([json.dumps({"id": 42, "path": p})])
            assert responses[0]["id"] == 42
        finally:
            os.unlink(p)

    def test_dynamic_markers_in_response(self):
        p = _write_tmp("eval('danger')\n")
        try:
            responses = self._run([json.dumps({"id": 5, "path": p})])
            result = responses[0]["result"]
            assert result["kind"] == "parsed"
            assert any("eval" in m for m in result["dynamic_markers"])
        finally:
            os.unlink(p)
