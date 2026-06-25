"""
test_extract.py — unit tests for symbols/extract.py

Run with:
    python -m pytest plugins/python-reachability/sidecar/symbols/test_extract.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Dict, List

import pytest

# ---------------------------------------------------------------------------
# Import the module under test directly (no install required).
# ---------------------------------------------------------------------------

SIDECAR_DIR = Path(__file__).parent
sys.path.insert(0, str(SIDECAR_DIR))

from extract import (  # noqa: E402
    _path_to_module,
    _parse_unified_diff,
    _extract_symbols_from_source,
    extract,
)


# ===========================================================================
# _path_to_module
# ===========================================================================

class TestPathToModule:
    def test_simple_file(self):
        assert _path_to_module("utils.py") == "utils"

    def test_nested_path(self):
        assert _path_to_module("celery/kombu/utils/encoding.py") == "celery.kombu.utils.encoding"

    def test_init_file(self):
        assert _path_to_module("src/app/__init__.py") == "src.app.__init__"

    def test_windows_separators(self):
        assert _path_to_module("celery\\kombu\\utils.py") == "celery.kombu.utils"

    def test_root_level_no_extension(self):
        # Non-.py paths: separators are still normalised to dots; .py is only
        # stripped when the path ends with ".py".  Callers filter .py files
        # before calling _path_to_module, so the output for .ts is intentionally
        # dot-separated (the function is a generic path→module converter).
        result = _path_to_module("src/utils.ts")
        assert result == "src.utils.ts"

    def test_strip_py_only(self):
        # Only .py suffix should be stripped
        result = _path_to_module("pkg/mod.py")
        assert result == "pkg.mod"


# ===========================================================================
# _parse_unified_diff
# ===========================================================================

SIMPLE_DIFF = textwrap.dedent("""\
    diff --git a/pkg/utils.py b/pkg/utils.py
    --- a/pkg/utils.py
    +++ b/pkg/utils.py
    @@ -1,3 +1,5 @@
     def old():
    -    pass
    +    return 1
    +
    +def new():
    +    pass
""")


class TestParseUnifiedDiff:
    def test_identifies_changed_file(self):
        changed = _parse_unified_diff(SIMPLE_DIFF)
        assert "pkg/utils.py" in changed

    def test_tracks_added_lines(self):
        changed = _parse_unified_diff(SIMPLE_DIFF)
        lines = changed["pkg/utils.py"]
        # Lines 2 (+return 1), 3 (blank), 4 (def new), 5 (pass) added
        assert 2 in lines
        assert 4 in lines

    def test_empty_patch_returns_empty(self):
        assert _parse_unified_diff("") == {}

    def test_strips_b_prefix_from_path(self):
        diff = "+++ b/src/main.py\n@@ -1,1 +1,2 @@\n+x = 1\n"
        changed = _parse_unified_diff(diff)
        assert "src/main.py" in changed

    def test_multi_file_diff(self):
        diff = textwrap.dedent("""\
            +++ b/a.py
            @@ -1,1 +1,2 @@
             x = 1
            +y = 2
            +++ b/b.py
            @@ -1,1 +1,2 @@
             z = 3
            +w = 4
        """)
        changed = _parse_unified_diff(diff)
        assert "a.py" in changed
        assert "b.py" in changed

    def test_only_python_files_matter_in_caller(self):
        # The diff parser itself is file-agnostic; filtering for .py is done
        # in extract().  Verify it tracks .ts files too.
        diff = "+++ b/src/app.ts\n@@ -1,1 +1,2 @@\n+const x = 1;\n"
        changed = _parse_unified_diff(diff)
        assert "src/app.ts" in changed


# ===========================================================================
# _extract_symbols_from_source
# ===========================================================================

SIMPLE_SOURCE = textwrap.dedent("""\
    def safe_decode(s):
        return s.decode("utf-8")

    async def fetch(url):
        pass

    class Encoder:
        def encode(self, s):
            return s.encode()

        async def async_encode(self, s):
            return s.encode()
""")


class TestExtractSymbolsFromSource:
    def test_function_extracted(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        names = [s["exportName"] for s in syms]
        assert "safe_decode" in names

    def test_async_function_extracted(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        kinds = {s["exportName"]: s["kind"] for s in syms}
        assert kinds["fetch"] == "async_function"

    def test_class_extracted(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        names = [s["exportName"] for s in syms]
        assert "Encoder" in names

    def test_method_extracted(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        names = [s["exportName"] for s in syms]
        assert "Encoder.encode" in names

    def test_async_method_kind(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        kinds = {s["exportName"]: s["kind"] for s in syms}
        assert kinds["Encoder.async_encode"] == "async_method"

    def test_module_field_populated(self):
        """module must be the dotted module path derived from the file path."""
        syms = _extract_symbols_from_source("celery/kombu/utils/encoding.py", SIMPLE_SOURCE, [])
        for s in syms:
            assert s["module"] == "celery.kombu.utils.encoding"

    def test_file_field_preserved(self):
        syms = _extract_symbols_from_source("pkg/utils.py", SIMPLE_SOURCE, [])
        for s in syms:
            assert s["file"] == "pkg/utils.py"

    def test_changed_lines_filter(self):
        """When changed_lines is provided only overlapping symbols are returned."""
        source = textwrap.dedent("""\
            def func_a():  # line 1
                pass       # line 2

            def func_b():  # line 4
                pass       # line 5
        """)
        # Only line 4-5 changed → only func_b
        syms = _extract_symbols_from_source("m.py", source, [4, 5])
        names = [s["exportName"] for s in syms]
        assert "func_b" in names
        assert "func_a" not in names

    def test_empty_changed_lines_includes_all(self):
        """Empty changed_lines means the whole file is changed."""
        syms = _extract_symbols_from_source("m.py", SIMPLE_SOURCE, [])
        assert len(syms) >= 4  # safe_decode, fetch, Encoder, Encoder.encode, Encoder.async_encode

    def test_syntax_error_returns_empty(self):
        syms = _extract_symbols_from_source("bad.py", "def (:", [])
        assert syms == []

    def test_empty_source_returns_empty(self):
        syms = _extract_symbols_from_source("empty.py", "", [])
        assert syms == []


# ===========================================================================
# extract() — integration
# ===========================================================================

PATCH_WITH_ENCODING = textwrap.dedent("""\
    diff --git a/celery/kombu/utils/encoding.py b/celery/kombu/utils/encoding.py
    --- a/celery/kombu/utils/encoding.py
    +++ b/celery/kombu/utils/encoding.py
    @@ -1,3 +1,5 @@
     # encoding helpers
    -def safe_decode(s):
    -    pass
    +def safe_decode(s):
    +    return s.decode('utf-8', errors='replace')
""")

ENCODING_CONTENT = textwrap.dedent("""\
    # encoding helpers
    def safe_decode(s):
        return s.decode('utf-8', errors='replace')
""")


class TestExtract:
    def test_basic_extraction(self):
        req = {
            "patch": PATCH_WITH_ENCODING,
            "files": [
                {
                    "path": "celery/kombu/utils/encoding.py",
                    "content": ENCODING_CONTENT,
                }
            ],
        }
        result = extract(req)
        assert isinstance(result, list)
        assert len(result) >= 1
        sym = result[0]
        assert sym["exportName"] == "safe_decode"
        assert sym["module"] == "celery.kombu.utils.encoding"
        assert sym["file"] == "celery/kombu/utils/encoding.py"
        assert sym["kind"] == "function"

    def test_module_field_present_in_every_symbol(self):
        req = {
            "patch": PATCH_WITH_ENCODING,
            "files": [{"path": "celery/kombu/utils/encoding.py", "content": ENCODING_CONTENT}],
        }
        for sym in extract(req):
            assert "module" in sym, f"symbol missing 'module': {sym}"

    def test_non_python_files_ignored(self):
        """Diff that touches a .ts file should produce no symbols."""
        diff = "+++ b/src/app.ts\n@@ -1,1 +1,2 @@\n+const x = 1;\n"
        req = {
            "patch": diff,
            "files": [{"path": "src/app.ts", "content": "const x = 1;"}],
        }
        result = extract(req)
        assert result == []

    def test_empty_patch_uses_all_files(self):
        """No patch → treat every .py file as fully changed."""
        req = {
            "patch": "",
            "files": [{"path": "utils.py", "content": "def foo(): pass\n"}],
        }
        result = extract(req)
        assert any(s["exportName"] == "foo" for s in result)

    def test_empty_request_returns_empty_list(self):
        result = extract({})
        assert result == []

    def test_file_not_in_diff_skipped(self):
        """A file provided in 'files' but absent from the diff is skipped."""
        req = {
            "patch": PATCH_WITH_ENCODING,
            "files": [
                {"path": "other.py", "content": "def bar(): pass\n"},
            ],
        }
        result = extract(req)
        # 'other.py' not in diff; encoding.py content not provided
        assert result == []

    def test_invalid_json_stdin_returns_empty(self):
        """Simulate bad stdin by calling main() via subprocess."""
        script = str(SIDECAR_DIR / "extract.py")
        proc = subprocess.run(
            [sys.executable, script],
            input=b"not json",
            capture_output=True,
        )
        assert proc.returncode == 0
        assert json.loads(proc.stdout.strip()) == []

    def test_valid_stdin_protocol(self):
        """End-to-end: send JSON via stdin, receive JSON from stdout."""
        req = {
            "patch": PATCH_WITH_ENCODING,
            "files": [{"path": "celery/kombu/utils/encoding.py", "content": ENCODING_CONTENT}],
        }
        script = str(SIDECAR_DIR / "extract.py")
        proc = subprocess.run(
            [sys.executable, script],
            input=json.dumps(req).encode(),
            capture_output=True,
        )
        assert proc.returncode == 0
        result = json.loads(proc.stdout.strip())
        assert isinstance(result, list)
        assert len(result) >= 1
        assert result[0]["module"] == "celery.kombu.utils.encoding"

    def test_multi_file_patch(self):
        """A diff touching two .py files produces symbols from both."""
        diff = textwrap.dedent("""\
            +++ b/pkg/a.py
            @@ -1,1 +1,2 @@
             x = 1
            +def func_a(): pass
            +++ b/pkg/b.py
            @@ -1,1 +1,2 @@
             y = 2
            +def func_b(): pass
        """)
        req = {
            "patch": diff,
            "files": [
                {"path": "pkg/a.py", "content": "x = 1\ndef func_a(): pass\n"},
                {"path": "pkg/b.py", "content": "y = 2\ndef func_b(): pass\n"},
            ],
        }
        result = extract(req)
        names = [s["exportName"] for s in result]
        assert "func_a" in names
        assert "func_b" in names

    def test_class_method_module_qualified(self):
        """Class methods carry the same module as top-level functions."""
        source = "class Foo:\n    def bar(self): pass\n"
        req = {
            "patch": "",
            "files": [{"path": "pkg/foo.py", "content": source}],
        }
        result = extract(req)
        method = next((s for s in result if s["exportName"] == "Foo.bar"), None)
        assert method is not None
        assert method["module"] == "pkg.foo"
