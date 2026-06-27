"""
Tests for dist_import_map.py

Spec: Map PyPI dist -> import module(s).
Provenance tags: importlib | curated | heuristic.
Hard invariants:
  - heuristic-mapped "not imported" -> UNKNOWN (never NOT_REACHABLE)
  - ambiguity -> UNKNOWN
  - importlib.metadata result supersedes curated/heuristic for installed dists
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from dist_import_map import (
    CURATED_MAP,
    Provenance,
    ResolvedImports,
    dist_to_imports,
    resolve_dist_imports,
)


class TestProvenance(unittest.TestCase):
    def test_provenance_values(self):
        self.assertEqual(Provenance.IMPORTLIB, "importlib")
        self.assertEqual(Provenance.CURATED, "curated")
        self.assertEqual(Provenance.HEURISTIC, "heuristic")


class TestResolvedImports(unittest.TestCase):
    def test_fields_present(self):
        r = ResolvedImports(
            dist_name="requests",
            imports=["requests"],
            provenance=Provenance.IMPORTLIB,
            ambiguous=False,
        )
        self.assertEqual(r.dist_name, "requests")
        self.assertEqual(r.imports, ["requests"])
        self.assertEqual(r.provenance, Provenance.IMPORTLIB)
        self.assertFalse(r.ambiguous)

    def test_is_unknown_heuristic_no_imports(self):
        """Heuristic provenance with empty imports -> UNKNOWN signal."""
        r = ResolvedImports(
            dist_name="some-pkg",
            imports=[],
            provenance=Provenance.HEURISTIC,
            ambiguous=False,
        )
        self.assertTrue(r.is_unknown)

    def test_is_unknown_ambiguous(self):
        """Ambiguity always yields UNKNOWN."""
        r = ResolvedImports(
            dist_name="ambig-pkg",
            imports=["a", "b"],
            provenance=Provenance.CURATED,
            ambiguous=True,
        )
        self.assertTrue(r.is_unknown)

    def test_not_unknown_importlib_single(self):
        r = ResolvedImports(
            dist_name="requests",
            imports=["requests"],
            provenance=Provenance.IMPORTLIB,
            ambiguous=False,
        )
        self.assertFalse(r.is_unknown)

    def test_not_unknown_curated_single(self):
        r = ResolvedImports(
            dist_name="PyYAML",
            imports=["yaml"],
            provenance=Provenance.CURATED,
            ambiguous=False,
        )
        self.assertFalse(r.is_unknown)

    def test_heuristic_with_imports_is_unknown(self):
        """ANY heuristic result is UNKNOWN regardless of imports content.

        Plan invariant: a HEURISTIC mapping is a guess. Even when the
        heuristic produces a non-empty imports list, the caller cannot use
        a 'not imported' conclusion to emit NOT_REACHABLE — the mapping may
        be wrong. is_unknown must be True for all HEURISTIC provenance.
        """
        r = ResolvedImports(
            dist_name="mylib",
            imports=["mylib"],
            provenance=Provenance.HEURISTIC,
            ambiguous=False,
        )
        self.assertTrue(r.is_unknown)


class TestCuratedMap(unittest.TestCase):
    def test_pyyaml_maps_to_yaml(self):
        self.assertIn("pyyaml", CURATED_MAP)
        self.assertEqual(CURATED_MAP["pyyaml"], ["yaml"])

    def test_beautifulsoup4_maps_to_bs4(self):
        self.assertIn("beautifulsoup4", CURATED_MAP)
        self.assertEqual(CURATED_MAP["beautifulsoup4"], ["bs4"])

    def test_pillow_maps_to_pil(self):
        self.assertIn("pillow", CURATED_MAP)
        self.assertEqual(CURATED_MAP["pillow"], ["PIL"])

    def test_scikit_learn_maps_to_sklearn(self):
        self.assertIn("scikit-learn", CURATED_MAP)
        self.assertEqual(CURATED_MAP["scikit-learn"], ["sklearn"])

    def test_opencv_python_maps_to_cv2(self):
        self.assertIn("opencv-python", CURATED_MAP)
        self.assertEqual(CURATED_MAP["opencv-python"], ["cv2"])

    def test_pyjwt_maps_to_jwt(self):
        self.assertIn("pyjwt", CURATED_MAP)
        self.assertEqual(CURATED_MAP["pyjwt"], ["jwt"])

    def test_python_dateutil_maps_to_dateutil(self):
        self.assertIn("python-dateutil", CURATED_MAP)
        self.assertEqual(CURATED_MAP["python-dateutil"], ["dateutil"])

    def test_keys_are_lowercase(self):
        """All curated map keys must be lowercase (canonical lookup form)."""
        for key in CURATED_MAP:
            self.assertEqual(key, key.lower(), f"Key {key!r} is not lowercase")


class TestDistToImports(unittest.TestCase):
    """Unit tests for dist_to_imports() which queries importlib.metadata."""

    def _make_fake_dist(self, top_level_txt=None, record=None):
        dist = MagicMock()
        dist.read_text = MagicMock(side_effect=lambda name: {
            "top_level.txt": top_level_txt,
            "RECORD": record,
        }.get(name))
        return dist

    @patch("dist_import_map._importlib_distribution")
    def test_uses_top_level_txt(self, mock_dist_fn):
        dist = self._make_fake_dist(top_level_txt="requests\n")
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("requests")
        self.assertEqual(imports, ["requests"])

    @patch("dist_import_map._importlib_distribution")
    def test_top_level_txt_multiline(self, mock_dist_fn):
        dist = self._make_fake_dist(top_level_txt="pkg\nother_pkg\n")
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("some-dist")
        self.assertIn("pkg", imports)
        self.assertIn("other_pkg", imports)

    @patch("dist_import_map._importlib_distribution")
    def test_falls_back_to_record(self, mock_dist_fn):
        record = (
            "mypackage/__init__.py,sha256=abc,100\n"
            "mypackage/utils.py,sha256=def,200\n"
            "mypackage-1.0.dist-info/RECORD,,\n"
        )
        dist = self._make_fake_dist(top_level_txt=None, record=record)
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("mypackage")
        self.assertIn("mypackage", imports)

    @patch("dist_import_map._importlib_distribution")
    def test_record_filters_dist_info(self, mock_dist_fn):
        """RECORD entries with .dist-info or .data should not become import roots."""
        record = (
            "requests/__init__.py,sha256=abc,100\n"
            "requests-2.28.0.dist-info/RECORD,,\n"
            "requests-2.28.0.data/scripts/httpx,,\n"
        )
        dist = self._make_fake_dist(top_level_txt=None, record=record)
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("requests")
        self.assertIn("requests", imports)
        self.assertNotIn("requests-2.28.0.dist-info", imports)
        self.assertNotIn("requests-2.28.0.data", imports)

    @patch("dist_import_map._importlib_distribution")
    def test_dist_not_found_returns_empty(self, mock_dist_fn):
        """If importlib.metadata cannot find the dist, return empty list."""
        mock_dist_fn.side_effect = Exception("not found")

        imports = dist_to_imports("unknown-package")
        self.assertEqual(imports, [])

    @patch("dist_import_map._importlib_distribution")
    def test_empty_top_level_falls_to_record(self, mock_dist_fn):
        """Empty top_level.txt should fall through to RECORD."""
        record = "mypkg/__init__.py,sha256=abc,100\n"
        dist = self._make_fake_dist(top_level_txt="", record=record)
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("mypkg")
        self.assertIn("mypkg", imports)

    @patch("dist_import_map._importlib_distribution")
    def test_whitespace_only_top_level_falls_to_record(self, mock_dist_fn):
        record = "mypkg/__init__.py,sha256=abc,100\n"
        dist = self._make_fake_dist(top_level_txt="   \n\n  ", record=record)
        mock_dist_fn.return_value = dist

        imports = dist_to_imports("mypkg")
        self.assertIn("mypkg", imports)


class TestResolveDistImports(unittest.TestCase):
    """
    Integration tests for resolve_dist_imports() — the main entry point.
    Exercises the provenance cascade:
      importlib (if dist found in venv) > curated > heuristic
    """

    @patch("dist_import_map._importlib_distribution")
    def test_importlib_provenance_when_installed(self, mock_dist_fn):
        dist = MagicMock()
        dist.read_text = MagicMock(return_value="requests\n")
        mock_dist_fn.return_value = dist

        result = resolve_dist_imports("requests", venv_available=True)
        self.assertEqual(result.provenance, Provenance.IMPORTLIB)
        self.assertEqual(result.imports, ["requests"])
        self.assertFalse(result.ambiguous)
        self.assertFalse(result.is_unknown)

    @patch("dist_import_map._importlib_distribution")
    def test_curated_provenance_no_venv(self, mock_dist_fn):
        """Without a venv, importlib is skipped; curated fallback used."""
        result = resolve_dist_imports("pyyaml", venv_available=False)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertEqual(result.imports, ["yaml"])
        self.assertFalse(result.ambiguous)
        self.assertFalse(result.is_unknown)
        mock_dist_fn.assert_not_called()

    @patch("dist_import_map._importlib_distribution")
    def test_curated_provenance_importlib_miss(self, mock_dist_fn):
        """importlib fails -> fall through to curated, marks incomplete.

        When venv_available=True but importlib misses the dist, the curated
        fallback is a degraded result: incomplete=True, is_unknown=True.
        Callers must treat this as UNKNOWN (cannot emit NOT_REACHABLE).
        """
        mock_dist_fn.side_effect = Exception("not found")

        result = resolve_dist_imports("beautifulsoup4", venv_available=True)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertEqual(result.imports, ["bs4"])
        self.assertTrue(result.incomplete, "importlib miss must set incomplete=True")
        self.assertTrue(
            result.is_unknown,
            "incomplete curated result must be is_unknown=True",
        )

    @patch("dist_import_map._importlib_distribution")
    def test_heuristic_provenance_unknown_package(self, mock_dist_fn):
        """Unknown package (not in curated, importlib fails) -> heuristic."""
        mock_dist_fn.side_effect = Exception("not found")

        result = resolve_dist_imports("my-custom-lib", venv_available=True)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        # Heuristic: lowercase + strip hyphens/underscores
        self.assertIn("my_custom_lib", result.imports)

    @patch("dist_import_map._importlib_distribution")
    def test_heuristic_no_venv_unknown_package(self, mock_dist_fn):
        result = resolve_dist_imports("some-obscure-pkg", venv_available=False)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        mock_dist_fn.assert_not_called()

    @patch("dist_import_map._importlib_distribution")
    def test_pyyaml_canonical_dist_name(self, mock_dist_fn):
        """PyYAML (mixed case dist name) should match curated via lowercasing."""
        result = resolve_dist_imports("PyYAML", venv_available=False)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertEqual(result.imports, ["yaml"])

    @patch("dist_import_map._importlib_distribution")
    def test_importlib_supersedes_curated(self, mock_dist_fn):
        """
        Even if curated says X, if importlib returns Y, importlib wins.
        Example: a fork of PyYAML that installs as 'cyaml' module.
        """
        dist = MagicMock()
        dist.read_text = MagicMock(return_value="cyaml\n")
        mock_dist_fn.return_value = dist

        result = resolve_dist_imports("pyyaml", venv_available=True)
        self.assertEqual(result.provenance, Provenance.IMPORTLIB)
        self.assertEqual(result.imports, ["cyaml"])

    # --- Hard invariant: heuristic "not imported" -> UNKNOWN ---

    @patch("dist_import_map._importlib_distribution")
    def test_heuristic_result_is_always_unknown(self, mock_dist_fn):
        """
        Core soundness invariant: a HEURISTIC result with a non-empty guessed
        imports list MUST yield is_unknown=True. A caller that checks
        'module not found in import closure' must emit UNKNOWN, never
        NOT_REACHABLE, when the mapping is heuristic — even if the heuristic
        produced a plausible guess. The false-NOT_REACHABLE path is forbidden.
        """
        mock_dist_fn.side_effect = Exception("not found")
        result = resolve_dist_imports("unknown-pkg", venv_available=True)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        # Heuristic produces a non-empty imports list (lowercase normalisation)
        self.assertTrue(len(result.imports) > 0, "expected a heuristic guess")
        # is_unknown MUST be True — cannot use this to prove NOT_REACHABLE
        self.assertTrue(
            result.is_unknown,
            "HEURISTIC result with imports must be is_unknown=True; "
            "a caller trusting is_unknown==False for heuristic would emit a "
            "false NOT_REACHABLE (plan invariant violation)",
        )

    @patch("dist_import_map._importlib_distribution")
    def test_heuristic_empty_imports_is_unknown(self, mock_dist_fn):
        """If heuristic produces no imports at all, is_unknown=True."""
        mock_dist_fn.side_effect = Exception("not found")
        # Patch heuristic to produce empty list (simulates edge case)
        with patch("dist_import_map._heuristic_imports", return_value=[]):
            result = resolve_dist_imports("weird-pkg", venv_available=True)
        self.assertTrue(result.is_unknown)

    # --- Ambiguity -> UNKNOWN ---

    @patch("dist_import_map._importlib_distribution")
    def test_ambiguous_importlib_multi_top_level(self, mock_dist_fn):
        """
        A dist with multiple top-level names is NOT ambiguous by itself;
        ambiguity only arises when it's unclear WHICH top-level maps to
        which advisory module. By default, multiple names are OK.
        This test ensures we return all names and mark ambiguous=False.
        """
        dist = MagicMock()
        dist.read_text = MagicMock(return_value="pkg_a\npkg_b\n")
        mock_dist_fn.return_value = dist

        result = resolve_dist_imports("multi-pkg", venv_available=True)
        self.assertEqual(result.provenance, Provenance.IMPORTLIB)
        self.assertIn("pkg_a", result.imports)
        self.assertIn("pkg_b", result.imports)
        # Multiple names -> ambiguous (caller cannot safely pick one for NOT_REACHABLE)
        self.assertTrue(result.ambiguous)
        self.assertTrue(result.is_unknown)

    @patch("dist_import_map._importlib_distribution")
    def test_single_importlib_not_ambiguous(self, mock_dist_fn):
        dist = MagicMock()
        dist.read_text = MagicMock(return_value="requests\n")
        mock_dist_fn.return_value = dist

        result = resolve_dist_imports("requests", venv_available=True)
        self.assertFalse(result.ambiguous)
        self.assertFalse(result.is_unknown)

    # --- Curated aliases ---

    def test_pillow_alias(self):
        result = resolve_dist_imports("Pillow", venv_available=False)
        self.assertEqual(result.imports, ["PIL"])
        self.assertEqual(result.provenance, Provenance.CURATED)

    def test_scikit_learn_alias(self):
        result = resolve_dist_imports("scikit-learn", venv_available=False)
        self.assertEqual(result.imports, ["sklearn"])
        self.assertEqual(result.provenance, Provenance.CURATED)

    def test_opencv_alias(self):
        result = resolve_dist_imports("opencv-python", venv_available=False)
        self.assertEqual(result.imports, ["cv2"])
        self.assertEqual(result.provenance, Provenance.CURATED)

    def test_pyjwt_alias(self):
        result = resolve_dist_imports("pyjwt", venv_available=False)
        self.assertEqual(result.imports, ["jwt"])
        self.assertEqual(result.provenance, Provenance.CURATED)

    def test_python_dateutil_alias(self):
        result = resolve_dist_imports("python-dateutil", venv_available=False)
        self.assertEqual(result.imports, ["dateutil"])
        self.assertEqual(result.provenance, Provenance.CURATED)

    def test_protobuf_alias(self):
        result = resolve_dist_imports("protobuf", venv_available=False)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertIn("google.protobuf", result.imports)

    # --- Heuristic normalization ---

    def test_heuristic_hyphen_to_underscore(self):
        result = resolve_dist_imports("my-package", venv_available=False)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        self.assertIn("my_package", result.imports)

    def test_heuristic_lowercase(self):
        result = resolve_dist_imports("MyPackage", venv_available=False)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        self.assertIn("mypackage", result.imports)

    def test_heuristic_mixed_case_hyphen(self):
        result = resolve_dist_imports("My-Package", venv_available=False)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        self.assertIn("my_package", result.imports)


class TestIncompleteFlag(unittest.TestCase):
    """
    Verify that incomplete=True is set when importlib was available but missed
    the dist, and that incomplete=True implies is_unknown=True.
    """

    @patch("dist_import_map._importlib_distribution")
    def test_importlib_miss_curated_fallback_is_incomplete(self, mock_dist_fn):
        """
        venv_available=True but importlib misses the dist -> curated fallback.
        Result must carry incomplete=True so callers treat it as UNKNOWN.
        """
        mock_dist_fn.side_effect = Exception("not installed")
        result = resolve_dist_imports("pyyaml", venv_available=True)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertTrue(
            result.incomplete,
            "curated fallback after importlib miss must set incomplete=True",
        )
        self.assertTrue(
            result.is_unknown,
            "incomplete curated result must be is_unknown=True",
        )

    @patch("dist_import_map._importlib_distribution")
    def test_importlib_miss_heuristic_fallback_is_incomplete(self, mock_dist_fn):
        """
        venv_available=True but importlib misses an unknown dist -> heuristic.
        Result must carry incomplete=True.
        """
        mock_dist_fn.side_effect = Exception("not installed")
        result = resolve_dist_imports("my-custom-lib", venv_available=True)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        self.assertTrue(result.incomplete)
        self.assertTrue(result.is_unknown)

    def test_no_venv_curated_not_incomplete(self):
        """
        No venv: importlib is not attempted, so the curated result is expected
        (not a degradation); incomplete must be False.
        """
        result = resolve_dist_imports("pyyaml", venv_available=False)
        self.assertEqual(result.provenance, Provenance.CURATED)
        self.assertFalse(result.incomplete)

    def test_no_venv_heuristic_not_incomplete(self):
        """
        No venv: importlib is not attempted; heuristic result is expected
        (not a degradation); incomplete must be False.
        """
        result = resolve_dist_imports("my-custom-lib", venv_available=False)
        self.assertEqual(result.provenance, Provenance.HEURISTIC)
        self.assertFalse(result.incomplete)
        # Still is_unknown because HEURISTIC
        self.assertTrue(result.is_unknown)

    @patch("dist_import_map._importlib_distribution")
    def test_importlib_hit_is_not_incomplete(self, mock_dist_fn):
        """
        Importlib succeeds: no degradation, incomplete must be False.
        """
        dist = MagicMock()
        dist.read_text = MagicMock(return_value="requests\n")
        mock_dist_fn.return_value = dist

        result = resolve_dist_imports("requests", venv_available=True)
        self.assertEqual(result.provenance, Provenance.IMPORTLIB)
        self.assertFalse(result.incomplete)
        self.assertFalse(result.is_unknown)

    def test_incomplete_true_implies_is_unknown(self):
        """
        Direct construction: incomplete=True on any result yields is_unknown=True
        regardless of provenance.
        """
        r = ResolvedImports(
            dist_name="some-pkg",
            imports=["some_pkg"],
            provenance=Provenance.CURATED,
            ambiguous=False,
            incomplete=True,
        )
        self.assertTrue(r.is_unknown)


class TestBatchResolve(unittest.TestCase):
    """Test resolve_many for batch usage."""

    @patch("dist_import_map._importlib_distribution")
    def test_batch_resolve(self, mock_dist_fn):
        from dist_import_map import resolve_many

        mock_dist_fn.side_effect = Exception("not found")

        results = resolve_many(
            ["pyyaml", "beautifulsoup4", "unknown-pkg"],
            venv_available=False,
        )
        self.assertEqual(len(results), 3)
        self.assertEqual(results["pyyaml"].provenance, Provenance.CURATED)
        self.assertEqual(results["beautifulsoup4"].provenance, Provenance.CURATED)
        self.assertEqual(results["unknown-pkg"].provenance, Provenance.HEURISTIC)

    @patch("dist_import_map._importlib_distribution")
    def test_batch_resolve_venv(self, mock_dist_fn):
        from dist_import_map import resolve_many

        dist = MagicMock()
        dist.read_text = MagicMock(return_value="requests\n")
        mock_dist_fn.return_value = dist

        results = resolve_many(["requests"], venv_available=True)
        self.assertEqual(results["requests"].provenance, Provenance.IMPORTLIB)


if __name__ == "__main__":
    unittest.main()
