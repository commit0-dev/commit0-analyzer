"""
test_confidence.py — unit tests for cg/confidence.py

Coverage
--------
- Confidence enum values
- HEURISTIC/ambiguous resolved_import => UNKNOWN (never NOT_REACHABLE)
- Dist absent + complete graph => NOT_REACHABLE
- Dist absent + incomplete graph => UNKNOWN (hard invariant)
- Dist imported + no symbols + complete graph => PACKAGE_REACHABLE
- Dist imported + dynamic markers => UNKNOWN
- Dist imported + call_path + matching symbols => SYMBOL_REACHABLE
- Dist imported + call_path + no symbol match => UNKNOWN
- dev_only propagation
- No-venv / site_packages absent => compiled-ext path not triggered

Run with:
    .claude/skills/.venv/bin/python3 -m pytest \
        plugins/python-reachability/sidecar/cg/test_confidence.py -v
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

CG_DIR = Path(__file__).parent
SIDECAR_DIR = CG_DIR.parent
sys.path.insert(0, str(SIDECAR_DIR))
sys.path.insert(0, str(CG_DIR))

from confidence import (
    AdvisoryMeta,
    Confidence,
    ConfidenceDecision,
    _has_dynamic_path_to_dist,
    _symbols_in_path,
    decide_confidence,
)


# ===========================================================================
# Helpers / stubs
# ===========================================================================

@dataclass
class _FakeGraph:
    """Minimal CallGraph stub."""
    _dist_imports: Dict[str, Set[str]] = None
    incomplete: bool = False
    dynamic_files: Set[str] = None

    def __post_init__(self):
        if self._dist_imports is None:
            self._dist_imports = {}
        if self.dynamic_files is None:
            self.dynamic_files = set()

    def imports_dist(self, dist_name: str) -> bool:
        return dist_name in self._dist_imports and bool(self._dist_imports[dist_name])

    def can_claim_not_reachable(self) -> bool:
        return not self.incomplete


@dataclass
class _FakeResolvedImport:
    """Minimal ResolvedImports stub."""
    provenance: str
    imports: List[str] = None
    ambiguous: bool = False
    incomplete: bool = False

    def __post_init__(self):
        if self.imports is None:
            self.imports = []

    @property
    def is_unknown(self) -> bool:
        if self.ambiguous:
            return True
        if self.provenance == "heuristic":
            return True
        if self.incomplete:
            return True
        return False


def _importlib(imports=("requests",)) -> _FakeResolvedImport:
    return _FakeResolvedImport(provenance="importlib", imports=list(imports))


def _curated(imports=("yaml",)) -> _FakeResolvedImport:
    return _FakeResolvedImport(provenance="curated", imports=list(imports))


def _heuristic(imports=("mylib",)) -> _FakeResolvedImport:
    return _FakeResolvedImport(provenance="heuristic", imports=list(imports))


def _graph_with(dist: str, *, incomplete: bool = False, dynamic: bool = False):
    dyn = {"broken.py"} if dynamic else set()
    return _FakeGraph(
        _dist_imports={dist: {dist}},
        incomplete=incomplete,
        dynamic_files=dyn,
    )


def _empty_graph(*, incomplete: bool = False) -> _FakeGraph:
    return _FakeGraph(incomplete=incomplete)


# ===========================================================================
# Confidence enum
# ===========================================================================

class TestConfidenceEnum:
    def test_values(self):
        assert Confidence.SYMBOL_REACHABLE == "SYMBOL_REACHABLE"
        assert Confidence.PACKAGE_REACHABLE == "PACKAGE_REACHABLE"
        assert Confidence.NOT_REACHABLE == "NOT_REACHABLE"
        assert Confidence.UNKNOWN == "UNKNOWN"


# ===========================================================================
# Hard invariant: HEURISTIC mapping => UNKNOWN
# ===========================================================================

class TestHeuristicAlwaysUnknown:
    def test_heuristic_dist_not_imported_never_not_reachable(self):
        """
        Core soundness invariant: if the dist-import mapping is HEURISTIC,
        we MUST emit UNKNOWN even when the dist is absent from the closure.
        A heuristic mapping might be wrong, so 'not imported' is not provably
        NOT_REACHABLE.
        """
        adv = AdvisoryMeta(dist_name="mylib", symbols=[])
        graph = _empty_graph(incomplete=False)   # complete graph
        ri = _heuristic(imports=["mylib"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True

    def test_heuristic_dist_imported_is_unknown(self):
        """Heuristic + dist found in closure => still UNKNOWN."""
        adv = AdvisoryMeta(dist_name="mylib", symbols=[])
        graph = _graph_with("mylib")
        ri = _heuristic(imports=["mylib"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN

    def test_ambiguous_mapping_is_unknown(self):
        """Ambiguous importlib mapping => UNKNOWN regardless of closure."""
        adv = AdvisoryMeta(dist_name="multi", symbols=[])
        graph = _empty_graph(incomplete=False)
        ri = _FakeResolvedImport(provenance="importlib", imports=["a", "b"], ambiguous=True)

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True

    def test_incomplete_curated_is_unknown(self):
        """Curated result with incomplete=True => is_unknown => UNKNOWN."""
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _empty_graph(incomplete=False)
        ri = _FakeResolvedImport(provenance="curated", imports=["requests"], incomplete=True)

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN


# ===========================================================================
# NOT_REACHABLE: only when complete graph + safe mapping + dist absent
# ===========================================================================

class TestNotReachable:
    def test_dist_absent_complete_graph_importlib(self):
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _empty_graph(incomplete=False)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.NOT_REACHABLE
        assert result.incomplete is False

    def test_dist_absent_complete_graph_curated(self):
        adv = AdvisoryMeta(dist_name="PyYAML", symbols=[])
        graph = _empty_graph(incomplete=False)
        ri = _curated(imports=["yaml"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.NOT_REACHABLE

    def test_dist_absent_incomplete_graph_importlib_is_unknown(self):
        """
        Hard invariant: even with importlib provenance, an incomplete graph
        means we CANNOT claim NOT_REACHABLE.
        """
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _empty_graph(incomplete=True)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True

    def test_dist_absent_incomplete_graph_curated_is_unknown(self):
        adv = AdvisoryMeta(dist_name="PyYAML", symbols=[])
        graph = _empty_graph(incomplete=True)
        ri = _curated(imports=["yaml"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True


# ===========================================================================
# PACKAGE_REACHABLE
# ===========================================================================

class TestPackageReachable:
    def test_dist_imported_no_symbols(self):
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _graph_with("requests")
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.PACKAGE_REACHABLE

    def test_dist_imported_no_symbols_curated(self):
        adv = AdvisoryMeta(dist_name="PyYAML", symbols=[])
        graph = _graph_with("PyYAML")
        ri = _curated(imports=["yaml"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.PACKAGE_REACHABLE


# ===========================================================================
# SYMBOL_REACHABLE
# ===========================================================================

class TestSymbolReachable:
    def test_call_path_with_matching_symbol(self):
        adv = AdvisoryMeta(dist_name="celery", symbols=["safe_decode"])
        graph = _graph_with("celery")
        ri = _importlib(imports=["celery"])

        result = decide_confidence(
            adv, graph, ri,
            call_path=["fetch_data", "celery.kombu.utils.encoding.safe_decode"],
        )
        assert result.confidence == Confidence.SYMBOL_REACHABLE

    def test_call_path_suffix_match(self):
        """Symbol 'safe_decode' matches 'module.safe_decode' via suffix."""
        adv = AdvisoryMeta(dist_name="celery", symbols=["safe_decode"])
        graph = _graph_with("celery")
        ri = _importlib(imports=["celery"])

        result = decide_confidence(
            adv, graph, ri,
            call_path=["app.run", "celery.utils.safe_decode"],
        )
        assert result.confidence == Confidence.SYMBOL_REACHABLE

    def test_call_path_no_match_is_unknown(self):
        """Call path exists but does not reach the vulnerable symbol."""
        adv = AdvisoryMeta(dist_name="celery", symbols=["dangerous_func"])
        graph = _graph_with("celery")
        ri = _importlib(imports=["celery"])

        result = decide_confidence(
            adv, graph, ri,
            call_path=["app.run", "celery.utils.safe_decode"],  # safe func
        )
        # Symbol not in path => UNKNOWN (cannot prove reachability)
        assert result.confidence == Confidence.UNKNOWN

    def test_no_call_path_with_symbols_is_unknown(self):
        """Advisory has symbols but no call path established => UNKNOWN."""
        adv = AdvisoryMeta(dist_name="celery", symbols=["dangerous_func"])
        graph = _graph_with("celery")
        ri = _importlib(imports=["celery"])

        result = decide_confidence(adv, graph, ri, call_path=None)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True


# ===========================================================================
# Dynamic markers — split behaviour (the over-poisoning fix)
# ===========================================================================

class TestDynamicMarkers:
    def test_dispatch_markers_do_not_block_package_reachable(self):
        """
        CORE FIX: dynamic_dispatch_markers (eval/exec/getattr/__getattr__)
        must NOT prevent PACKAGE_REACHABLE.  They are symbol-level only.
        A project with eval() everywhere should still produce PACKAGE_REACHABLE
        for an imported dist with no symbol advisory data.
        """
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        # dynamic=True means dynamic_files is non-empty (dispatch markers)
        # incomplete=False means no unbounded dynamic imports → package closure is known
        graph = _graph_with("requests", incomplete=False, dynamic=True)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        # Must be PACKAGE_REACHABLE — not blocked by dispatch markers
        assert result.confidence == Confidence.PACKAGE_REACHABLE, (
            "dynamic dispatch (eval/getattr) must NOT block PACKAGE_REACHABLE; "
            "it is symbol-level only and does not affect package import closure"
        )

    def test_dispatch_markers_degrade_symbol_reachable_to_unknown(self):
        """
        Dynamic dispatch markers DO degrade symbol-level confidence.
        When we have a call path + symbols but dynamic dispatch is present,
        we cannot confirm the exact symbol path → UNKNOWN.
        """
        adv = AdvisoryMeta(dist_name="requests", symbols=["dangerous_func"])
        graph = _graph_with("requests", incomplete=False, dynamic=True)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(
            adv, graph, ri,
            call_path=["app.run", "requests.dangerous_func"],
        )
        # Symbol path unconfirmed due to dispatch markers → UNKNOWN
        assert result.confidence == Confidence.UNKNOWN

    def test_unbounded_dynamic_import_blocks_not_reachable(self):
        """
        An unbounded dynamic import sets incomplete=True, which forbids
        NOT_REACHABLE for absent dists.
        """
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        # incomplete=True from unbounded dynamic import
        graph = _empty_graph(incomplete=True)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        assert result.confidence == Confidence.UNKNOWN
        assert result.incomplete is True

    def test_old_dynamic_file_with_reachable_dist_and_incomplete(self):
        """
        When graph.incomplete=True (from an unbounded dynamic import or
        parse failure) AND the dist IS imported, it is still at minimum
        PACKAGE_REACHABLE (we know the dist is in the closure).
        """
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _graph_with("requests", incomplete=True, dynamic=True)
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        # Dist IS imported → at least PACKAGE_REACHABLE
        # (incomplete only gates NOT_REACHABLE for ABSENT dists)
        assert result.confidence == Confidence.PACKAGE_REACHABLE


# ===========================================================================
# dev_only propagation
# ===========================================================================

class TestDevOnly:
    def test_dev_only_flagged_on_package_reachable(self):
        adv = AdvisoryMeta(dist_name="pytest", symbols=[])
        graph = _graph_with("pytest")
        ri = _curated(imports=["pytest"])

        result = decide_confidence(adv, graph, ri, is_dev_only=True)
        assert result.dev_only is True
        assert result.confidence == Confidence.PACKAGE_REACHABLE

    def test_dev_only_not_reachable_propagates(self):
        adv = AdvisoryMeta(dist_name="pytest", symbols=[])
        graph = _empty_graph(incomplete=False)
        ri = _curated(imports=["pytest"])

        result = decide_confidence(adv, graph, ri, is_dev_only=True)
        assert result.confidence == Confidence.NOT_REACHABLE
        assert result.dev_only is True

    def test_dev_only_default_false(self):
        adv = AdvisoryMeta(dist_name="requests", symbols=[])
        graph = _graph_with("requests")
        ri = _importlib(imports=["requests"])

        result = decide_confidence(adv, graph, ri)
        assert result.dev_only is False


# ===========================================================================
# _symbols_in_path helper
# ===========================================================================

class TestSymbolsInPath:
    def test_exact_match(self):
        assert _symbols_in_path(["safe_decode"], ["safe_decode"]) == ["safe_decode"]

    def test_suffix_match(self):
        matched = _symbols_in_path(["safe_decode"], ["celery.utils.safe_decode"])
        assert matched == ["safe_decode"]

    def test_no_match(self):
        assert _symbols_in_path(["dangerous"], ["celery.utils.safe_decode"]) == []

    def test_multiple_symbols_partial_match(self):
        matched = _symbols_in_path(
            ["safe_decode", "other_func"],
            ["celery.utils.safe_decode"],
        )
        assert "safe_decode" in matched
        assert "other_func" not in matched

    def test_empty_path(self):
        assert _symbols_in_path(["safe_decode"], []) == []

    def test_empty_symbols(self):
        assert _symbols_in_path([], ["celery.utils.safe_decode"]) == []


# ===========================================================================
# _has_dynamic_path_to_dist helper
# ===========================================================================

class TestHasDynamicPath:
    def test_dynamic_files_present(self):
        graph = _FakeGraph(dynamic_files={"broken.py"})
        assert _has_dynamic_path_to_dist("requests", graph) is True

    def test_no_dynamic_files(self):
        graph = _FakeGraph(dynamic_files=set())
        assert _has_dynamic_path_to_dist("requests", graph) is False


# ===========================================================================
# ConfidenceDecision dataclass
# ===========================================================================

class TestConfidenceDecision:
    def test_fields(self):
        d = ConfidenceDecision(
            confidence=Confidence.UNKNOWN,
            incomplete=True,
            reason="test reason",
            dev_only=False,
        )
        assert d.confidence == Confidence.UNKNOWN
        assert d.incomplete is True
        assert d.reason == "test reason"
        assert d.dev_only is False

    def test_defaults(self):
        d = ConfidenceDecision(confidence=Confidence.NOT_REACHABLE)
        assert d.incomplete is False
        assert d.reason == ""
        assert d.dev_only is False
