"""
parser_pool.py — crash-isolated subprocess worker pool for Python AST parsing.

Architecture
------------
Each slot in the pool is an IsolatedParser that owns exactly one
``ast_worker.py`` subprocess.  Requests are dispatched round-robin over idle
slots with a timeout guard.  If the subprocess dies (stdout EOF) or times out,
the slot is respawned and the failing file yields a ``kind="unknown"`` result.

Parallelism model
-----------------
The pool uses a ThreadPoolExecutor to dispatch requests concurrently across
N IsolatedParser subprocess slots.  Each slot owns one ast_worker.py process
(which runs ast.parse in a separate Python interpreter, achieving true CPU
parallelism without GIL interference between slots).

This is equivalent in effect to ProcessPoolExecutor but avoids the pickling
overhead and the multiprocessing start method complexity — the CPU work happens
in the worker subprocesses, not in threads within this process.

Only Python stdlib is used (subprocess, threading, queue, json, os, sys,
pathlib, concurrent.futures).

Public API
----------
    pool = ParserPool(worker_script=".../ast_worker.py", concurrency=4)
    result = pool.parse("/abs/path/to/file.py")   # returns ParseResult
    pool.shutdown()

ParseResult shape
-----------------
    dataclass ParseResult:
        kind: str            # "parsed" | "unknown"
        path: str
        imports: list        # empty on unknown
        functions: list      # empty on unknown
        calls: list          # empty on unknown
        dynamic_import_markers: list   # [{kind, line, target, prefix}, ...]
        dynamic_dispatch_markers: list # ["eval at line N", ...]
        dynamic_markers: list          # backward-compat combined list
        reason: str          # non-empty on kind="unknown"
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONCURRENCY: int = 4
DEFAULT_TIMEOUT_SEC: float = 10.0   # Per-file parse timeout


# ---------------------------------------------------------------------------
# ParseResult
# ---------------------------------------------------------------------------

@dataclass
class ParseResult:
    """
    Outcome of parsing a single Python file.

    Hard invariant: kind=="unknown" means the caller MUST NOT emit
    NOT_REACHABLE for any advisory involving this file's transitive deps.

    Fields added for marker split (see ast_worker.py):
    - dynamic_import_markers: list of {kind, line, target, prefix} dicts.
        kind="unbounded" -> opaque package-level frontier.
        kind="bounded"   -> deterministic namespace (NOT a frontier).
    - dynamic_dispatch_markers: list of strings for eval/exec/dynamic getattr.
        SYMBOL-LEVEL only; do NOT gate package-level NOT_REACHABLE.
    - dynamic_markers: backward-compat combined list (dispatch + import strings).
    """
    kind: str                          # "parsed" | "unknown"
    path: str = ""
    imports: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[Dict[str, Any]] = field(default_factory=list)
    calls: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_import_markers: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_dispatch_markers: List[str] = field(default_factory=list)
    dynamic_markers: List[str] = field(default_factory=list)   # backward-compat
    reason: str = ""                   # non-empty when kind=="unknown"

    @property
    def is_unknown(self) -> bool:
        return self.kind == "unknown"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ParseResult":
        kind = d.get("kind", "unknown")
        if kind != "parsed":
            return cls(
                kind="unknown",
                path=d.get("path", ""),
                reason=d.get("reason", "unknown kind"),
            )
        return cls(
            kind="parsed",
            path=d.get("path", ""),
            imports=d.get("imports", []),
            functions=d.get("functions", []),
            calls=d.get("calls", []),
            dynamic_import_markers=d.get("dynamic_import_markers", []),
            dynamic_dispatch_markers=d.get("dynamic_dispatch_markers", []),
            dynamic_markers=d.get("dynamic_markers", []),
        )

    @classmethod
    def unknown(cls, path: str = "", reason: str = "") -> "ParseResult":
        return cls(kind="unknown", path=path, reason=reason)


# ---------------------------------------------------------------------------
# IsolatedParser — one subprocess slot
# ---------------------------------------------------------------------------

class IsolatedParser:
    """
    Manages a single ``ast_worker.py`` subprocess.

    Thread-safe for a single caller at a time (the pool serialises access).
    If the subprocess dies, it is respawned on the next call.
    """

    def __init__(self, worker_script: str, python_exe: str = sys.executable) -> None:
        self._worker_script = worker_script
        self._python_exe = python_exe
        self._proc: Optional[subprocess.Popen] = None
        self._next_id: int = 1
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _spawn(self) -> None:
        """Start (or restart) the worker subprocess."""
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=2)
            except Exception:
                pass
        self._proc = subprocess.Popen(
            [self._python_exe, self._worker_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

    def _ensure_alive(self) -> bool:
        """Return True if subprocess is (still) running; spawn if dead."""
        if self._proc is None or self._proc.poll() is not None:
            try:
                self._spawn()
            except Exception:
                return False
        return True

    def shutdown(self) -> None:
        """Terminate the worker process cleanly."""
        if self._proc is not None:
            try:
                self._proc.stdin.close()  # type: ignore[union-attr]
            except Exception:
                pass
            try:
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    # ------------------------------------------------------------------
    # Parse a single file
    # ------------------------------------------------------------------

    def parse(self, path: str, timeout: float = DEFAULT_TIMEOUT_SEC) -> ParseResult:
        """
        Send a parse request to the worker and return the result.

        Crash-isolation contract:
        - If the subprocess dies mid-request, respawn and return unknown.
        - If the request times out, kill the worker, respawn, return unknown.
        - Any JSON decode error returns unknown.
        """
        with self._lock:
            return self._parse_locked(path, timeout)

    def _parse_locked(self, path: str, timeout: float) -> ParseResult:
        if not self._ensure_alive():
            return ParseResult.unknown(path=path, reason="worker spawn failed")

        req_id = self._next_id
        self._next_id += 1

        request = json.dumps({"id": req_id, "path": path}) + "\n"

        # --- send ---
        try:
            self._proc.stdin.write(request.encode("utf-8"))  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, OSError):
            self._spawn()
            return ParseResult.unknown(path=path, reason="worker died before write")

        # --- receive with timeout ---
        result_holder: List[Optional[Dict[str, Any]]] = [None]
        exc_holder: List[Optional[str]] = [None]

        def _read() -> None:
            try:
                line = self._proc.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    exc_holder[0] = "EOF from worker"
                    return
                resp = json.loads(line.decode("utf-8"))
                if resp.get("id") == req_id:
                    result_holder[0] = resp.get("result", {})
                else:
                    exc_holder[0] = f"unexpected response id {resp.get('id')}"
            except Exception as exc:
                exc_holder[0] = str(exc)

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if t.is_alive():
            try:
                self._proc.kill()
            except Exception:
                pass
            self._spawn()
            return ParseResult.unknown(path=path, reason=f"parse timeout after {timeout}s")

        if exc_holder[0]:
            self._spawn()
            return ParseResult.unknown(path=path, reason=exc_holder[0])

        if result_holder[0] is None:
            return ParseResult.unknown(path=path, reason="empty result")

        result = result_holder[0]
        result["path"] = path
        return ParseResult.from_dict(result)


# ---------------------------------------------------------------------------
# ParserPool — round-robin over N IsolatedParser slots
# ---------------------------------------------------------------------------

class ParserPool:
    """
    A pool of crash-isolated AST parse workers.

    Thread-safe: multiple goroutines/threads can call ``parse()`` concurrently.
    The pool is a semaphore over ``concurrency`` IsolatedParser slots; callers
    block until a slot is free.

    True CPU parallelism is achieved because each IsolatedParser slot owns a
    separate ast_worker.py *subprocess* — the CPU-bound ast.parse() runs in
    an independent Python interpreter, bypassing the GIL.  The ThreadPoolExecutor
    in parse_many() fans out requests across all subprocess slots concurrently.
    """

    def __init__(
        self,
        worker_script: str,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        python_exe: str = sys.executable,
    ) -> None:
        self._concurrency = max(1, concurrency)
        self._slots: List[IsolatedParser] = [
            IsolatedParser(worker_script, python_exe=python_exe)
            for _ in range(self._concurrency)
        ]
        self._sem = threading.Semaphore(self._concurrency)
        self._slot_queue: Queue[IsolatedParser] = Queue()
        for slot in self._slots:
            self._slot_queue.put(slot)
        self._timeout = timeout

    def parse(self, path: str) -> ParseResult:
        """Acquire a free slot, parse the file, release the slot."""
        self._sem.acquire()
        slot = self._slot_queue.get()
        try:
            return slot.parse(path, timeout=self._timeout)
        finally:
            self._slot_queue.put(slot)
            self._sem.release()

    def parse_many(self, paths: List[str]) -> Dict[str, ParseResult]:
        """
        Parse a list of files concurrently using the pool workers.

        Uses a ThreadPoolExecutor to fan out requests across all subprocess
        slots.  Since the CPU work (ast.parse) happens inside the worker
        subprocesses — each running in its own Python interpreter — this
        achieves true CPU parallelism without GIL contention.

        The number of threads matches the number of subprocess slots so that
        all workers can be busy simultaneously.
        """
        if not paths:
            return {}
        results: Dict[str, ParseResult] = {}
        with ThreadPoolExecutor(max_workers=self._concurrency) as executor:
            future_to_path = {executor.submit(self.parse, p): p for p in paths}
            for future in as_completed(future_to_path):
                p = future_to_path[future]
                try:
                    results[p] = future.result()
                except Exception as exc:
                    results[p] = ParseResult.unknown(path=p, reason=str(exc))
        return results

    def shutdown(self) -> None:
        """Terminate all worker subprocesses."""
        for slot in self._slots:
            slot.shutdown()
