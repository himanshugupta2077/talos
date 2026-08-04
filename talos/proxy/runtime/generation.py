"""
Module: talos.proxy.runtime.generation

Purpose:
    Per-project proxy configuration generation counters and transactions.

    desired_generation advances when proxy-relevant config commits.
    applied_generation (in proxy runtime state) records the spawn-time
    generation of the running process — never a later generation.

Dependencies: json, threading, pathlib, atomic_io
Data flow:
    notify / writers → bump_generation → reconcile reads get_generation
Side effects:
    Writes projects/<id>/proxy_generation.json under the projects root.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from talos.proxy.runtime.atomic_io import atomic_write_text

logger = logging.getLogger(__name__)

_txn_local = threading.local()


def _generation_path(projects_root: Path, project_id: str) -> Path:
    return projects_root / project_id / "proxy_generation.json"


def get_generation(projects_root: Path, project_id: str) -> int:
    """
    Purpose:
        Read the desired configuration generation for a project.
    Output:
        Non-negative integer (0 if never bumped).
    """
    path = _generation_path(projects_root, project_id)
    if not path.exists():
        return 0
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return int(raw.get("generation", 0))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def bump_generation(
    projects_root: Path,
    project_id: str,
    *,
    reason: str = "",
) -> int:
    """
    Purpose:
        Atomically increment desired generation for project_id.
        No-op (no bump) when inside a nested transaction — the outermost
        commit bumps once.
    Output:
        New generation value (or current if inside txn without commit).
    """
    depth = getattr(_txn_local, "depth", 0)
    if depth > 0:
        dirty: set = getattr(_txn_local, "dirty", set())
        dirty.add(project_id)
        _txn_local.dirty = dirty
        _txn_local.reasons = getattr(_txn_local, "reasons", [])
        _txn_local.reasons.append(reason)
        _txn_local.projects_root = projects_root
        return get_generation(projects_root, project_id)

    return _bump_now(projects_root, project_id, reason=reason)


def _bump_now(projects_root: Path, project_id: str, *, reason: str) -> int:
    path = _generation_path(projects_root, project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = get_generation(projects_root, project_id)
    new_val = current + 1
    payload = json.dumps(
        {"generation": new_val, "reason": reason},
        indent=2,
        sort_keys=True,
    ) + "\n"
    atomic_write_text(
        path,
        payload,
        prefix=".proxy_generation.",
        suffix=".tmp",
    )
    logger.info(
        "Proxy config generation %s → %s project=%s reason=%s",
        current,
        new_val,
        project_id,
        reason or "(none)",
    )
    return new_val


@contextmanager
def proxy_config_transaction(
    projects_root: Path,
    project_id: str,
) -> Iterator[None]:
    """
    Purpose:
        Coalesce multiple proxy-relevant writes into one generation bump.
        On successful exit: bump once (if any nested bump was requested).
        On exception: no generation bump from the transaction wrapper.
    """
    depth = getattr(_txn_local, "depth", 0)
    if depth == 0:
        _txn_local.dirty = set()
        _txn_local.reasons = []
        _txn_local.projects_root = projects_root
    _txn_local.depth = depth + 1
    try:
        yield
    except Exception:
        _txn_local.depth = depth
        if depth == 0:
            _txn_local.dirty = set()
            _txn_local.reasons = []
        raise
    else:
        _txn_local.depth = depth
        if depth == 0:
            dirty: set = getattr(_txn_local, "dirty", set())
            reasons = getattr(_txn_local, "reasons", [])
            root = getattr(_txn_local, "projects_root", projects_root)
            _txn_local.dirty = set()
            _txn_local.reasons = []
            if project_id in dirty or dirty:
                # Bump the transaction's project once (and any other dirty ids).
                targets = dirty if dirty else {project_id}
                reason = "; ".join(r for r in reasons if r) or "transaction"
                for pid in targets:
                    _bump_now(root, pid, reason=reason)
