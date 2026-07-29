"""
Package: talos.replay

Purpose:
    Replay engine — sends stored HTTP flows exactly as captured and persists
    the result as a new flow (source=auto_replay).

    Public API:
        replay_flow(flow_id, db_path, project_id)     → ReplayOutcome
        replay_endpoint(endpoint_id, db_path, project_id) → ReplayOutcome

    Both are async coroutines; callers use asyncio.run() when invoking from
    synchronous CLI context.

Import hygiene:
    Submodules such as ``talos.replay.db`` are pure SQLite helpers and must
    remain importable without httpx / network stack. Engine symbols are
    exposed lazily so offline consumers (e.g. unauth filter reclassify in
    the Control Panel process) do not pull engine dependencies at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = ["ReplayOutcome", "replay_flow", "replay_endpoint"]

if TYPE_CHECKING:
    from talos.replay.engine import ReplayOutcome, replay_endpoint, replay_flow


def __getattr__(name: str) -> Any:
    if name in __all__:
        from talos.replay import engine as _engine

        return getattr(_engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
