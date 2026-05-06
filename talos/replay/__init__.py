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
"""

from talos.replay.engine import ReplayOutcome, replay_endpoint, replay_flow

__all__ = ["ReplayOutcome", "replay_flow", "replay_endpoint"]
