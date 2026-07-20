"""
Package: talos.scheduler

Purpose:
    Replay Scheduler Layer — the control plane between stored flows and the
    replay engine.

    Inserts a bounded, rate-limited, priority-aware queue between the DB and
    replay execution.  Without this layer, auto-replay would fire instantly,
    produce burst traffic, and generate noisy or detection-triggering signals.

    Separation of concerns:
        Proxy      → capture only.
        Worker     → normalise and store.
        Scheduler  → decide WHEN to replay.
        Engine     → execute the HTTP request.
        Diff       → evaluate the result.

Public submodules:
    talos.scheduler.job        — ReplayJob dataclass and constants.
    talos.scheduler.db         — Persistent queue CRUD (scheduler_jobs table).
    talos.scheduler.scheduler  — ReplayScheduler execution loop.
    talos.scheduler.cli        — CLI entry point for talos scheduler commands.
"""
