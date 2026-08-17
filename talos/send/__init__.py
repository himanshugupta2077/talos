"""
Package: talos.send

Purpose:
    Talos Repeater (Mode 2) — mutable edit → send → review with lineage.

    Distinct from exact replay (Mode 1):
        • talos replay …  = bit-identical re-send (no mutation)
        • talos send  …  = free mutation with lineage (Mode 2)

    Product rule (non-negotiable):
        Never modify the captured flow. Every send inserts a new flow row
        with source=manual_send|ai_send and full parent/root lineage.

    Phase 2 CLI: from, edit, once (--repeat/--parallel), redo, dup, show,
    export, history, tree, diff, note.

    Tab archive CLI: tab open|list|show|close|rename|touch|clear
        Project-scoped sticky Repeater workspace slots (repeater_tabs).
        Metadata only — draft bodies stay local until Send.

Public surface:
    engine.send_once / send_repeat / send_parallel / redo_send,
    draft helpers, raw_http parse/serialize, request_diff, CLI entry,
    send.db tab archive helpers.

Import hygiene:
    Submodules such as ``talos.send.db`` are pure SQLite helpers and must
    remain importable without httpx / network stack. Engine symbols are
    exposed lazily so Control Panel Send-to-Repeater (tab archive) does
    not pull engine dependencies at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "SendOutcome",
    "MultiSendOutcome",
    "send_once",
    "send_repeat",
    "send_parallel",
    "redo_send",
    "MAX_PROFILE_N",
    "MAX_PARALLEL_CONCURRENCY",
]

if TYPE_CHECKING:
    from talos.send.engine import (
        MAX_PARALLEL_CONCURRENCY,
        MAX_PROFILE_N,
        MultiSendOutcome,
        SendOutcome,
        redo_send,
        send_once,
        send_parallel,
        send_repeat,
    )


def __getattr__(name: str) -> Any:
    if name in __all__:
        from talos.send import engine as _engine

        return getattr(_engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
