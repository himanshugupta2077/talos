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

Public surface:
    engine.send_once / send_repeat / send_parallel / redo_send,
    draft helpers, raw_http parse/serialize, request_diff, CLI entry.
"""

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
