"""
Package: talos.send

Purpose:
    Talos Repeater Phase 1 (MVP) — mutable edit → send once → review.

    Distinct from exact replay (Mode 1):
        • talos replay …  = bit-identical re-send (no mutation)
        • talos send  …  = free mutation with lineage (Mode 2)

    Product rule (non-negotiable):
        Never modify the captured flow. Every send inserts a new flow row
        with source=manual_send|ai_send and full parent/root lineage.

Public surface:
    engine.send_once, draft helpers, raw_http parse/serialize, CLI entry.
"""

from talos.send.engine import SendOutcome, send_once

__all__ = ["SendOutcome", "send_once"]
