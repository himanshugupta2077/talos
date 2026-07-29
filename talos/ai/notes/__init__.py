"""
Package: talos.ai.notes

Purpose:
    Structured application-understanding notes (AI-only store). Never writes
    endpoint_policy.notes (replacement API would wipe operator content).
"""

from talos.ai.notes.store import (
    NotesError,
    NotesRevisionConflict,
    NotesStore,
    empty_document,
    get_notes,
    pack_for_planner,
    patch_notes,
    replace_notes,
)

__all__ = [
    "NotesError",
    "NotesRevisionConflict",
    "NotesStore",
    "empty_document",
    "get_notes",
    "pack_for_planner",
    "patch_notes",
    "replace_notes",
]
