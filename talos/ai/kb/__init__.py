"""
Module: talos.ai.kb

Purpose:
    Minimal knowledge base: operator-authored Markdown files under
    ~/.talos/ai/kb/ (or TALOS_DATA_DIR/ai/kb). No seed DB, no promote
    pipeline — drop .md files in the directory when you want them.
"""

from talos.ai.kb.store import (
    KbDoc,
    ensure_kb_dir,
    get_doc,
    kb_dir,
    list_docs,
    search_docs,
)

__all__ = [
    "KbDoc",
    "ensure_kb_dir",
    "get_doc",
    "kb_dir",
    "list_docs",
    "search_docs",
]
