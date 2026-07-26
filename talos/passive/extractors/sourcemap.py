"""
Module: talos.passive.extractors.sourcemap

Purpose:
    Parse JavaScript source map JSON and emit virtual SourceDocuments for
    each non-empty ``sourcesContent`` entry.  The scan worker registers and
    scans these as children of the parent map document (Phase 10).

    Design rules:
        - No outbound HTTP (never fetch missing sources)
        - Map without sourcesContent → empty list (occurrence only on parent)
        - Cap number and size of virtual sources (DoS protection)
        - Virtual path from sources[] when available

Dependencies: json, hashlib, uuid (stdlib); talos.passive.constants/models
Data flow: map text → parse → list[SourceDocument] (in-memory, not persisted)
Side effects: None (pure).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from talos.passive.constants import SourceKind
from talos.passive.models import SourceDocument

# Safety caps — large maps with full sourcesContent can be multi-MB.
_MAX_VIRTUAL_SOURCES = 50
_MAX_VIRTUAL_SOURCE_CHARS = 500_000
_MAX_TOTAL_VIRTUAL_CHARS = 2_000_000


def parse_sourcemap_json(text: str) -> Optional[dict[str, Any]]:
    """
    Purpose:
        Parse a source map body as JSON object.
    Input:
        text — response body text (already normalized to str)
    Output:
        dict if valid object JSON, else None
    Side effects: None.
    """
    if not text or not text.strip():
        return None
    stripped = text.lstrip()
    # Ignore JSONP / leading )]}' XSSI prefix used by some maps
    if stripped.startswith(")]}'"):
        stripped = stripped[4:].lstrip()
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def extract_sourcemap_virtual_docs(
    map_text: str,
    *,
    parent_document_id: str,
    project_id: str,
    max_sources: int = _MAX_VIRTUAL_SOURCES,
    max_source_chars: int = _MAX_VIRTUAL_SOURCE_CHARS,
    max_total_chars: int = _MAX_TOTAL_VIRTUAL_CHARS,
) -> list[SourceDocument]:
    """
    Purpose:
        Build in-memory virtual SourceDocuments from sourcesContent.

    Input:
        map_text — full source map JSON text
        parent_document_id — source_documents.id of the .map response
        project_id — owning project
        max_* — safety caps

    Output:
        list[SourceDocument] with:
            - source_kind=JAVASCRIPT (original sources are typically JS/TS)
            - text set to sourcesContent entry
            - parent_document_id set
            - logical_source_name from sources[] path
            - body_hash left empty (worker re-hashes bytes for registry)
            - temporary id (worker may ignore and assign via upsert)

        Empty list when: invalid JSON, no sourcesContent, all empty entries.

    Side effects: None.
    """
    data = parse_sourcemap_json(map_text)
    if data is None:
        return []

    contents = data.get("sourcesContent")
    if not isinstance(contents, list) or not contents:
        return []

    sources = data.get("sources")
    if not isinstance(sources, list):
        sources = []

    virtuals: list[SourceDocument] = []
    total_chars = 0
    limit = max(0, int(max_sources))

    for idx, content in enumerate(contents):
        if len(virtuals) >= limit:
            break
        if content is None:
            continue
        if not isinstance(content, str):
            continue
        text = content
        if not text.strip():
            continue
        if len(text) > max_source_chars:
            text = text[:max_source_chars]
        if total_chars + len(text) > max_total_chars:
            break
        total_chars += len(text)

        path_hint = ""
        if idx < len(sources) and isinstance(sources[idx], str):
            path_hint = sources[idx]
        logical = _normalize_virtual_path(path_hint) or f"sourcesContent[{idx}]"

        body_bytes = text.encode("utf-8", errors="replace")
        virtuals.append(
            SourceDocument(
                id=str(uuid.uuid4()),
                project_id=project_id,
                body_hash="",  # worker computes real hash from bytes
                source_kind=SourceKind.JAVASCRIPT,
                body_size=len(body_bytes),
                truncated=len(content) > max_source_chars,
                parent_document_id=parent_document_id,
                logical_source_name=logical,
                text=text,
            )
        )

    return virtuals


def _normalize_virtual_path(path: str) -> str:
    """
    Purpose:
        Clean webpack/vite-style source paths for UI display.
    Input:
        path — sources[] entry (may include webpack://, query, etc.)
    Output:
        Shortened logical path string
    Side effects: None.
    """
    if not path:
        return ""
    p = path.strip()
    for prefix in (
        "webpack://",
        "webpack:///",
        "ng://",
        "vite://",
        "file://",
    ):
        if p.startswith(prefix):
            p = p[len(prefix) :]
            break
    # Drop leading ./ and query fragments
    if p.startswith("./"):
        p = p[2:]
    if "?" in p:
        p = p.split("?", 1)[0]
    return p[:500]
