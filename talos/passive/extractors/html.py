"""
Module: talos.passive.extractors.html

Purpose:
    Extract virtual SourceDocuments from HTML response bodies for passive
    secret scanning (Phase 11):

        1. Inline <script> blocks without a ``src`` attribute
        2. Conservative bootstrap JSON islands:
           - <script type="application/json|ld+json" …>
           - id/__NEXT_DATA__ / similar named script JSON payloads
           - window.__CONFIG__ / window.__INITIAL_STATE__ assignments

    Never fetches external scripts (no HTTP). Caps count and size so large
    HTML shells cannot explode the passive queue.

Dependencies: re, hashlib, uuid (stdlib); talos.passive.constants / models
Data flow: HTML text → list[SourceDocument] (in-memory; worker persists)
Side effects: None (pure).
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from talos.passive.constants import SourceKind
from talos.passive.models import SourceDocument

# Safety caps — HTML shells with many inline blocks can be huge.
_MAX_INLINE_SCRIPTS = 40
_MAX_BOOTSTRAP_JSON = 20
_MAX_VIRTUAL_SOURCE_CHARS = 500_000
_MAX_TOTAL_VIRTUAL_CHARS = 2_000_000

# <script …>…</script> — case-insensitive; DOTALL for multi-line bodies.
# Non-greedy body so consecutive scripts do not merge.
_SCRIPT_TAG = re.compile(
    r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)

# Attribute helpers (applied to attrs substring)
_ATTR_SRC = re.compile(r"""\bsrc\s*=""", re.IGNORECASE)
_ATTR_TYPE = re.compile(
    r"""\btype\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_ATTR_ID = re.compile(
    r"""\bid\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# window.__CONFIG__ = {…}; / window["__INITIAL_STATE__"] = {…};
# Conservative: only well-known bootstrap names; balanced-ish brace extract.
_WINDOW_BOOTSTRAP = re.compile(
    r"""window(?:\[["']|[\.])(__?(?:CONFIG|INITIAL_STATE|INITIAL_DATA|"""
    r"""PRELOADED_STATE|__NEXT_DATA__|APP_CONFIG|ENV|RUNTIME_CONFIG)"""
    r"""_?)["']?\]?\s*=\s*""",
    re.IGNORECASE,
)

_JSON_SCRIPT_TYPES = frozenset({
    "application/json",
    "application/ld+json",
    "text/json",
})

_BOOTSTRAP_ID_HINTS = frozenset({
    "__next_data__",
    "__nuxt_data__",
    "__nuxt__",
    "__app_data__",
    "__config__",
    "app-config",
    "runtime-config",
})


def extract_html_virtual_docs(
    html_text: str,
    *,
    parent_document_id: str,
    project_id: str,
    max_scripts: int = _MAX_INLINE_SCRIPTS,
    max_bootstrap: int = _MAX_BOOTSTRAP_JSON,
    max_source_chars: int = _MAX_VIRTUAL_SOURCE_CHARS,
    max_total_chars: int = _MAX_TOTAL_VIRTUAL_CHARS,
) -> list[SourceDocument]:
    """
    Purpose:
        Build in-memory virtual SourceDocuments from inline scripts and
        bootstrap JSON islands inside an HTML body.

    Input:
        html_text — normalized HTML text
        parent_document_id — source_documents.id of the HTML response
        project_id — owning project
        max_* — safety caps

    Output:
        list[SourceDocument] with:
            - source_kind JAVASCRIPT (inline script) or JSON (bootstrap)
            - text set to extracted content
            - parent_document_id set
            - logical_source_name describing origin (e.g. inline-script[0])
            - body_hash empty (worker re-hashes for registry)
            - temporary id

        Empty list when HTML has no extractable islands.

    Side effects: None.
    """
    if not html_text or not html_text.strip():
        return []

    virtuals: list[SourceDocument] = []
    total_chars = 0
    script_count = 0
    bootstrap_count = 0
    script_idx = 0

    for m in _SCRIPT_TAG.finditer(html_text):
        attrs = m.group("attrs") or ""
        body = m.group("body") or ""
        # External scripts: never fetch; skip entirely.
        if _ATTR_SRC.search(attrs):
            script_idx += 1
            continue
        text = body.strip()
        if not text:
            script_idx += 1
            continue

        type_m = _ATTR_TYPE.search(attrs)
        type_val = (type_m.group(1) if type_m else "").strip().lower()
        id_m = _ATTR_ID.search(attrs)
        id_val = (id_m.group(1) if id_m else "").strip()
        id_lower = id_val.lower()

        is_json_type = type_val in _JSON_SCRIPT_TYPES
        is_bootstrap_id = id_lower in _BOOTSTRAP_ID_HINTS or any(
            hint in id_lower for hint in ("__next", "__nuxt", "config", "bootstrap")
        )

        if is_json_type or is_bootstrap_id:
            if bootstrap_count >= max_bootstrap:
                script_idx += 1
                continue
            kind = SourceKind.JSON
            logical = (
                f"bootstrap-json[{id_val or type_val or script_idx}]"
            )
            bootstrap_count += 1
        else:
            # Treat module / classic inline JS as javascript
            if type_val and type_val not in (
                "text/javascript",
                "application/javascript",
                "module",
                "text/ecmascript",
                "application/ecmascript",
                "",
            ):
                # Unknown non-JS types (e.g. text/template) — still scan as text
                # but cap under script budget to avoid template spam.
                if script_count >= max_scripts:
                    script_idx += 1
                    continue
                kind = SourceKind.TEXT
                logical = f"inline-script-misc[{script_idx}]"
            else:
                if script_count >= max_scripts:
                    script_idx += 1
                    continue
                kind = SourceKind.JAVASCRIPT
                logical = f"inline-script[{script_idx}]"
            script_count += 1

        added = _append_virtual(
            virtuals,
            text=text,
            kind=kind,
            logical=logical,
            parent_document_id=parent_document_id,
            project_id=project_id,
            max_source_chars=max_source_chars,
            max_total_chars=max_total_chars,
            total_chars=total_chars,
        )
        if added is None:
            break
        total_chars = added
        script_idx += 1

    # window.__CONFIG__ = {…} style assignments outside script tags (rare but
    # appears in some SPA shells). Cap under remaining bootstrap budget.
    if bootstrap_count < max_bootstrap and total_chars < max_total_chars:
        for wm in _WINDOW_BOOTSTRAP.finditer(html_text):
            if bootstrap_count >= max_bootstrap:
                break
            start = wm.end()
            payload = _extract_balanced_jsonish(html_text, start)
            if not payload or len(payload.strip()) < 4:
                continue
            name = wm.group(1) or "window_bootstrap"
            added = _append_virtual(
                virtuals,
                text=payload,
                kind=SourceKind.JSON,
                logical=f"window-bootstrap[{name}]",
                parent_document_id=parent_document_id,
                project_id=project_id,
                max_source_chars=max_source_chars,
                max_total_chars=max_total_chars,
                total_chars=total_chars,
            )
            if added is None:
                break
            total_chars = added
            bootstrap_count += 1

    return virtuals


def _append_virtual(
    virtuals: list[SourceDocument],
    *,
    text: str,
    kind: SourceKind,
    logical: str,
    parent_document_id: str,
    project_id: str,
    max_source_chars: int,
    max_total_chars: int,
    total_chars: int,
) -> Optional[int]:
    """
    Purpose:
        Truncate and append one virtual document; return new total_chars
        or None when the total budget is exhausted.
    Side effects: Appends to virtuals in place.
    """
    content = text
    truncated = False
    if len(content) > max_source_chars:
        content = content[:max_source_chars]
        truncated = True
    if total_chars + len(content) > max_total_chars:
        remaining = max_total_chars - total_chars
        if remaining <= 0:
            return None
        content = content[:remaining]
        truncated = True
    body_bytes = content.encode("utf-8", errors="replace")
    virtuals.append(
        SourceDocument(
            id=str(uuid.uuid4()),
            project_id=project_id,
            body_hash="",
            source_kind=kind,
            body_size=len(body_bytes),
            truncated=truncated,
            parent_document_id=parent_document_id,
            logical_source_name=logical[:500],
            text=content,
        )
    )
    return total_chars + len(content)


def _extract_balanced_jsonish(text: str, start: int) -> str:
    """
    Purpose:
        From an assignment start index, extract a balanced {...} or [...]
        payload (string-aware enough for common bootstrap blobs).
    Input:
        text  — full HTML
        start — index of first char of value (should be { or [)
    Output:
        Extracted substring, or empty string on failure
    Side effects: None.
    """
    if start >= len(text):
        return ""
    # Skip whitespace
    i = start
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    if i >= len(text) or text[i] not in "{[":
        return ""
    open_ch = text[i]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    escape = False
    quote = ""
    j = i
    while j < len(text):
        ch = text[j]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
        else:
            if ch in ('"', "'"):
                in_str = True
                quote = ch
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return text[i : j + 1]
            # Bail on statement terminator outside structure
            elif ch == ";" and depth == 0:
                break
        j += 1
        # Hard cap extraction walk
        if j - i > _MAX_VIRTUAL_SOURCE_CHARS:
            break
    return ""
