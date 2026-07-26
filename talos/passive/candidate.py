"""
Module: talos.passive.candidate

Purpose:
    Cheap FlowWorker gate: decide whether a captured response is worth
    enqueueing for Passive Source Intelligence.

    Primary signals are Content-Type and path (extension / known hints).
    Optional body is used only for empty checks and a short magic-byte
    sniff (PNG/JPEG/PDF/…) so mislabeled binaries are not enqueued.

    Must never: run detectors, decode full body to text, or block on I/O.

    Design contract:
        is_source_candidate() is the only passive work on the capture path.
        Heavy classify/normalize/detect runs in SourceScanWorker.

Dependencies: talos.passive.classifier, talos.passive.constants
Data flow: (content_type, path, optional status/body) → bool
Side effects: None.
"""

from __future__ import annotations

from typing import Optional, Union

from talos.passive.classifier import (
    classify_source,
    is_scannable_kind,
    parse_media_type,
    path_extension,
    path_has_source_hint,
    sniff_magic,
)
from talos.passive.constants import SourceKind

# Content-Types that are never candidates (fast path before classify).
_REJECT_CT_PREFIXES: tuple[str, ...] = (
    "image/",
    "audio/",
    "video/",
    "font/",
    "application/font-",
    "multipart/",
)
_REJECT_CT_EXACT: frozenset[str] = frozenset({
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/wasm",
    "application/ogg",
})


def is_source_candidate(
    content_type: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    body: Optional[bytes] = None,
    truncated: bool = False,
) -> bool:
    """
    Purpose:
        Return True when the response looks like source-like content that
        should be scanned for secrets (HTML/JS/JSON/XML/text/CSS/source maps).

    Cheap rules (CT + path first; body only for empty + magic):
        Allow  — listed content-types; source extensions; path hints
                 (env.js, swagger, .map, …); text/plain and
                 application/octet-stream when path/sniff says source-like.
        Reject — empty body; PNG/JPEG/GIF/PDF/WASM/fonts/media (CT or magic);
                 non-scannable SourceKind (BINARY, WASM, UNKNOWN).

    Status:
        Non-2xx with empty body → False.
        Non-2xx error HTML/JSON with sizeable body → True when CT/path allows.
        204 / 304 → False when body empty.

    Input:
        content_type — response Content-Type (may be empty / None)
        path         — request path or URL
        status_code  — HTTP status when known (optional)
        body         — optional raw body for empty + magic checks
        truncated    — capture truncated flag (does not force accept)

    Output:
        True if the flow should be enqueued for passive scan.

    Side effects: None.

    Notes:
        `truncated` is accepted for API symmetry with PassiveScanJob; it does
        not alone make a body a candidate.  Config toggles (enabled,
        scan_wasm, …) are applied by the caller (FlowWorker / worker), not here.
    """
    del truncated  # API symmetry only; gate does not use it

    # Empty body is never worth scanning (truncated empty still empty).
    if body is not None and len(body) == 0:
        return False

    if status_code is not None:
        # No-content responses
        if status_code in (204, 304) and (body is None or len(body) == 0):
            return False
        # Error/empty responses with no body
        if not (200 <= int(status_code) < 300):
            if body is not None and len(body) == 0:
                return False
            # Non-2xx with body: still allow if content looks source-like
            # (e.g. HTML error page, JSON error with config leak).

    # Fast CT reject for media/fonts/pdf/wasm before classify
    media = parse_media_type(content_type)
    if media in _REJECT_CT_EXACT:
        return False
    for prefix in _REJECT_CT_PREFIXES:
        if media.startswith(prefix):
            return False

    # Magic binary → never enqueue (even if CT says text/plain)
    magic = sniff_magic(body)
    if magic in (SourceKind.BINARY, SourceKind.WASM):
        return False

    # Extension hard-reject (.png, .pdf, …)
    ext = path_extension(path)
    if ext in {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
        ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".otf",
        ".mp3", ".mp4", ".webm", ".wasm", ".exe", ".dll",
    }:
        return False

    kind = classify_source(content_type=content_type, path=path, body=body)
    if is_scannable_kind(kind):
        return True

    # UNKNOWN with no positive path signal → not a candidate
    if kind is SourceKind.UNKNOWN:
        # last chance: explicit path hint without classified kind
        # (should already be covered by classify, but keep defense)
        return path_has_source_hint(path)

    # BINARY / WASM
    return False


def is_source_candidate_from_flow(
    *,
    content_type: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[Union[int, str]] = None,
    body: Optional[bytes] = None,
    truncated: bool = False,
) -> bool:
    """
    Purpose:
        Convenience wrapper when status_code may arrive as a string from DB.
    Input/Output/Side effects: same as is_source_candidate.
    """
    code: Optional[int] = None
    if status_code is not None and status_code != "":
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            code = None
    return is_source_candidate(
        content_type=content_type,
        path=path,
        status_code=code,
        body=body,
        truncated=truncated,
    )
