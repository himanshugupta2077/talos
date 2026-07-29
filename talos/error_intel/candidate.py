"""
Module: talos.error_intel.candidate

Purpose:
    Cheap FlowWorker gate: decide whether a captured / replayed / attack
    response is worth enqueueing for Error Intelligence.

    Unlike Passive Source Intelligence, this gate does **not** require
    source-like Content-Type.  JSON APIs, plain-text 500s, and framework
    error HTML are primary targets.  Status ≥400 is one signal only —
    stack traces and exception-shaped JSON on 200 are also in scope.

    Must never: run full detectors, decode multi-MB bodies, or block on I/O.

    Design contract:
        is_error_candidate() is the only Error Intelligence work on the
        capture path (until maybe_enqueue_error_scan in Phase 6).
        Heavy parse/normalize/fingerprint runs in ErrorIntelWorker.

Dependencies:
    re, typing; talos.passive.classifier (parse_media_type, sniff_magic);
    talos.error_intel.constants
Data flow: (status, CT, headers, optional body/path) → bool
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Union

from talos.error_intel.constants import (
    DEFAULT_ERROR_HEADER_NAMES,
    DEFAULT_GATE_SNIFF_BYTES,
)
from talos.passive.classifier import parse_media_type, sniff_magic
from talos.passive.constants import SourceKind

# Content-Types that are never error-scan candidates (same spirit as passive).
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
    # Note: application/octet-stream is NOT rejected here — some servers
    # return it for plain-text 500s; magic + null-ratio sniff handle binaries.
})

# Path extensions that are pure static/binary assets when body is absent.
_REJECT_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".webm", ".wasm", ".exe", ".dll",
})

# Error-shaped JSON object keys with a *non-null / non-empty* value (BUG-14).
# Deliberately omits bare "message" / "detail" / "title" — common on healthy
# 2xx payloads. Rejects "error":null / "error":"" / "errors":[] / "error":{}.
_ERROR_JSON_KEY_RE = re.compile(
    r'"(?:error|errors|exception|fault|trace|stack|stackTrace|stack_trace|'
    r'errorMessage|error_message|errorCode|error_code|errorType|error_type)"\s*:\s*'
    r'(?!null\b|undefined\b|""|\'\'|\[\s*\]|\{\s*\})',
    re.IGNORECASE,
)

# Stack / exception markers (language families A + DB markers).
_STACK_MARKER_RE = re.compile(
    r"(?:"
    r"Traceback \(most recent call last\)|"
    r"Caused by:|"
    r"\bSQLSTATE(?:\[[^\]]+\])?|"
    r"\bORA-\d{5}\b|"
    r"\bjava\.(?:lang|sql|io|util)\.|"
    r"\bjavax\.|\bjakarta\.|"
    r"\bSQLException\b|"
    r"\bHibernate(?:Exception)?\b|"
    r"\bat com\.[A-Za-z0-9_.$]+|"
    r"\bSystem\.[A-Za-z0-9_.]+Exception\b|"
    r"\bStackTrace:|"
    r'File "[^"]+", line \d+|'
    r"\bUnhandledPromiseRejection\b|"
    r"\bTypeError:|\bReferenceError:|\bSyntaxError:|"
    r"\bFatal error:|\bParse error:|"
    r"\bCall to undefined |"
    r"\bNoMethodError\b|"
    r"\bpanic:|"
    r"goroutine \d+ \[|"
    r"thread '[^']+' panicked at|"
    r"\bNullReferenceException\b|"
    r"\bException in thread\b|"
    r"\bPHP (?:Warning|Notice|Fatal error)\b"
    r")",
    re.IGNORECASE,
)

# Strong framework / app-server error chrome for 2xx body gate (BUG-14).
# Weak product words alone (Laravel / ASP.NET / Internal Server Error) are
# common on healthy marketing/docs pages and must not enqueue on 2xx.
_FRAMEWORK_STRONG_CHROME_RE = re.compile(
    r"(?:"
    r"Whitelabel Error Page|"
    r"Werkzeug Debugger|"
    r"Server Error in '|"
    r"Whoops!|"
    r"Action Controller: Exception caught|"
    r"Django (?:Debug|Version)|"
    r"Traceback \(most recent call last\)|"
    r"__NEXT_ERROR__|"
    r"Symfony Exception|"
    r"Yellow Screen of Death|"
    r"type Status report"
    r")",
    re.IGNORECASE,
)

# Null-byte density threshold for "this is binary, stop sniffing".
_NULL_RATIO_REJECT = 0.02


def is_error_candidate(
    *,
    status_code: Optional[int] = None,
    content_type: Optional[str] = None,
    headers: Optional[Any] = None,
    body: Optional[Union[bytes, str]] = None,
    path: Optional[str] = None,
    truncated: bool = False,
    error_header_names: Optional[frozenset[str]] = None,
    gate_sniff_bytes: int = DEFAULT_GATE_SNIFF_BYTES,
) -> bool:
    """
    Purpose:
        Return True when the response looks error-like and should be
        enqueued for Error Intelligence analysis.

    Cheap rules (order matters for early exit):
        Reject — media/binary Content-Type; magic PNG/JPEG/PDF/WASM/…;
                 empty body with no error headers; pure static path with
                 no status/body signal.
        Allow  — HTTP 4xx/5xx with scannable body (or body deferred);
                 error/debug response headers;
                 stack / exception / framework markers in a short body sniff;
                 error-shaped JSON keys even on 2xx.

    Status is **not** required to be ≥400: exception dumps on 200 JSON
    still pass when the body sniff hits.

    Generic storage policy (`store_generic_http_errors`) is **not** applied
    here — the gate may accept a boring 404 HTML page; the worker/store
    layer decides whether Stage G clusters are persisted.

    Input:
        status_code        — HTTP status when known
        content_type       — response Content-Type (may be empty / None)
        headers            — dict, sequence of pairs, or raw header text
        body               — optional raw body (bytes or str) for empty +
                             magic + marker sniff
        path               — request path or URL (extension hard-reject aid)
        truncated          — capture truncated flag (API symmetry only)
        error_header_names — override default X-Exception-style allow-list
        gate_sniff_bytes   — max bytes to decode for marker sniff

    Output:
        True if the flow should be enqueued for error analysis.

    Side effects: None.

    Notes:
        `truncated` does not alone make a response a candidate.
        Config master switch (`enabled`) is applied by the caller
        (FlowWorker / observe_error), not here.
    """
    del truncated  # API symmetry with ErrorIntelJob; gate does not use it

    header_allow = error_header_names if error_header_names is not None else DEFAULT_ERROR_HEADER_NAMES
    has_err_hdr = _has_error_headers(headers, header_allow)

    body_bytes = _coerce_body_bytes(body)
    body_empty = body_bytes is not None and len(body_bytes) == 0
    body_present = body_bytes is not None and len(body_bytes) > 0

    # --- Hard rejects: media / binary ---------------------------------
    media = parse_media_type(content_type)
    if media in _REJECT_CT_EXACT:
        return False
    for prefix in _REJECT_CT_PREFIXES:
        if media.startswith(prefix):
            return False

    if body_present:
        magic = sniff_magic(body_bytes)
        if magic in (SourceKind.BINARY, SourceKind.WASM):
            return False

    # Empty body (b"") and deferred body (None) share the same gate rules for
    # error statuses: capture often stores an empty BLOB rather than NULL.
    # Worker may still no-op when there is nothing to parse.
    if body_empty or body_bytes is None:
        if has_err_hdr:
            return True
        if status_code is not None and _is_error_status(status_code):
            # Skip pure static asset paths when CT is also empty.
            if _path_looks_binary_asset(path) and not media:
                return False
            return True
        return False

    # body_present from here -------------------------------------------
    if has_err_hdr:
        return True

    if status_code is not None and _is_error_status(status_code):
        # 4xx/5xx with non-empty non-binary body is always a candidate.
        # Store layer may drop generic 404/400 later.
        return True

    # 2xx / unknown status: need body markers or framework chrome.
    if _body_has_error_signals(body_bytes, gate_sniff_bytes):
        return True

    return False


def is_error_candidate_from_flow(
    *,
    status_code: Optional[Union[int, str]] = None,
    content_type: Optional[str] = None,
    headers: Optional[Any] = None,
    body: Optional[Union[bytes, str]] = None,
    path: Optional[str] = None,
    truncated: bool = False,
    error_header_names: Optional[frozenset[str]] = None,
    gate_sniff_bytes: int = DEFAULT_GATE_SNIFF_BYTES,
) -> bool:
    """
    Purpose:
        Convenience wrapper when status_code may arrive as a string from DB.
    Input/Output/Side effects: same as is_error_candidate.
    """
    code: Optional[int] = None
    if status_code is not None and status_code != "":
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            code = None
    return is_error_candidate(
        status_code=code,
        content_type=content_type,
        headers=headers,
        body=body,
        path=path,
        truncated=truncated,
        error_header_names=error_header_names,
        gate_sniff_bytes=gate_sniff_bytes,
    )


def status_bucket(status_code: Optional[int], *, body_error_shaped: bool = False) -> str:
    """
    Purpose:
        Map an HTTP status to a fingerprint status bucket (Phase 4 prep).
    Input:
        status_code — HTTP status or None
        body_error_shaped — True when 2xx body carried error markers
    Output:
        One of STATUS_BUCKET_* string constants.
    Side effects: None.
    """
    from talos.error_intel.constants import (
        STATUS_BUCKET_2XX_ERROR_BODY,
        STATUS_BUCKET_4XX,
        STATUS_BUCKET_5XX,
        STATUS_BUCKET_NONE,
        STATUS_BUCKET_OTHER,
    )

    if status_code is None:
        return STATUS_BUCKET_NONE
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return STATUS_BUCKET_NONE
    if 500 <= code <= 599:
        return STATUS_BUCKET_5XX
    if 400 <= code <= 499:
        return STATUS_BUCKET_4XX
    if 200 <= code <= 299 and body_error_shaped:
        return STATUS_BUCKET_2XX_ERROR_BODY
    if 200 <= code <= 299:
        return STATUS_BUCKET_OTHER
    return STATUS_BUCKET_OTHER


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _is_error_status(status_code: int) -> bool:
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return False
    return 400 <= code <= 599


def _coerce_body_bytes(body: Optional[Union[bytes, str]]) -> Optional[bytes]:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", errors="replace")
    return None


def _path_looks_binary_asset(path: Optional[str]) -> bool:
    if not path:
        return False
    # strip query / fragment; take final path segment extension
    raw = str(path).split("?", 1)[0].split("#", 1)[0]
    if "://" in raw:
        # keep path component only
        try:
            from urllib.parse import urlparse
            raw = urlparse(raw).path or ""
        except Exception:
            raw = raw.rsplit("/", 1)[-1]
    lower = raw.lower()
    dot = lower.rfind(".")
    if dot < 0:
        return False
    ext = lower[dot:]
    # handle .js.map style — only last extension
    return ext in _REJECT_EXTENSIONS


def _has_error_headers(
    headers: Optional[Any],
    allow: frozenset[str],
) -> bool:
    if not headers or not allow:
        return False
    names = _header_names(headers)
    for name in names:
        if name in allow:
            return True
    return False


def _header_names(headers: Any) -> set[str]:
    """Extract lowercased header names from dict / pairs / raw text."""
    names: set[str] = set()
    if isinstance(headers, Mapping):
        for key in headers.keys():
            if key is None:
                continue
            names.add(str(key).strip().lower())
        return names
    if isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 1:
                names.add(str(item[0]).strip().lower())
            elif isinstance(item, str) and ":" in item:
                names.add(item.split(":", 1)[0].strip().lower())
        return names
    if isinstance(headers, str):
        for line in headers.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("http/"):
                continue
            if ":" in line:
                names.add(line.split(":", 1)[0].strip().lower())
        return names
    return names


def _body_has_error_signals(body: bytes, sniff_bytes: int) -> bool:
    """Short-window text sniff for stack markers, JSON keys, framework chrome."""
    limit = max(256, int(sniff_bytes) if sniff_bytes else DEFAULT_GATE_SNIFF_BYTES)
    sample = body[:limit]
    if not sample:
        return False
    # Binary-ish: too many NULs → do not treat as text error page
    nulls = sample.count(b"\x00")
    if nulls and nulls / max(len(sample), 1) >= _NULL_RATIO_REJECT:
        return False

    try:
        text = sample.decode("utf-8", errors="replace")
    except Exception:
        text = sample.decode("latin-1", errors="replace")

    if not text or not text.strip():
        return False

    if _STACK_MARKER_RE.search(text):
        return True
    if _ERROR_JSON_KEY_RE.search(text):
        return True
    # 2xx path only reaches here — require strong error chrome, not product names.
    if _FRAMEWORK_STRONG_CHROME_RE.search(text):
        return True
    return False
