"""
Module: talos.passive.normalize

Purpose:
    Convert raw response body bytes into scan text for detectors.

    Charset resolution order:
        1. charset= parameter from Content-Type (when present and known)
        2. UTF-8 (strict, then replace)
        3. Latin-1 (never fails for arbitrary bytes)

    Truncation is recorded from the capture flag; this module does not
    re-truncate unless max_chars is set (optional safety for tests/workers).

    Never claims decryption — this is encoding/charset decode only.

Dependencies: codecs, dataclasses, re (stdlib)
Data flow: body bytes + content_type → NormalizeResult (text + metadata)
Side effects: None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# charset=... in Content-Type (quoted or bare)
_CHARSET_RE = re.compile(
    r"charset\s*=\s*([\"']?)([^\s\"';,]+)\1",
    re.IGNORECASE,
)

# Aliases → codecs name
_CHARSET_ALIASES: dict[str, str] = {
    "utf8": "utf-8",
    "utf-8": "utf-8",
    "utf-16": "utf-16",
    "utf-16le": "utf-16-le",
    "utf-16be": "utf-16-be",
    "ascii": "ascii",
    "us-ascii": "ascii",
    "latin1": "latin-1",
    "latin-1": "latin-1",
    "iso-8859-1": "latin-1",
    "iso8859-1": "latin-1",
    "cp1252": "cp1252",
    "windows-1252": "cp1252",
}


@dataclass(frozen=True)
class NormalizeResult:
    """
    Purpose:
        Immutable result of body → text normalization.

    Fields:
        text              — decoded scan text (may be empty)
        encoding          — codec name actually used
        truncated         — True if capture (or max_chars) truncated content
        body_size         — raw byte length of input body
        had_decode_errors — True if replacement characters were required
        charset_declared  — charset from Content-Type, or None
    """

    text: str
    encoding: str
    truncated: bool
    body_size: int
    had_decode_errors: bool = False
    charset_declared: Optional[str] = None


def extract_charset(content_type: Optional[str]) -> Optional[str]:
    """
    Purpose:
        Parse charset parameter from a Content-Type header.
    Input:
        content_type — full header value or None
    Output:
        Normalized codec name, or None if absent/unknown alias kept as raw
        lowercased token for callers that want to try codecs.lookup later.
    Side effects: None.
    """
    if not content_type:
        return None
    match = _CHARSET_RE.search(str(content_type))
    if not match:
        return None
    raw = match.group(2).strip().lower()
    if not raw:
        return None
    return _CHARSET_ALIASES.get(raw, raw)


def normalize_body(
    body: Optional[bytes],
    *,
    content_type: Optional[str] = None,
    truncated: bool = False,
    max_chars: Optional[int] = None,
) -> NormalizeResult:
    """
    Purpose:
        Decode response body bytes to Unicode text for the detector pipeline.

    Input:
        body          — raw response_body bytes (None treated as empty)
        content_type  — optional Content-Type (charset= used when present)
        truncated     — True when capture already truncated the body
        max_chars     — optional hard cap on output character count (worker
                        safety); when hit, truncated becomes True

    Output:
        NormalizeResult with text and decode metadata.

    Side effects: None.
    """
    if body is None:
        body = b""
    body_size = len(body)
    declared = extract_charset(content_type)

    text, encoding, had_errors = _decode_bytes(body, declared)

    out_truncated = bool(truncated)
    if max_chars is not None and max_chars >= 0 and len(text) > max_chars:
        text = text[:max_chars]
        out_truncated = True

    return NormalizeResult(
        text=text,
        encoding=encoding,
        truncated=out_truncated,
        body_size=body_size,
        had_decode_errors=had_errors,
        charset_declared=declared,
    )


def _decode_bytes(
    body: bytes,
    declared_charset: Optional[str],
) -> tuple[str, str, bool]:
    """
    Purpose:
        Try declared charset → utf-8 → latin-1.
    Output:
        (text, encoding_used, had_decode_errors)
    Side effects: None.
    """
    if not body:
        return "", declared_charset or "utf-8", False

    # Strip UTF-8 BOM if present when trying utf-8 family
    candidates: list[str] = []
    if declared_charset:
        candidates.append(declared_charset)
    if "utf-8" not in candidates:
        candidates.append("utf-8")
    if "latin-1" not in candidates:
        candidates.append("latin-1")

    last_error: Optional[Exception] = None
    for enc in candidates:
        try:
            # Strict first for quality signal
            return body.decode(enc), enc, False
        except (LookupError, UnicodeDecodeError) as exc:
            last_error = exc
            continue

    # Fallback: utf-8 with replacement (should rarely hit if latin-1 tried)
    try:
        text = body.decode("utf-8", errors="replace")
        had = "\ufffd" in text
        return text, "utf-8", had
    except Exception:
        # Absolute last resort
        text = body.decode("latin-1", errors="replace")
        return text, "latin-1", True if last_error else False
