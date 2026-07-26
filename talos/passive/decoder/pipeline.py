"""
Module: talos.passive.decoder.pipeline

Purpose:
    Depth-limited multi-codec decoder for Passive Source Intelligence.

    Never claims decryption.  Pure Base64 / hex blobs produce DecodeResult
    only — findings come from rescanning decoded text with secret detectors.

    Codecs (try order per step):
        url → html entity → unicode/JS escape → base64url → base64 → hex

    Resource limits:
        max_decode_depth (default 3)
        max_decode_bytes (decoded expansion cap)
        max_candidates per document

Dependencies: base64, binascii, html, re, urllib.parse; models.DecodeResult
Data flow: text → extract_decode_candidates → decode_candidate → DecodeResult
Side effects: None.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, unquote_plus

from talos.passive.constants import (
    DEFAULT_MAX_DECODE_BYTES,
    DEFAULT_MAX_DECODE_DEPTH,
)
from talos.passive.models import DecodeResult

# Candidate shapes pulled from source text
_B64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])"
)
_B64URL_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_\-=])([A-Za-z0-9_\-]{16,}={0,2})(?![A-Za-z0-9_\-=])"
)
_HEX_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f])((?:0x)?[0-9A-Fa-f]{16,})(?![0-9A-Fa-f])"
)
_URL_CANDIDATE = re.compile(
    r"(?:%[0-9A-Fa-f]{2}){4,}"
)
_HTML_ENTITY_CANDIDATE = re.compile(
    r"(?:&#\d+;|&#x[0-9A-Fa-f]+;|&[a-zA-Z]+;){3,}"
)
_UNICODE_ESCAPE_CANDIDATE = re.compile(
    r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\U[0-9A-Fa-f]{8}){4,}"
)

# data: URI image payloads — skip (not secret scan targets for decoder)
_DATA_URI_IMAGE = re.compile(
    r"data:image/[a-zA-Z0-9.+-]+;base64,",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DecodeCandidate:
    """
    Purpose:
        One blob extracted from source text for decoding.
    Fields:
        value — candidate string
        start / end — offsets in original text
        hint — optional codec hint (base64, hex, …)
    """

    value: str
    start: int
    end: int
    hint: str = ""


def extract_decode_candidates(
    text: str,
    *,
    max_candidates: int = 100,
) -> list[DecodeCandidate]:
    """
    Purpose:
        Pull encode-looking substrings from text for the decoder pipeline.
    Input:
        text / max_candidates cap
    Output:
        list[DecodeCandidate] (deduped by start offset, capped)
    Side effects: None.
    """
    if not text:
        return []

    # Skip entire image data-URIs regions
    skip_ranges: list[tuple[int, int]] = []
    for m in _DATA_URI_IMAGE.finditer(text):
        # Skip from start of data: to end of base64 run
        start = m.start()
        rest = text[m.end() :]
        end_m = re.match(r"[A-Za-z0-9+/=]+", rest)
        end = m.end() + (end_m.end() if end_m else 0)
        skip_ranges.append((start, end))

    def _in_skip(pos: int) -> bool:
        for a, b in skip_ranges:
            if a <= pos < b:
                return True
        return False

    found: list[DecodeCandidate] = []
    seen_starts: set[int] = set()

    def _add(value: str, start: int, end: int, hint: str) -> None:
        if start in seen_starts or _in_skip(start):
            return
        if not value or len(value) < 8:
            return
        seen_starts.add(start)
        found.append(DecodeCandidate(value=value, start=start, end=end, hint=hint))

    for m in _URL_CANDIDATE.finditer(text):
        _add(m.group(0), m.start(), m.end(), "url")
        if len(found) >= max_candidates:
            return found

    for m in _HTML_ENTITY_CANDIDATE.finditer(text):
        _add(m.group(0), m.start(), m.end(), "html")
        if len(found) >= max_candidates:
            return found

    for m in _UNICODE_ESCAPE_CANDIDATE.finditer(text):
        _add(m.group(0), m.start(), m.end(), "unicode")
        if len(found) >= max_candidates:
            return found

    for m in _B64_CANDIDATE.finditer(text):
        _add(m.group(1), m.start(1), m.end(1), "base64")
        if len(found) >= max_candidates:
            return found

    for m in _B64URL_CANDIDATE.finditer(text):
        # Avoid double-adding pure base64 already captured
        if m.start(1) in seen_starts:
            continue
        _add(m.group(1), m.start(1), m.end(1), "base64url")
        if len(found) >= max_candidates:
            return found

    for m in _HEX_CANDIDATE.finditer(text):
        raw = m.group(1)
        if raw.lower().startswith("0x"):
            raw = raw[2:]
        if len(raw) % 2 != 0:
            continue
        _add(raw, m.start(1), m.end(1), "hex")
        if len(found) >= max_candidates:
            return found

    return found


def try_decode_once(
    value: str,
    *,
    max_bytes: int = DEFAULT_MAX_DECODE_BYTES,
    prefer: Optional[str] = None,
) -> Optional[tuple[str, str]]:
    """
    Purpose:
        Attempt a single codec decode step.
    Input:
        value     — candidate string
        max_bytes — reject expansions larger than this
        prefer    — optional codec hint to try first
    Output:
        (decoded_text, codec_name) or None if no codec succeeds
    Side effects: None.
    """
    if not value or len(value) > max_bytes * 2:
        return None

    order = ["url", "html", "unicode", "base64url", "base64", "hex"]
    if prefer and prefer in order:
        order = [prefer] + [c for c in order if c != prefer]

    for codec in order:
        decoded = _apply_codec(value, codec, max_bytes=max_bytes)
        if decoded is None:
            continue
        if decoded == value:
            continue
        if not decoded or len(decoded.encode("utf-8", errors="replace")) > max_bytes:
            continue
        # Require printable-ish output (avoid binary noise)
        if not _looks_like_text(decoded):
            continue
        return decoded, codec
    return None


def decode_candidate(
    value: str,
    *,
    max_depth: int = DEFAULT_MAX_DECODE_DEPTH,
    max_bytes: int = DEFAULT_MAX_DECODE_BYTES,
    prefer: Optional[str] = None,
) -> DecodeResult:
    """
    Purpose:
        Iteratively decode a candidate up to max_depth codecs.
    Input:
        value / max_depth / max_bytes / prefer hint
    Output:
        DecodeResult (success=True when ≥1 step applied)
    Side effects: None.
    """
    if not value:
        return DecodeResult(
            original=value or "",
            decoded="",
            success=False,
            error="empty",
        )

    current = value
    chain: list[str] = []
    depth = 0
    last_error: Optional[str] = None

    while depth < max_depth:
        if len(current.encode("utf-8", errors="replace")) > max_bytes:
            last_error = "max_decode_bytes"
            break
        step = try_decode_once(
            current,
            max_bytes=max_bytes,
            prefer=prefer if depth == 0 else None,
        )
        if step is None:
            break
        decoded, codec = step
        # Prevent expansion bombs: each step must not explode wildly
        if len(decoded) > max(len(current) * 8, 64) and len(decoded) > max_bytes // 4:
            # Allow moderate expansion; hard stop on huge jumps past cap fraction
            if len(decoded.encode("utf-8", errors="replace")) > max_bytes:
                last_error = "expansion_limit"
                break
        chain.append(codec)
        current = decoded
        depth += 1
        prefer = None  # only first step uses hint

    if not chain:
        return DecodeResult(
            original=value,
            decoded=value,
            encoding_chain=[],
            depth=0,
            success=False,
            error=last_error or "no_codec",
        )

    return DecodeResult(
        original=value,
        decoded=current,
        encoding_chain=chain,
        depth=depth,
        success=True,
        error=last_error,
    )


# ------------------------------------------------------------------ #
# Codec implementations                                                #
# ------------------------------------------------------------------ #

def _apply_codec(value: str, codec: str, *, max_bytes: int) -> Optional[str]:
    """Apply one named codec; return decoded str or None. Side effects: None."""
    try:
        if codec == "url":
            if "%" not in value and "+" not in value:
                return None
            out = unquote_plus(value)
            if out != value:
                return out
            out2 = unquote(value)
            return out2 if out2 != value else None
        if codec == "html":
            if "&" not in value:
                return None
            out = html.unescape(value)
            return out if out != value else None
        if codec == "unicode":
            if "\\u" not in value and "\\x" not in value and "\\U" not in value:
                return None
            return _decode_js_escapes(value)
        if codec == "base64":
            return _decode_base64(value, urlsafe=False, max_bytes=max_bytes)
        if codec == "base64url":
            return _decode_base64(value, urlsafe=True, max_bytes=max_bytes)
        if codec == "hex":
            return _decode_hex(value, max_bytes=max_bytes)
    except Exception:
        return None
    return None


def _decode_base64(value: str, *, urlsafe: bool, max_bytes: int) -> Optional[str]:
    """Decode standard or URL-safe base64 to UTF-8 text. Side effects: None."""
    cleaned = value.strip().replace("\n", "").replace("\r", "")
    if len(cleaned) < 12:
        return None
    # Base64 length should be plausible
    if not re.fullmatch(r"[A-Za-z0-9_\-+/]+=*", cleaned):
        return None
    pad = (-len(cleaned)) % 4
    padded = cleaned + ("=" * pad)
    try:
        if urlsafe:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if len(raw) > max_bytes or len(raw) == 0:
        return None
    # Reject if mostly non-text
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if not _looks_like_text(text):
        return None
    return text


def _decode_hex(value: str, *, max_bytes: int) -> Optional[str]:
    """Decode even-length hex to UTF-8 text. Side effects: None."""
    cleaned = value.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) < 16 or len(cleaned) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return None
    try:
        raw = binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError):
        return None
    if len(raw) > max_bytes or len(raw) == 0:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if not _looks_like_text(text):
        return None
    return text


def _decode_js_escapes(value: str) -> Optional[str]:
    """
    Purpose:
        Decode \\uXXXX / \\xHH / \\UXXXXXXXX sequences.
    Output:
        Decoded string or None if nothing changed / invalid.
    Side effects: None.
    """
    if not value:
        return None

    def _u(m: re.Match[str]) -> str:
        return chr(int(m.group(1), 16))

    out = value
    out2 = re.sub(r"\\u([0-9A-Fa-f]{4})", _u, out)
    out2 = re.sub(r"\\x([0-9A-Fa-f]{2})", _u, out2)
    out2 = re.sub(r"\\U([0-9A-Fa-f]{8})", _u, out2)
    if out2 == value:
        return None
    return out2


def _looks_like_text(value: str) -> bool:
    """
    Purpose:
        Heuristic: decoded payload should be mostly printable text.
    Side effects: None.
    """
    if not value:
        return False
    # Reject NULs and high binary ratio
    if "\x00" in value:
        return False
    sample = value[:4000]
    printable = sum(
        1
        for ch in sample
        if ch.isprintable() or ch in "\n\r\t"
    )
    return (printable / max(1, len(sample))) >= 0.85
