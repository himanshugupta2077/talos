"""
Package: talos.intruder.processors

Purpose:
    Payload processors applied after generation (Phase 1 + Phase 2).

    Phase 1: url_encode, base64_encode
    Phase 2: url_decode, base64_decode, to_lower, to_upper, html_encode,
             html_decode, md5, sha1, sha256, strip, prefix:<text>, suffix:<text>
"""

from __future__ import annotations

import base64
import hashlib
import html
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, unquote

from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    KNOWN_PROCESSORS,
    PROC_BASE64_DECODE,
    PROC_BASE64_ENCODE,
    PROC_HTML_DECODE,
    PROC_HTML_ENCODE,
    PROC_MD5,
    PROC_SHA1,
    PROC_SHA256,
    PROC_STRIP,
    PROC_TO_LOWER,
    PROC_TO_UPPER,
    PROC_URL_DECODE,
    PROC_URL_ENCODE,
)


@runtime_checkable
class PayloadProcessor(Protocol):
    def process(self, value: str, context: dict[str, Any] | None = None) -> str: ...


class UrlEncodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return quote(value, safe="")


class UrlDecodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return unquote(value)


class Base64EncodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")


class Base64DecodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        # Tolerate missing padding.
        raw = value.encode("ascii", errors="ignore")
        pad = (-len(raw)) % 4
        if pad:
            raw = raw + b"=" * pad
        try:
            return base64.b64decode(raw, validate=False).decode("utf-8", errors="replace")
        except Exception:
            return ""


class ToLowerProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return value.lower()


class ToUpperProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return value.upper()


class HtmlEncodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return html.escape(value, quote=True)


class HtmlDecodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return html.unescape(value)


class Md5Processor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return hashlib.md5(value.encode("utf-8")).hexdigest()


class Sha1Processor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return hashlib.sha1(value.encode("utf-8")).hexdigest()


class Sha256Processor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


class StripProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return value.strip()


class PrefixProcessor:
    def __init__(self, prefix: str) -> None:
        self._prefix = prefix

    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return self._prefix + value


class SuffixProcessor:
    def __init__(self, suffix: str) -> None:
        self._suffix = suffix

    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return value + self._suffix


_REGISTRY: dict[str, type] = {
    PROC_URL_ENCODE: UrlEncodeProcessor,
    PROC_URL_DECODE: UrlDecodeProcessor,
    PROC_BASE64_ENCODE: Base64EncodeProcessor,
    PROC_BASE64_DECODE: Base64DecodeProcessor,
    PROC_TO_LOWER: ToLowerProcessor,
    PROC_TO_UPPER: ToUpperProcessor,
    PROC_HTML_ENCODE: HtmlEncodeProcessor,
    PROC_HTML_DECODE: HtmlDecodeProcessor,
    PROC_MD5: Md5Processor,
    PROC_SHA1: Sha1Processor,
    PROC_SHA256: Sha256Processor,
    PROC_STRIP: StripProcessor,
}


def _is_known_processor_name(name: str) -> bool:
    """True if name is a registered processor or parameterized prefix:/suffix:."""
    key = (name or "").strip().lower()
    if key in _REGISTRY:
        return True
    if key.startswith("prefix:") or key.startswith("suffix:"):
        return True
    return False


def is_known_processor(name: str) -> bool:
    """Public check used by config validation."""
    return _is_known_processor_name(name)


def build_processor(name: str) -> PayloadProcessor:
    """
    Build a processor by name.

    Parameterized forms:
        prefix:<text>  — prepend text (text may be empty)
        suffix:<text>  — append text
    """
    raw = (name or "").strip()
    key = raw.lower()
    if key.startswith("prefix:"):
        # Preserve original case of the prefix payload after the colon.
        return PrefixProcessor(raw[len("prefix:") :])
    if key.startswith("suffix:"):
        return SuffixProcessor(raw[len("suffix:") :])
    cls = _REGISTRY.get(key)
    if cls is None:
        raise ValueError(f"{ERR_UNKNOWN_PLUGIN}:processor:{name}")
    return cls()


def apply_processors(
    value: str,
    processor_names: list[str],
    context: dict[str, Any] | None = None,
) -> str:
    out = value
    for name in processor_names or []:
        proc = build_processor(name)
        out = proc.process(out, context)
    return out


def list_processors() -> list[str]:
    """Stable sorted inventory of built-in (non-parameterized) processors."""
    return sorted(KNOWN_PROCESSORS)


__all__ = [
    "PayloadProcessor",
    "UrlEncodeProcessor",
    "UrlDecodeProcessor",
    "Base64EncodeProcessor",
    "Base64DecodeProcessor",
    "ToLowerProcessor",
    "ToUpperProcessor",
    "HtmlEncodeProcessor",
    "HtmlDecodeProcessor",
    "Md5Processor",
    "Sha1Processor",
    "Sha256Processor",
    "StripProcessor",
    "PrefixProcessor",
    "SuffixProcessor",
    "build_processor",
    "apply_processors",
    "is_known_processor",
    "list_processors",
]
