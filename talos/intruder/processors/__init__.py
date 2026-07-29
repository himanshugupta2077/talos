"""
Package: talos.intruder.processors

Purpose:
    Payload processors (url_encode, base64_encode) applied after generation.
"""

from __future__ import annotations

import base64
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    PROC_BASE64_ENCODE,
    PROC_URL_ENCODE,
)


@runtime_checkable
class PayloadProcessor(Protocol):
    def process(self, value: str, context: dict[str, Any] | None = None) -> str: ...


class UrlEncodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        # Encode all specials including slash (safe="").
        return quote(value, safe="")


class Base64EncodeProcessor:
    def process(self, value: str, context: dict[str, Any] | None = None) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")


_REGISTRY: dict[str, type] = {
    PROC_URL_ENCODE: UrlEncodeProcessor,
    PROC_BASE64_ENCODE: Base64EncodeProcessor,
}


def build_processor(name: str) -> PayloadProcessor:
    key = (name or "").strip().lower()
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


__all__ = [
    "PayloadProcessor",
    "UrlEncodeProcessor",
    "Base64EncodeProcessor",
    "build_processor",
    "apply_processors",
]
