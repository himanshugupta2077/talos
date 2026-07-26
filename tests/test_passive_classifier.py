"""
Golden tests for talos.passive.classifier.classify_source.

CT / path / sniff priority, source maps, mislabeled content-types,
binary magic.  No worker wiring.
"""

from __future__ import annotations

import pytest

from talos.passive.classifier import (
    classify_source,
    is_scannable_kind,
    parse_media_type,
    path_extension,
    path_for_classification,
    path_has_source_hint,
    sniff_magic,
)
from talos.passive.constants import SourceKind

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 8
PDF = b"%PDF-1.7\n"
WASM = b"\x00asm\x01\x00\x00\x00"


def test_parse_media_type_strips_charset() -> None:
    assert parse_media_type("text/html; charset=UTF-8") == "text/html"
    assert parse_media_type(None) == ""
    assert parse_media_type("  Application/JSON ") == "application/json"


def test_path_helpers() -> None:
    assert path_for_classification("https://ex.com/A/B.JS?x=1#h") == "/a/b.js"
    assert path_extension("/static/app.deadbeef.js") == ".js"
    assert path_extension("/static/app.js.map") == ".map"
    assert path_has_source_hint("/cdn/env.js")
    assert path_has_source_hint("/api/swagger/v1")
    assert not path_has_source_hint("/img/logo")


# ---------------------------------------------------------------------------
# Content-Type driven
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "content_type,expected",
    [
        ("text/html", SourceKind.HTML),
        ("text/html; charset=utf-8", SourceKind.HTML),
        ("application/javascript", SourceKind.JAVASCRIPT),
        ("text/javascript", SourceKind.JAVASCRIPT),
        ("application/json", SourceKind.JSON),
        ("application/ld+json", SourceKind.JSON),
        ("application/vnd.api+json", SourceKind.JSON),
        ("application/xml", SourceKind.XML),
        ("text/xml", SourceKind.XML),
        ("text/plain", SourceKind.TEXT),
        ("text/css", SourceKind.CSS),
        ("application/wasm", SourceKind.WASM),
        ("application/pdf", SourceKind.BINARY),
        ("image/png", SourceKind.BINARY),
        ("video/mp4", SourceKind.BINARY),
        ("font/woff2", SourceKind.BINARY),
    ],
)
def test_classify_by_content_type(content_type: str, expected: SourceKind) -> None:
    assert classify_source(content_type=content_type) == expected


# ---------------------------------------------------------------------------
# Path driven
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path,expected",
    [
        ("/static/app.js", SourceKind.JAVASCRIPT),
        ("/a.mjs", SourceKind.JAVASCRIPT),
        ("/a.cjs", SourceKind.JAVASCRIPT),
        ("/a.tsx", SourceKind.JAVASCRIPT),
        ("/data.json", SourceKind.JSON),
        ("/bundle.js.map", SourceKind.SOURCEMAP),
        ("/index.html", SourceKind.HTML),
        ("/styles.css", SourceKind.CSS),
        ("/feed.xml", SourceKind.XML),
        ("/icon.svg", SourceKind.XML),
        ("/readme.txt", SourceKind.TEXT),
        ("/x.png", SourceKind.BINARY),
        ("/x.pdf", SourceKind.BINARY),
        ("/m.wasm", SourceKind.WASM),
    ],
)
def test_classify_by_path_extension(path: str, expected: SourceKind) -> None:
    assert classify_source(path=path) == expected


def test_json_ct_with_map_path_is_sourcemap() -> None:
    assert (
        classify_source(
            content_type="application/json",
            path="/static/app.js.map",
        )
        == SourceKind.SOURCEMAP
    )


def test_text_plain_refined_by_js_extension() -> None:
    assert (
        classify_source(
            content_type="text/plain",
            path="/static/app.js",
        )
        == SourceKind.JAVASCRIPT
    )


def test_path_hints() -> None:
    assert (
        classify_source(
            content_type="application/octet-stream",
            path="/assets/env.js",
        )
        == SourceKind.JAVASCRIPT
    )
    assert (
        classify_source(
            content_type="application/octet-stream",
            path="/v1/swagger",
        )
        == SourceKind.JSON
    )


# ---------------------------------------------------------------------------
# Magic + sniff
# ---------------------------------------------------------------------------

def test_magic_overrides_lying_content_type() -> None:
    assert classify_source("text/plain", "/x.txt", body=PNG) == SourceKind.BINARY
    assert classify_source("application/javascript", "/a.js", body=JPEG) == SourceKind.BINARY
    assert classify_source("text/html", "/a", body=PDF) == SourceKind.BINARY
    assert classify_source(None, None, body=WASM) == SourceKind.WASM


def test_sniff_magic_helper() -> None:
    assert sniff_magic(PNG) == SourceKind.BINARY
    assert sniff_magic(WASM) == SourceKind.WASM
    assert sniff_magic(b"const x = 1") is None


def test_sniff_javascript() -> None:
    body = b"function boot() { return 1; }\n"
    assert (
        classify_source(
            content_type="application/octet-stream",
            path="/unknown",
            body=body,
        )
        == SourceKind.JAVASCRIPT
    )


def test_sniff_json() -> None:
    body = b'{"version": 3, "ok": true}\n'
    kind = classify_source(path="/blob", body=body)
    assert kind in (SourceKind.JSON, SourceKind.SOURCEMAP)


def test_sniff_sourcemap() -> None:
    body = b'{"version":3,"sources":["a.ts"],"mappings":"AAAA"}\n'
    assert (
        classify_source(path="/x", body=body) == SourceKind.SOURCEMAP
    )


def test_sniff_html() -> None:
    body = b"<!DOCTYPE html><html><head></head></html>"
    assert classify_source(path="/x", body=body) == SourceKind.HTML


def test_sniff_xml() -> None:
    body = b'<?xml version="1.0"?><root/>'
    assert classify_source(path="/x", body=body) == SourceKind.XML


def test_binary_payload_no_signals() -> None:
    body = bytes(range(256)) * 2
    assert classify_source(path="/download", body=body) == SourceKind.BINARY


def test_empty_unknown() -> None:
    assert classify_source() == SourceKind.UNKNOWN
    assert classify_source(content_type="", path="", body=None) == SourceKind.UNKNOWN


def test_is_scannable_kind() -> None:
    assert is_scannable_kind(SourceKind.JAVASCRIPT)
    assert is_scannable_kind(SourceKind.SOURCEMAP)
    assert not is_scannable_kind(SourceKind.BINARY)
    assert not is_scannable_kind(SourceKind.WASM)
    assert not is_scannable_kind(SourceKind.UNKNOWN)


def test_full_url_path_classification() -> None:
    assert (
        classify_source(
            path="https://cdn.example/static/app.abc123.js?v=2",
        )
        == SourceKind.JAVASCRIPT
    )
