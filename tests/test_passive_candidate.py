"""
Golden tests for talos.passive.candidate.is_source_candidate.

Content-type matrix, path matrix, magic-byte rejects (PNG/JPEG/PDF),
empty body / status edge cases.  No FlowWorker wiring.
"""

from __future__ import annotations

import pytest

from talos.passive.candidate import (
    is_source_candidate,
    is_source_candidate_from_flow,
)

# Minimal real magic prefixes (not full files)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
GIF = b"GIF89a" + b"\x00" * 16
PDF = b"%PDF-1.4\n%" + b"\x00" * 16
WASM = b"\x00asm" + b"\x01\x00\x00\x00"
ZIP = b"PK\x03\x04" + b"\x00" * 16

JS_BODY = b"const apiKey = 'x';\n"
JSON_BODY = b'{"ok": true}\n'
HTML_BODY = b"<!DOCTYPE html><html><body>hi</body></html>"
EMPTY = b""


# ---------------------------------------------------------------------------
# Content-Type allow matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "content_type,path,expected",
    [
        ("text/html", "/index", True),
        ("text/html; charset=utf-8", "/page", True),
        ("application/xhtml+xml", "/a", True),
        ("application/javascript", "/static/app.js", True),
        ("text/javascript", "/x", True),
        ("application/x-javascript", "/x", True),
        ("application/json", "/api/config", True),
        ("application/json; charset=utf-8", "/api", True),
        ("application/ld+json", "/ld", True),
        ("text/plain", "/readme.txt", True),
        ("text/css", "/styles.css", True),
        ("application/xml", "/feed.xml", True),
        ("text/xml", "/x", True),
        ("application/manifest+json", "/manifest.webmanifest", True),
    ],
)
def test_allow_content_types(
    content_type: str, path: str, expected: bool
) -> None:
    assert (
        is_source_candidate(content_type, path, body=JS_BODY if "javascript" in content_type or content_type.startswith("text/html") else JSON_BODY)
        is expected
    )


@pytest.mark.parametrize(
    "content_type",
    [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",  # still image/* prefix — reject at gate (XML via path ok)
        "video/mp4",
        "audio/mpeg",
        "font/woff2",
        "application/font-woff",
        "application/pdf",
        "application/zip",
        "application/wasm",
        "multipart/form-data",
    ],
)
def test_reject_media_content_types(content_type: str) -> None:
    # Even with a .js path, explicit media CT rejects (except we still check —
    # design: CT reject prefixes win for image/* etc.)
    assert is_source_candidate(content_type, "/static/app.js", body=JS_BODY) is False


def test_svg_via_extension_without_image_ct() -> None:
    """SVG as .svg path with XML-ish body is source-like (XML kind)."""
    body = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>'
    assert is_source_candidate("image/svg+xml", "/icon.svg", body=body) is False
    assert is_source_candidate("application/xml", "/icon.svg", body=body) is True


# ---------------------------------------------------------------------------
# Path matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path,expected",
    [
        ("/static/app.js", True),
        ("/assets/main.mjs", True),
        ("/bundle.cjs", True),
        ("/app.tsx", True),
        ("/config.json", True),
        ("/static/app.js.map", True),
        ("/index.html", True),
        ("/styles.css", True),
        ("/feed.xml", True),
        ("/notes.txt", True),
        ("/api/v1/swagger.json", True),
        ("/openapi.yaml", True),
        ("/config/env.js", True),
        ("/cdn/app.a1b2c3d4.js", True),
        # rejects
        ("/img/logo.png", False),
        ("/photo.JPEG", False),
        ("/doc.pdf", False),
        ("/font.woff2", False),
        ("/video.mp4", False),
        ("/module.wasm", False),
        ("/archive.zip", False),
    ],
)
def test_path_extension_matrix(path: str, expected: bool) -> None:
    # Empty CT — path extension / hints decide (no body required for extensions).
    assert is_source_candidate(None, path, body=None) is expected
    assert is_source_candidate("", path, body=None) is expected


def test_path_hints_without_extension() -> None:
    assert is_source_candidate(
        "application/octet-stream",
        "/assets/env.js",
        body=JS_BODY,
    )
    assert is_source_candidate(
        "application/octet-stream",
        "/api/swagger",
        body=JSON_BODY,
    )


def test_octet_stream_with_js_path() -> None:
    assert is_source_candidate(
        "application/octet-stream",
        "/static/vendor.js",
        body=JS_BODY,
    )


def test_octet_stream_without_path_or_text_sniff() -> None:
    # Binary-ish payload, no path → not a candidate
    assert (
        is_source_candidate(
            "application/octet-stream",
            "/download",
            body=b"\x00\x01\x02\x03" + bytes(range(64)),
        )
        is False
    )


def test_octet_stream_text_sniff_json() -> None:
    assert is_source_candidate(
        "application/octet-stream",
        "/unknown",
        body=b'{"version": 1, "config": true}\n',
    )


def test_empty_ct_js_path() -> None:
    assert is_source_candidate(None, "/app.js", body=JS_BODY)
    assert is_source_candidate("", "/app.js", body=JS_BODY)


# ---------------------------------------------------------------------------
# Magic-byte rejects (PNG / JPEG / PDF) even if CT lies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,body",
    [
        ("png", PNG),
        ("jpeg", JPEG),
        ("gif", GIF),
        ("pdf", PDF),
        ("wasm", WASM),
        ("zip", ZIP),
    ],
)
def test_reject_magic_binary_despite_text_ct(label: str, body: bytes) -> None:
    assert (
        is_source_candidate("text/plain", f"/file.{label}", body=body) is False
    )
    assert (
        is_source_candidate("application/javascript", "/app.js", body=body) is False
    )


def test_reject_png_path() -> None:
    assert is_source_candidate("image/png", "/x.png", body=PNG) is False
    assert is_source_candidate(None, "/x.png", body=PNG) is False


def test_reject_jpeg_path() -> None:
    assert is_source_candidate("image/jpeg", "/x.jpg", body=JPEG) is False


def test_reject_pdf_path() -> None:
    assert is_source_candidate("application/pdf", "/doc.pdf", body=PDF) is False
    assert is_source_candidate(None, "/doc.pdf") is False


# ---------------------------------------------------------------------------
# Empty body / status
# ---------------------------------------------------------------------------

def test_empty_body_rejected() -> None:
    assert is_source_candidate("application/javascript", "/a.js", body=EMPTY) is False
    assert is_source_candidate("text/html", "/", body=b"") is False


def test_none_body_still_allows_strong_ct_path() -> None:
    # FlowWorker may call without body (cheap path): CT/path only
    assert is_source_candidate("application/javascript", "/a.js", body=None) is True
    assert is_source_candidate("image/png", "/a.png", body=None) is False
    assert is_source_candidate(None, "/a.js", body=None) is True
    assert is_source_candidate(None, "/a.png", body=None) is False


def test_status_204_empty() -> None:
    assert (
        is_source_candidate(
            "text/html", "/", status_code=204, body=EMPTY
        )
        is False
    )


def test_status_404_with_html_body_allowed() -> None:
    assert is_source_candidate(
        "text/html",
        "/missing",
        status_code=404,
        body=HTML_BODY,
    )


def test_status_500_empty_rejected() -> None:
    assert (
        is_source_candidate(
            "text/html", "/err", status_code=500, body=EMPTY
        )
        is False
    )


def test_status_200_js() -> None:
    assert is_source_candidate(
        "application/javascript",
        "/app.js",
        status_code=200,
        body=JS_BODY,
    )


def test_from_flow_string_status() -> None:
    assert is_source_candidate_from_flow(
        content_type="application/json",
        path="/api",
        status_code="200",
        body=JSON_BODY,
    )
    assert (
        is_source_candidate_from_flow(
            content_type="text/html",
            path="/",
            status_code="204",
            body=EMPTY,
        )
        is False
    )


def test_full_url_path() -> None:
    assert is_source_candidate(
        "application/javascript",
        "https://cdn.example.com/static/app.deadbeef.js?v=1",
        body=JS_BODY,
    )


def test_truncated_flag_does_not_force_accept() -> None:
    assert (
        is_source_candidate(
            "image/png", "/x.png", body=PNG, truncated=True
        )
        is False
    )
    assert is_source_candidate(
        "application/javascript",
        "/app.js",
        body=JS_BODY,
        truncated=True,
    )
