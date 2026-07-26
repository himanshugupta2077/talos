"""
Tests for talos.passive.normalize — body bytes → scan text.
"""

from __future__ import annotations

from talos.passive.normalize import (
    NormalizeResult,
    extract_charset,
    normalize_body,
)


def test_extract_charset() -> None:
    assert extract_charset("text/html; charset=UTF-8") == "utf-8"
    assert extract_charset('application/json; charset="iso-8859-1"') == "latin-1"
    assert extract_charset("text/plain") is None
    assert extract_charset(None) is None


def test_utf8_roundtrip() -> None:
    body = "hello — café 🔐".encode("utf-8")
    result = normalize_body(body, content_type="text/plain; charset=utf-8")
    assert isinstance(result, NormalizeResult)
    assert result.text == "hello — café 🔐"
    assert result.encoding == "utf-8"
    assert result.body_size == len(body)
    assert result.truncated is False
    assert result.had_decode_errors is False
    assert result.charset_declared == "utf-8"


def test_utf8_without_declared_charset() -> None:
    body = b'{"msg": "ok"}'
    result = normalize_body(body)
    assert result.text == '{"msg": "ok"}'
    assert result.encoding == "utf-8"


def test_latin1_fallback_for_invalid_utf8() -> None:
    # 0xff is invalid in UTF-8; latin-1 decodes it
    body = b"price: \xff99"
    result = normalize_body(body)
    assert result.encoding == "latin-1"
    assert "\xff" in result.text or result.text.endswith("99")
    assert result.had_decode_errors is False


def test_declared_latin1() -> None:
    body = "café".encode("latin-1")
    result = normalize_body(
        body,
        content_type="text/html; charset=iso-8859-1",
    )
    assert result.text == "café"
    assert result.encoding == "latin-1"
    assert result.charset_declared == "latin-1"


def test_empty_body() -> None:
    result = normalize_body(b"")
    assert result.text == ""
    assert result.body_size == 0
    result_none = normalize_body(None)
    assert result_none.text == ""
    assert result_none.body_size == 0


def test_truncated_flag_preserved() -> None:
    result = normalize_body(b"abc", truncated=True)
    assert result.truncated is True
    assert result.text == "abc"


def test_max_chars_truncates() -> None:
    result = normalize_body(b"abcdefghij", max_chars=4)
    assert result.text == "abcd"
    assert result.truncated is True
    assert result.body_size == 10


def test_js_bundle_sample() -> None:
    body = b"var config={apiKey:'AKIAIOSFODNN7EXAMPLE'};\n"
    result = normalize_body(
        body,
        content_type="application/javascript; charset=utf-8",
    )
    assert "AKIAIOSFODNN7EXAMPLE" in result.text
    assert result.encoding == "utf-8"
