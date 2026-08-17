"""
Tests for outbound httpx client helpers.

Covers encode_outbound_headers: httpx rejects non-ASCII header strings
with UnicodeEncodeError ('ascii' codec can't encode character '\\xe9'…).
"""

from __future__ import annotations

import httpx
import pytest

from talos.input_validation.phases import prepare_iv_probe
from talos.input_validation.taxonomy import CLASS_SPECS
from talos.proxy.http_client import encode_outbound_headers


def test_ascii_headers_pass_through_unchanged() -> None:
    headers = {"Host": "api.example.com", "X-Request-Id": "abc"}
    assert encode_outbound_headers(headers) is headers


def test_empty_and_none() -> None:
    assert encode_outbound_headers(None) == {}
    assert encode_outbound_headers({}) == {}


def test_iv_unicode_probe_encodes_as_latin1() -> None:
    payload = CLASS_SPECS["unicode"].representatives[0]
    assert payload == "é"
    encoded = encode_outbound_headers({"X-Name": payload})
    assert encoded["X-Name"] == "é".encode("latin-1")
    assert encoded["X-Name"] == b"\xe9"


def test_cjk_header_falls_back_to_utf8() -> None:
    encoded = encode_outbound_headers({"X-Name": "中"})
    assert encoded["X-Name"] == "中".encode("utf-8")


def test_httpx_request_accepts_encoded_unicode_header() -> None:
    raw = {"X-Name": "é", "Cookie": "display=café"}
    # The failure reported on issue #6:
    with pytest.raises(UnicodeEncodeError, match="ascii"):
        httpx.Request("GET", "https://example.com/", headers=raw)

    req = httpx.Request(
        "GET",
        "https://example.com/",
        headers=encode_outbound_headers(raw),
    )
    assert req.headers["X-Name"] == "é"
    assert "café" in req.headers["Cookie"]


def test_iv_header_inject_is_sendable() -> None:
    flow = {
        "method": "GET",
        "url": "https://api.example.com/users",
        "request_headers": '{"X-User": "alice", "Host": "api.example.com"}',
        "request_body": None,
    }
    mutations = prepare_iv_probe("characters", flow, "X-User", "header", "é")
    headers = mutations["request_headers"]
    assert headers["X-User"] == "é"
    req = httpx.Request(
        "GET",
        flow["url"],
        headers=encode_outbound_headers(headers),
    )
    assert req.headers["x-user"] == "é"


def test_sequence_pairs_and_list_values() -> None:
    pairs = [("X-A", "ok"), ("X-B", "é")]
    encoded = encode_outbound_headers(pairs)
    assert encoded[0] == ("X-A", "ok")
    assert encoded[1] == ("X-B", b"\xe9")

    mapped = encode_outbound_headers({"X-Multi": ["ok", "é"]})
    assert mapped["X-Multi"][0] == "ok"
    assert mapped["X-Multi"][1] == b"\xe9"
