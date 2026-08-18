"""Payload catalogue for HTTP request smuggling."""

from __future__ import annotations

import pytest

from talos.smuggle.models import TECHNIQUE_NAMES
from talos.smuggle.payloads import (
    canary_path_for,
    canary_request,
    generate_smuggle_payloads,
    render_http_request,
)


def test_canary_path_stable() -> None:
    assert canary_path_for("abcd") == "/talos-hrs-abcd"


def test_generate_all_techniques() -> None:
    payloads = generate_smuggle_payloads(host="app.example.com", nonce="deadbeef")
    names = [p.technique for p in payloads]
    assert names == list(TECHNIQUE_NAMES)
    for payload in payloads:
        assert payload.canary_path == "/talos-hrs-deadbeef"
        header_names = [n.lower() for n, _ in payload.headers]
        assert "host" in header_names
        assert "connection" in header_names
        raw = render_http_request(
            payload.method, "/login", list(payload.headers), payload.body
        )
        assert raw.startswith(b"POST /login HTTP/1.1\r\n")
        assert b"/talos-hrs-deadbeef" in payload.body or b"/talos-hrs-deadbeef" in raw


def test_cl_te_has_both_framing_headers() -> None:
    payload = generate_smuggle_payloads(
        host="app.example.com", nonce="aa", techniques=["cl_te"]
    )[0]
    headers = [(n.lower(), v) for n, v in payload.headers]
    assert ("transfer-encoding", "chunked") in headers
    cl = next(v for n, v in headers if n == "content-length")
    assert int(cl) == len(payload.body)
    assert payload.body.startswith(b"0\r\n\r\n")


def test_te_cl_content_length_is_size_line_only() -> None:
    payload = generate_smuggle_payloads(
        host="app.example.com", nonce="bb", techniques=["te_cl"]
    )[0]
    cl = next(v for n, v in payload.headers if n.lower() == "content-length")
    # Size line is "{hex}\r\n" — a few bytes, not the whole body.
    assert int(cl) < len(payload.body)
    assert int(cl) <= 8


def test_cl_cl_has_duplicate_content_length() -> None:
    payload = generate_smuggle_payloads(
        host="app.example.com", nonce="cc", techniques=["cl_cl"]
    )[0]
    cls = [v for n, v in payload.headers if n.lower() == "content-length"]
    assert len(cls) == 2
    assert cls[0] != cls[1]


def test_unknown_technique_raises() -> None:
    with pytest.raises(ValueError, match="unknown"):
        generate_smuggle_payloads(
            host="app.example.com", nonce="x", techniques=["nope"]
        )


def test_canary_request_is_complete_get() -> None:
    raw = canary_request("/talos-hrs-x", "app.example.com")
    assert raw.startswith(b"GET /talos-hrs-x HTTP/1.1\r\n")
    assert raw.endswith(b"\r\n\r\n")
