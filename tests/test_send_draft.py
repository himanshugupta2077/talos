"""
Tests for talos.send.draft and talos.send.raw_http.

Covers:
    - draft_from_flow copies request fields only
    - structured patches (method, url, header, query, body)
    - raw parse / serialize round-trip for GET and POST with body
"""

from __future__ import annotations

import json

import pytest

from talos.send.draft import (
    apply_body,
    apply_header,
    apply_method,
    apply_query_param,
    apply_raw_message,
    apply_structured_patches,
    apply_url,
    draft_from_flow,
    draft_to_raw_bytes,
    remove_header,
)
from talos.send.raw_http import parse_request, serialize_request


def _parent_flow(**overrides: object) -> dict:
    base = {
        "id": "parent-uuid-1",
        "method": "POST",
        "url": "https://api.example.com/v1/orders?x=1",
        "host": "api.example.com",
        "path": "/v1/orders",
        "query": "x=1",
        "request_headers": json.dumps(
            {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Cookie": "sid=abc",
                "Content-Length": "15",
            }
        ),
        "request_cookies": json.dumps({"sid": "abc"}),
        "request_body": b'{"qty":1}',
        "status_code": 200,
        "response_body": b"ok",
        "endpoint_id": "ep-1",
        "role_id": "role-1",
        "module_id": "mod-1",
        "source": "proxy_capture",
        "original_flow_id": None,
    }
    base.update(overrides)
    return base


class TestDraftFromFlow:
    def test_copies_request_fields_and_lineage(self) -> None:
        draft = draft_from_flow(_parent_flow())
        assert draft["method"] == "POST"
        assert draft["url"] == "https://api.example.com/v1/orders?x=1"
        assert draft["request_headers"]["Cookie"] == "sid=abc"
        assert draft["request_body"] == b'{"qty":1}'
        assert draft["parent_flow_id"] == "parent-uuid-1"
        assert draft["original_flow_id"] == "parent-uuid-1"
        assert draft["endpoint_id"] == "ep-1"
        assert draft["role_id"] == "role-1"

    def test_root_from_parent_original(self) -> None:
        draft = draft_from_flow(
            _parent_flow(
                id="send-2",
                original_flow_id="capture-root",
                source="manual_send",
            )
        )
        assert draft["parent_flow_id"] == "send-2"
        assert draft["original_flow_id"] == "capture-root"


class TestStructuredPatches:
    def test_method_url_header_query_body(self) -> None:
        d = draft_from_flow(_parent_flow())
        d = apply_method(d, "put")
        d = apply_url(d, "https://api.example.com/v1/items?z=9")
        d = apply_header(d, "X-Test", "1")
        d = remove_header(d, "Cookie")
        d = apply_query_param(d, "z", "10")
        d = apply_body(d, b"hello")

        assert d["method"] == "PUT"
        assert "z=10" in d["url"]
        assert d["query"] == "z=10"
        assert d["request_headers"]["X-Test"] == "1"
        assert "Cookie" not in d["request_headers"]
        assert d["request_body"] == b"hello"

    def test_batch_structured(self) -> None:
        d = draft_from_flow(_parent_flow())
        d = apply_structured_patches(
            d,
            method="GET",
            headers=[("X-A", "a")],
            remove_headers=["Content-Type"],
            query_params=[("page", "2")],
            body=None,
            body_set=True,
        )
        assert d["method"] == "GET"
        assert d["request_headers"]["X-A"] == "a"
        assert "Content-Type" not in {
            k for k in d["request_headers"] if k.lower() == "content-type"
        } or "Content-Type" not in d["request_headers"]
        assert "page=2" in d["query"]
        assert d["request_body"] is None


class TestRawHttp:
    def test_get_round_trip(self) -> None:
        raw = serialize_request(
            "GET",
            "https://example.com/path?q=1",
            {"Host": "example.com", "Accept": "*/*"},
            None,
        )
        parsed = parse_request(raw, default_scheme="https")
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/path"
        assert parsed["query"] == "q=1"
        assert parsed["host"] == "example.com"
        assert parsed["request_body"] is None
        assert parsed["request_headers"]["Accept"] == "*/*"

    def test_post_with_body_round_trip(self) -> None:
        body = b'{"a":1}'
        raw = serialize_request(
            "POST",
            "https://api.example.com/v1",
            {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body,
        )
        parsed = parse_request(raw, default_scheme="https")
        assert parsed["method"] == "POST"
        assert parsed["request_body"] == body
        assert parsed["request_headers"]["Content-Type"] == "application/json"

    def test_lf_only_line_endings(self) -> None:
        raw = (
            b"GET /x HTTP/1.1\n"
            b"Host: h.test\n"
            b"X-Foo: bar\n"
            b"\n"
        )
        parsed = parse_request(raw, default_scheme="https")
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/x"
        assert parsed["request_headers"]["X-Foo"] == "bar"

    def test_apply_raw_preserves_lineage(self) -> None:
        d = draft_from_flow(_parent_flow())
        raw = draft_to_raw_bytes(d)
        # Mutate body in raw
        raw = raw.replace(b'{"qty":1}', b'{"qty":99}')
        d2 = apply_raw_message(d, raw)
        assert d2["parent_flow_id"] == "parent-uuid-1"
        assert d2["endpoint_id"] == "ep-1"
        assert d2["request_body"] == b'{"qty":99}'
        assert d2["edit_mode"] == "raw"

    def test_parse_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_request(b"")
