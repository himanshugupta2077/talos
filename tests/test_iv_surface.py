"""
Tests for Module 9 — Surface completeness.

Covers:
  - Path segment rewrite via normalized {name} placeholders
  - Header / cookie hardening (multi-cookie, case, hop-by-hop)
  - Multipart field value + filename inject
  - GraphQL variables + XML leaf inject
  - Auth artifact skip policy
  - prepare_iv_probe end-to-end on fixture flows
  - Capability / surface synthesis hooks
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

from talos.input_validation.phases import prepare_iv_probe
from talos.input_validation.profile import (
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_PATH_PARAMETER,
    empty_param_profile,
)
from talos.input_validation.synthesize import _fill_capabilities, _fill_surface
from talos.input_validation.surface import (
    SKIP_AUTH_ARTIFACT,
    SKIP_HOP_BY_HOP_HEADER,
    SKIP_TRANSPORT_INVALID_COOKIE,
    SKIP_TRANSPORT_INVALID_HEADER,
    SURFACE_GRAPHQL_VARIABLE,
    SURFACE_MULTIPART_FILENAME,
    SURFACE_PATH,
    SURFACE_XML_LEAF,
    detect_surface_kind,
    headers_are_transport_legal,
    inject_cookie_param,
    inject_graphql_param,
    inject_header_param,
    inject_json_param,
    inject_multipart_filename,
    inject_multipart_param,
    inject_path_param,
    inject_value,
    inject_xml_param,
    is_auth_artifact,
    is_hop_by_hop_header,
    is_http_header_value_legal,
    make_cookie_safe,
    make_header_safe,
    header_names_from_param_specs,
    injection_point_matches_spec,
    json_param_path_matches,
    parse_json_param_path,
    should_skip_param,
    transport_skip_for_headers,
    transport_skip_for_payload,
)


# ---------------------------------------------------------------------------
# Path injection
# ---------------------------------------------------------------------------


class TestPathInjection:
    def test_rewrite_named_segment(self) -> None:
        url = "https://api.example.com/users/42/orders/7?x=1"
        out = inject_path_param(
            url,
            "id",
            "PROBE",
            normalized_path="/users/{id}/orders/{oid}",
        )
        p = urlparse(out)
        assert p.path == "/users/PROBE/orders/7"
        assert p.query == "x=1"

    def test_rewrite_second_segment(self) -> None:
        url = "https://api.example.com/users/42/orders/7"
        out = inject_path_param(
            url,
            "oid",
            "ZZ",
            normalized_path="/users/{id}/orders/{oid}",
        )
        assert urlparse(out).path == "/users/42/orders/ZZ"

    def test_encodes_special_chars(self) -> None:
        url = "https://api.example.com/items/a"
        out = inject_path_param(
            url, "id", "a/b", normalized_path="/items/{id}"
        )
        assert "a%2Fb" in urlparse(out).path

    def test_no_normalized_path_unchanged(self) -> None:
        url = "https://api.example.com/users/42"
        out = inject_path_param(url, "id", "X")
        assert out == url

    def test_prepare_iv_probe_path_fixture(self) -> None:
        flow = {
            "method": "GET",
            "url": "https://api.example.com/v1/users/99",
            "request_headers": "{}",
            "request_body": None,
            "normalized_path": "/v1/users/{user_id}",
        }
        mut = prepare_iv_probe(
            "identifier",
            flow,
            "user_id",
            "path",
            "TL_CANARY",
        )
        assert "url" in mut
        assert "/v1/users/TL_CANARY" in mut["url"]


# ---------------------------------------------------------------------------
# Header / cookie
# ---------------------------------------------------------------------------


class TestHeaderCookie:
    def test_header_case_insensitive_replace(self) -> None:
        headers = {"X-Tenant": "acme", "Accept": "json"}
        out = inject_header_param(headers, "x-tenant", "probe")
        assert out["X-Tenant"] == "probe"
        assert out["Accept"] == "json"

    def test_header_add_when_missing(self) -> None:
        out = inject_header_param({}, "X-Custom", "v")
        assert out["X-Custom"] == "v"

    def test_hop_by_hop_not_mutated(self) -> None:
        headers = {"Connection": "keep-alive", "X-Ok": "1"}
        out = inject_header_param(headers, "Connection", "close")
        assert out["Connection"] == "keep-alive"
        assert is_hop_by_hop_header("Transfer-Encoding")

    def test_multi_cookie_replace(self) -> None:
        headers = {"Cookie": "a=1; session=SECRET; b=2"}
        out = inject_cookie_param(headers, "b", "PROBE")
        assert "a=1" in out["Cookie"]
        assert "session=SECRET" in out["Cookie"]
        assert "b=PROBE" in out["Cookie"]

    def test_cookie_append_when_missing(self) -> None:
        headers = {"Cookie": "a=1"}
        out = inject_cookie_param(headers, "new", "v")
        assert "a=1" in out["Cookie"]
        assert "new=v" in out["Cookie"]

    def test_cookie_create_header(self) -> None:
        out = inject_cookie_param({}, "c", "v")
        assert out["Cookie"] == "c=v"

    def test_prepare_header_profile_schema(self) -> None:
        flow = {
            "method": "GET",
            "url": "https://api.example.com/",
            "request_headers": json.dumps({"X-Tenant": "t1", "Accept": "*/*"}),
            "request_body": None,
        }
        mut = prepare_iv_probe("baseline", flow, "x-tenant", "header", None)
        assert mut == {}
        mut = prepare_iv_probe(
            "identifier", flow, "x-tenant", "header", "CANARY"
        )
        assert "request_headers" in mut
        hdrs = mut["request_headers"]
        assert hdrs["X-Tenant"] == "CANARY"

    def test_cookie_strips_outer_whitespace(self) -> None:
        out = inject_cookie_param({"Cookie": "a=1"}, "b", "  val  ")
        assert "b=val" in out["Cookie"]
        assert headers_are_transport_legal(out)


# ---------------------------------------------------------------------------
# Transport-legal header / cookie payloads
# ---------------------------------------------------------------------------


class TestTransportSafety:
    def test_illegal_leading_trailing_spaces(self) -> None:
        assert not is_http_header_value_legal("  TlNormabc  ")
        skip = transport_skip_for_payload("header", "  TlNormabc  ")
        assert skip is not None
        assert skip.reason == SKIP_TRANSPORT_INVALID_HEADER
        # Query still allows spaces (application characterization).
        assert transport_skip_for_payload("query", "  TlNormabc  ") is None

    def test_illegal_null_byte_header_and_cookie(self) -> None:
        assert not is_http_header_value_legal("a\x00b")
        h = transport_skip_for_payload("header", "a\x00b")
        c = transport_skip_for_payload("cookie", "a\x00b")
        assert h is not None and h.reason == SKIP_TRANSPORT_INVALID_HEADER
        assert c is not None and c.reason == SKIP_TRANSPORT_INVALID_COOKIE

    def test_legal_printable_header(self) -> None:
        assert is_http_header_value_legal("TL~^~alpha=a~^~digit=7")
        assert transport_skip_for_payload("header", "TL~^~alpha=a") is None

    def test_make_header_safe_strips_and_drops_ctl(self) -> None:
        assert make_header_safe("  abc  ") == "abc"
        assert make_header_safe("a\x00b") == "ab"
        assert make_header_safe("\x00") is None
        assert make_header_safe("   ") is None

    def test_make_cookie_safe(self) -> None:
        assert make_cookie_safe("  x  ") == "x"
        assert make_cookie_safe("a\x00b") == "ab"
        assert make_cookie_safe("\x00") is None

    def test_post_inject_cookie_with_null_illegal(self) -> None:
        headers = inject_cookie_param(
            {"Cookie": "lang=en; token=abc"},
            "show_tool_calls",
            "TL1~^~null=\x00~^~TL1",
        )
        assert not headers_are_transport_legal(headers)
        skip = transport_skip_for_headers("cookie", headers)
        assert skip is not None
        assert skip.reason == SKIP_TRANSPORT_INVALID_COOKIE

    def test_post_inject_legal_cookie_multiprobe_without_null(self) -> None:
        headers = inject_cookie_param(
            {"Cookie": "lang=en"},
            "show_tool_calls",
            "TL1~^~alpha=a~^~digit=7~^~TL1",
        )
        assert headers_are_transport_legal(headers)
        assert transport_skip_for_headers("cookie", headers) is None


# ---------------------------------------------------------------------------
# Multipart / GraphQL / XML
# ---------------------------------------------------------------------------


class TestMultipartGraphqlXml:
    def _multipart(self) -> tuple[bytes, str]:
        boundary = "----TalosBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="note"\r\n\r\n'
            f"hello\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="upload"; filename="a.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"filedata\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        ct = f"multipart/form-data; boundary={boundary}"
        return body, ct

    def test_multipart_field_value(self) -> None:
        body, ct = self._multipart()
        out = inject_multipart_param(body, ct, "note", "PROBE", target="value")
        assert b"PROBE" in out
        assert b"hello" not in out
        assert b'filename="a.txt"' in out

    def test_multipart_filename(self) -> None:
        body, ct = self._multipart()
        out = inject_multipart_filename(body, ct, "upload", "evil.php")
        assert b'filename="evil.php"' in out
        assert b"filedata" in out

    def test_graphql_variables_path(self) -> None:
        body = json.dumps({
            "query": "query($id: ID!){ user(id:$id){ name } }",
            "variables": {"id": "1", "nested": {"x": "y"}},
        }).encode()
        out = inject_graphql_param(body, "variables.id", "PROBE")
        data = json.loads(out)
        assert data["variables"]["id"] == "PROBE"
        assert data["variables"]["nested"]["x"] == "y"

    def test_json_boolean_stays_native(self) -> None:
        body = json.dumps({"enabled": True, "name": "x"}).encode()
        out = inject_json_param(body, "enabled", "false", payload_type="boolean_false")
        data = json.loads(out)
        assert data["enabled"] is False
        assert data["name"] == "x"

    def test_json_integer_stays_native(self) -> None:
        body = json.dumps({"count": 5}).encode()
        out = inject_json_param(body, "count", "-999999", payload_type="negative_int")
        data = json.loads(out)
        assert data["count"] == -999999
        assert isinstance(data["count"], int)

    def test_json_type_confusion_stays_string(self) -> None:
        body = json.dumps({"enabled": True}).encode()
        out = inject_json_param(body, "enabled", "notabool", payload_type="string")
        data = json.loads(out)
        assert data["enabled"] == "notabool"

    def test_json_array_path_first_element(self) -> None:
        body = json.dumps({
            "items": [{"id": "a", "n": 1}, {"id": "b", "n": 2}],
        }).encode()
        out = inject_json_param(body, "items[].id", "PROBE", payload_type="string")
        data = json.loads(out)
        assert data["items"][0]["id"] == "PROBE"
        assert data["items"][1]["id"] == "b"
        assert data["items"][0]["n"] == 1

    def test_json_array_empty_native(self) -> None:
        body = json.dumps({"tags": ["a", "b"]}).encode()
        out = inject_json_param(body, "tags", "[]", payload_type="array_empty")
        data = json.loads(out)
        assert data["tags"] == []

    def test_json_nested_header_like_key(self) -> None:
        body = json.dumps({
            "headers": {"Host": "api.example.com", "Accept": "*/*"},
        }).encode()
        out = inject_json_param(
            body, "headers.Host", "talos-canary.invalid", payload_type="url_sink:hostname",
        )
        data = json.loads(out)
        assert data["headers"]["Host"] == "talos-canary.invalid"
        assert data["headers"]["Accept"] == "*/*"

    def test_parse_json_path_brackets(self) -> None:
        parts = parse_json_param_path("items[].id")
        assert [p.kind for p in parts] == ["key", "index", "key"]
        assert parts[0].key == "items"
        assert parts[1].index is None
        assert parts[2].key == "id"

    def test_json_param_path_matches_array_schema(self) -> None:
        assert json_param_path_matches("[].Fiscal Year", "[0].Fiscal Year")
        assert json_param_path_matches("items[].id", "items[0].id")
        assert json_param_path_matches("items[0].id", "items[0].id")
        assert not json_param_path_matches("items[1].id", "items[0].id")
        assert not json_param_path_matches("items[].id", "items")
        assert json_param_path_matches("q", "q")
        assert injection_point_matches_spec(
            "body:[].Fiscal Year",
            "body",
            "[0].Fiscal Year",
            allowed_locations=frozenset({"query", "body"}),
        )
        assert header_names_from_param_specs(
            ["header:host", "header:Origin", "query:url"]
        ) == ["host", "Origin"]

    def test_prepare_iv_probe_json_boolean_false(self) -> None:
        flow = {
            "method": "POST",
            "url": "https://api.example.com/cfg",
            "request_headers": json.dumps({"Content-Type": "application/json"}),
            "request_body": json.dumps({"enabled": True, "limit": 3}).encode(),
        }
        mut = prepare_iv_probe(
            "types",
            flow,
            "enabled",
            "body",
            "false",
            payload_type="boolean_false",
        )
        body = json.loads(mut["request_body"])
        assert body["enabled"] is False
        assert body["limit"] == 3

    def test_graphql_bare_variable_name(self) -> None:
        body = json.dumps({
            "query": "{x}",
            "variables": {"id": "1"},
        }).encode()
        out = inject_graphql_param(body, "id", "Z")
        assert json.loads(out)["variables"]["id"] == "Z"

    def test_xml_leaf(self) -> None:
        body = b"<req><userId>42</userId><name>bob</name></req>"
        out = inject_xml_param(body, "userId", "PROBE")
        assert b"<userId>PROBE</userId>" in out
        assert b"<name>bob</name>" in out

    def test_inject_value_routes_multipart_filename(self) -> None:
        body, ct = self._multipart()
        headers = {"Content-Type": ct}
        _u, _h, new_body = inject_value(
            "body",
            "upload",
            "x.exe",
            "https://api.example.com/up",
            headers,
            body,
            semantic_type="filename",
        )
        assert b'filename="x.exe"' in (new_body or b"")

    def test_surface_kind_detection(self) -> None:
        assert detect_surface_kind(location="path") == SURFACE_PATH
        assert detect_surface_kind(
            location="body",
            param_name="variables.id",
            content_type="application/json",
        ) == SURFACE_GRAPHQL_VARIABLE
        assert detect_surface_kind(
            location="body",
            param_name="upload",
            semantic_type="filename",
            content_type="multipart/form-data; boundary=x",
        ) == SURFACE_MULTIPART_FILENAME
        assert detect_surface_kind(
            location="body",
            param_name="userId",
            content_type="application/xml",
        ) == SURFACE_XML_LEAF


# ---------------------------------------------------------------------------
# Auth skip policy
# ---------------------------------------------------------------------------


class TestAuthSkip:
    def test_authorization_skipped(self) -> None:
        d = should_skip_param(location="header", name="Authorization")
        assert d.skip
        assert d.reason == SKIP_AUTH_ARTIFACT

    def test_session_cookie_skipped(self) -> None:
        d = should_skip_param(location="cookie", name="sessionid")
        assert d.skip
        assert d.reason == SKIP_AUTH_ARTIFACT

    def test_configured_cookie_skipped(self) -> None:
        d = should_skip_param(
            location="cookie",
            name="myapp_sess",
            configured_cookies=["myapp_sess"],
        )
        assert d.skip

    def test_include_auth_artifacts_allows(self) -> None:
        d = should_skip_param(
            location="header",
            name="Authorization",
            include_auth_artifacts=True,
        )
        assert not d.skip

    def test_hop_by_hop_always_skipped(self) -> None:
        d = should_skip_param(
            location="header",
            name="Transfer-Encoding",
            include_auth_artifacts=True,
        )
        assert d.skip
        assert d.reason == SKIP_HOP_BY_HOP_HEADER

    def test_normal_header_not_skipped(self) -> None:
        d = should_skip_param(location="header", name="x-tenant")
        assert not d.skip

    def test_response_location_skipped_inventory_only(self) -> None:
        """QA-USD-05: location=response is inventory-only, never IV-scheduled."""
        from talos.input_validation.surface import SKIP_INVENTORY_ONLY

        d = should_skip_param(location="response", name="redirect_url")
        assert d.skip
        assert d.reason == SKIP_INVENTORY_ONLY

    def test_jwt_virtual_claim_skipped_inventory_only(self) -> None:
        """QA-USD-06: virtual jwt.* claims must not inject literal headers."""
        from talos.input_validation.surface import SKIP_INVENTORY_ONLY

        d = should_skip_param(location="header", name="jwt.jku")
        assert d.skip
        assert d.reason == SKIP_INVENTORY_ONLY
        d2 = should_skip_param(location="header", name="jwt.iss")
        assert d2.skip

    def test_is_auth_artifact_jwt_cookie(self) -> None:
        assert is_auth_artifact(
            location="cookie", name="id", semantic_type="jwt"
        )


# ---------------------------------------------------------------------------
# Synthesis capabilities
# ---------------------------------------------------------------------------


class TestSurfaceSynthesis:
    def test_path_capability(self) -> None:
        profile = empty_param_profile(
            param_uuid="u", host="h", location="path", name="id"
        )
        _fill_surface(profile, {"location": "path", "name": "id"}, [])
        _fill_capabilities(profile, "path")
        assert CAPABILITY_PATH_PARAMETER in profile["capabilities"]
        assert profile["observed"]["surface"]["kind"] == SURFACE_PATH

    def test_header_capability(self) -> None:
        profile = empty_param_profile(
            param_uuid="u", host="h", location="header", name="x-tenant"
        )
        _fill_surface(
            profile, {"location": "header", "name": "x-tenant"}, []
        )
        _fill_capabilities(profile, "header")
        assert CAPABILITY_HEADER_INJECTION_SURFACE in profile["capabilities"]

    def test_graphql_capability(self) -> None:
        profile = empty_param_profile(
            param_uuid="u",
            host="h",
            location="body",
            name="variables.id",
        )
        _fill_surface(
            profile,
            {"location": "body", "name": "variables.id"},
            [],
        )
        _fill_capabilities(profile, "body")
        assert CAPABILITY_GRAPHQL_VARIABLE in profile["capabilities"]

    def test_multipart_filename_capability(self) -> None:
        profile = empty_param_profile(
            param_uuid="u", host="h", location="body", name="upload"
        )
        profile["observed"]["surface"] = {
            "location": "body",
            "kind": SURFACE_MULTIPART_FILENAME,
        }
        _fill_capabilities(profile, "body")
        assert CAPABILITY_MULTIPART_FILENAME in profile["capabilities"]


# ---------------------------------------------------------------------------
# Engine skip integration (cache row)
# ---------------------------------------------------------------------------


class TestEngineSurfaceSkip:
    def test_plan_skips_auth_cookie(self, tmp_path: Path) -> None:
        from talos.projects.db import init_project_db
        from talos.input_validation.config import IVConfig
        from talos.input_validation.engine import plan_and_enqueue_for_param
        from talos.input_validation import db as iv_db

        db_path = tmp_path / "t.db"
        init_project_db(db_path)
        host, location, name = "api.example.com", "cookie", "sessionid"
        ep_id = str(uuid.uuid4())
        now = "2024-01-01T00:00:00Z"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO endpoints "
                "(id, project_id, host, method, path, normalized_path, first_seen, last_seen) "
                "VALUES (?, 'p', ?, 'GET', '/x', '/x', ?, ?)",
                (ep_id, host, now, now),
            )
            conn.execute(
                "INSERT INTO parameters (id, endpoint_id, name, location) "
                "VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), ep_id, name, location),
            )
            conn.commit()

        cfg = IVConfig(enabled=True, include_auth_artifacts=False)
        n = plan_and_enqueue_for_param(
            db_path,
            "p",
            host=host,
            location=location,
            name=name,
            endpoint_id=ep_id,
            config=cfg,
        )
        assert n == 0
        entry = iv_db.get_param_cache_entry(
            db_path, host, location, name, "surface"
        )
        assert entry is not None
        assert entry["status"] == "skipped"
        result = entry["result"]
        if isinstance(result, str):
            result = json.loads(result)
        assert result.get("skip_reason") == SKIP_AUTH_ARTIFACT
