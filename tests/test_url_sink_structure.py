"""
Tests: URL Sink Discovery Phase 2 — structure discovery.

Purpose:
    Cover PR-4 + PR-5 surfaces:
        - base64 / URL-encoded JSON unwrap with dotted paths
        - JWT URL-shaped claims as virtual params
        - header allowlist + value-first custom headers
        - HTML hidden fields + JS/bootstrap config inventory
        - regression: Phase 1 extract still works; noise gated
"""

from __future__ import annotations

import base64
import json
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import quote

import pytest

from talos.projects.db import SCHEMA_VERSION, init_project_db
from talos.projects.parameters import (
    extract_flow_params,
    extract_response_url_sink_params,
    upsert_endpoint_params,
)
from talos.url_sink.decode import try_unwrap_json, walk_unwrapped_leaves
from talos.url_sink.html_js_extract import extract_html_js_params, passes_inventory_gate
from talos.url_sink.jwt_claims import (
    decode_jwt_payload,
    extract_jwt_token,
    extract_url_claim_params,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(payload: dict) -> str:
    header = _b64url(b'{"alg":"none","typ":"JWT"}')
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}.sig"


def _b64_json(obj: object) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


# ---------------------------------------------------------------------------
# decode.py
# ---------------------------------------------------------------------------

def test_unwrap_base64_json_nested_path() -> None:
    blob = _b64_json({"oauth": {"metadata": {"url": "https://cdn.example/m"}}})
    result = try_unwrap_json(blob)
    assert result.parsed is not None
    assert "decode:base64" in result.evidence
    leaves = walk_unwrapped_leaves(result.parsed, prefix="config")
    assert ("config.oauth.metadata.url", "https://cdn.example/m") in leaves


def test_unwrap_url_encoded_json() -> None:
    raw = json.dumps({"callback": {"url": "https://hooks.example/x"}})
    encoded = quote(raw)
    result = try_unwrap_json(encoded)
    assert result.parsed is not None
    assert "decode:url" in result.evidence
    leaves = walk_unwrapped_leaves(result.parsed, prefix="cfg")
    assert any(n.endswith("callback.url") for n, _ in leaves)


def test_unwrap_rejects_plain_url() -> None:
    result = try_unwrap_json("https://cdn.example/x")
    assert result.parsed is None


def test_unwrap_rejects_email() -> None:
    result = try_unwrap_json("user@example.com")
    assert result.parsed is None


def test_unwrap_rejects_tiny_noise() -> None:
    assert try_unwrap_json("abc").parsed is None


# ---------------------------------------------------------------------------
# jwt_claims.py
# ---------------------------------------------------------------------------

def test_jwt_extract_jku_and_iss() -> None:
    token = _make_jwt({
        "jku": "https://evil.example/jwks",
        "iss": "https://issuer.example/",
        "kid": "opaque-key-id",
        "sub": "user-1",
    })
    claims = extract_url_claim_params(
        f"Bearer {token}",
        parent_name="authorization",
        parent_location="header",
    )
    by_name = {c.name: c for c in claims}
    assert "jwt.jku" in by_name
    assert by_name["jwt.jku"].sample_value == "https://evil.example/jwks"
    assert "jwt.iss" in by_name
    # Opaque kid/sub must not emit.
    assert "jwt.kid" not in by_name
    assert "jwt.sub" not in by_name
    assert any("parent:authorization" in e for e in by_name["jwt.jku"].evidence)


def test_jwt_kid_emitted_only_when_url_shaped() -> None:
    token = _make_jwt({"kid": "https://keys.example/kid1"})
    claims = extract_url_claim_params(token, parent_name="id_token")
    assert any(c.name == "jwt.kid" for c in claims)


def test_jwt_token_and_payload_helpers() -> None:
    token = _make_jwt({"iss": "https://a.example/"})
    assert extract_jwt_token(f"Bearer {token}") == token
    payload = decode_jwt_payload(token)
    assert payload is not None
    assert payload["iss"] == "https://a.example/"


# ---------------------------------------------------------------------------
# parameters: encoded JSON on form / query
# ---------------------------------------------------------------------------

def test_extract_form_base64_json_dotted_path() -> None:
    blob = _b64_json({"oauth": {"metadata": {"url": "https://cdn.example/m"}}})
    params = extract_flow_params(
        query="",
        request_body=f"config={blob}".encode(),
        request_headers={"content-type": "application/x-www-form-urlencoded"},
    )
    by_name = {p.name: p for p in params}
    assert "config" in by_name
    assert "config.oauth.metadata.url" in by_name
    nested = by_name["config.oauth.metadata.url"]
    assert nested.location == "body"
    assert nested.semantic_type == "url"
    feat = json.loads(nested.url_features)
    assert feat["score"] >= 90
    assert any("decode:base64" in e for e in feat["evidence"])


def test_extract_query_url_encoded_json() -> None:
    raw = json.dumps({"redirect": {"url": "https://app.example/home"}})
    q = "payload=" + quote(raw, safe="")
    params = extract_flow_params(
        query=q,
        request_body=None,
        request_headers={},
    )
    names = {p.name for p in params}
    assert "payload" in names
    assert any(n.endswith("redirect.url") for n in names)
    nested = next(p for p in params if p.name.endswith("redirect.url"))
    assert nested.location == "query"
    feat = json.loads(nested.url_features)
    assert feat["possible_network_resource"] is True


def test_extract_json_string_leaf_base64_expand() -> None:
    """JSON body string leaf that holds base64 JSON is also expanded."""
    blob = _b64_json({"callback_url": "https://hooks.example/cb"})
    body = json.dumps({"wrap": blob}).encode()
    params = extract_flow_params(
        query="",
        request_body=body,
        request_headers={"content-type": "application/json"},
    )
    names = {p.name for p in params}
    assert "wrap" in names
    assert "wrap.callback_url" in names
    p = next(x for x in params if x.name == "wrap.callback_url")
    assert p.semantic_type == "url"


def test_multipart_field_value_url_features() -> None:
    boundary = "----TalosBound"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="avatar"\r\n\r\n'
        f"https://cdn.example/a.png\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    params = extract_flow_params(
        query="",
        request_body=body,
        request_headers={
            "content-type": f"multipart/form-data; boundary={boundary}",
        },
    )
    avatar = next(p for p in params if p.name == "avatar")
    assert avatar.semantic_type == "url"
    feat = json.loads(avatar.url_features)
    assert feat["score"] >= 90


# ---------------------------------------------------------------------------
# parameters: JWT + headers
# ---------------------------------------------------------------------------

def test_extract_authorization_jwt_claims() -> None:
    token = _make_jwt({
        "jku": "https://evil.example/jwks.json",
        "iss": "https://login.example/",
        "aud": "https://api.example/resource",
    })
    params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={"authorization": f"Bearer {token}"},
    )
    by_name = {p.name: p for p in params}
    assert "authorization" in by_name
    assert by_name["authorization"].semantic_type == "jwt"
    assert "jwt.jku" in by_name
    assert by_name["jwt.jku"].location == "header"
    assert by_name["jwt.jku"].semantic_type == "url"
    assert "jwt.iss" in by_name
    assert "jwt.aud" in by_name


def test_cookie_jwt_claims() -> None:
    token = _make_jwt({"jku": "https://keys.example/jwks"})
    params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={},
        request_cookies={"session": token},
    )
    by_name = {p.name: p for p in params}
    assert "session" in by_name
    assert "jwt.jku" in by_name
    assert by_name["jwt.jku"].location == "cookie"


def test_header_allowlist_content_location_and_link() -> None:
    params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={
            "content-location": "https://cdn.example/doc",
            "destination": "https://app.example/dest",
            "x-rewrite-url": "/internal/path",
            "x-forwarded-server": "edge.internal",
        },
    )
    names = {p.name for p in params}
    assert "content-location" in names
    assert "destination" in names
    assert "x-rewrite-url" in names
    assert "x-forwarded-server" in names


def test_header_value_first_custom_url_header() -> None:
    """Custom header not on allowlist but value is URL → still captured."""
    params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={
            "x-my-callback": "https://hooks.example/cb",
            "accept": "text/html",
            "user-agent": "TestAgent/1.0",
        },
    )
    by_name = {p.name: p for p in params}
    assert "x-my-callback" in by_name
    feat = json.loads(by_name["x-my-callback"].url_features)
    assert "header_value_first" in feat["evidence"]
    assert feat["score"] >= 90
    # Routine headers skipped
    assert "accept" not in by_name
    assert "user-agent" not in by_name


def test_header_value_first_skips_plain_noise() -> None:
    params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={"x-request-trace": "abc-not-a-url"},
    )
    assert all(p.name != "x-request-trace" for p in params)


# ---------------------------------------------------------------------------
# html_js_extract + response inventory
# ---------------------------------------------------------------------------

_SAMPLE_HTML = """
<!doctype html>
<html><body>
<form>
  <input type="hidden" name="redirect_url" value="https://app.example/home">
  <input type="hidden" name="csrf_token" value="abc123noturl">
  <input type="text" name="q" value="search">
</form>
<script id="__NEXT_DATA__" type="application/json">
{"props":{"pageProps":{"apiUrl":"https://api.example/v1","title":"Home"}}}
</script>
<script>window.__CONFIG__ = {"baseUrl": "https://cdn.example/static"};</script>
<script>
  const webhook_url = "https://hooks.example/events";
</script>
</body></html>
"""


def test_html_js_hidden_and_bootstrap() -> None:
    cands = extract_html_js_params(_SAMPLE_HTML)
    by_name = {c.name: c for c in cands}
    assert "redirect_url" in by_name
    assert by_name["redirect_url"].source == "html_hidden"
    assert by_name["redirect_url"].score >= 90
    # csrf without URL shape / name category for sink should be gated out
    assert "csrf_token" not in by_name
    # Nested NEXT_DATA leaf
    assert any("apiUrl" in n for n in by_name)
    assert any("baseUrl" in c.name for c in cands)
    # JS assign pattern
    assert any(
        c.sample_value == "https://hooks.example/events" for c in cands
    )


def test_inventory_gate_rejects_static_cdn_noise_without_name() -> None:
    """Random name + weak non-URL value fails gate."""
    ok, score, _ = passes_inventory_gate("x", "hello")
    assert ok is False
    assert score < 45


def test_inventory_gate_accepts_value_first() -> None:
    ok, score, _ = passes_inventory_gate("abc", "https://cdn.example/x")
    assert ok is True
    assert score >= 90


def test_extract_response_url_sink_params_location() -> None:
    params = extract_response_url_sink_params(
        _SAMPLE_HTML.encode(),
        {"content-type": "text/html; charset=utf-8"},
        role_id="role-1",
    )
    assert params
    assert all(p.location == "response" for p in params)
    assert all(p.role_id == "role-1" for p in params)
    names = {p.name for p in params}
    assert "redirect_url" in names
    # Evidence marks source
    redir = next(p for p in params if p.name == "redirect_url")
    feat = json.loads(redir.url_features)
    assert "html_hidden" in feat["evidence"]


def test_extract_response_skips_json_api() -> None:
    body = json.dumps({"apiUrl": "https://api.example/v1"}).encode()
    params = extract_response_url_sink_params(
        body,
        {"content-type": "application/json"},
    )
    assert params == []


def test_phase1_regression_random_name_url() -> None:
    """Phase 1 success metric still holds after structure expansion."""
    params = extract_flow_params(
        query="abc=https%3A%2F%2Fcdn.example%2Fx",
        request_body=None,
        request_headers={},
    )
    abc = next(p for p in params if p.name == "abc")
    feat = json.loads(abc.url_features)
    assert feat["score"] >= 90
    assert feat["possible_network_resource"] is True
    assert feat["name_category"] is None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

@pytest.fixture()
def project_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    assert SCHEMA_VERSION >= 53
    return db_path


def _seed_endpoint(conn: sqlite3.Connection) -> str:
    endpoint_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO endpoints (
            id, project_id, method, host, path, normalized_path,
            first_seen, last_seen
        ) VALUES (?, 'p1', 'GET', 'http://example.com', '/x', '/x',
                  '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
        """,
        (endpoint_id,),
    )
    return endpoint_id


def test_upsert_structure_and_response_params(project_db: Path) -> None:
    token = _make_jwt({"jku": "https://evil.example/jwks"})
    req_params = extract_flow_params(
        query="",
        request_body=None,
        request_headers={"authorization": f"Bearer {token}"},
    )
    resp_params = extract_response_url_sink_params(
        _SAMPLE_HTML.encode(),
        {"content-type": "text/html"},
    )
    all_params = list(req_params) + list(resp_params)
    with sqlite3.connect(str(project_db)) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = _seed_endpoint(conn)
        upsert_endpoint_params(conn, endpoint_id, all_params)
        conn.commit()
        rows = conn.execute(
            "SELECT name, location, url_features FROM parameters "
            "WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchall()
    by_key = {(r["name"], r["location"]): r for r in rows}
    assert ("jwt.jku", "header") in by_key
    assert ("redirect_url", "response") in by_key
    jku_feat = json.loads(by_key[("jwt.jku", "header")]["url_features"])
    assert jku_feat["score"] >= 90
    assert any("jwt_claim" in e for e in jku_feat["evidence"])
